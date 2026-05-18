import asyncio
import logging
from typing import Optional, List, Dict
from urllib.parse import urlparse

import aiohttp
from aiohttp_socks import ProxyConnector
from rich.console import Console

from config import settings

console = Console()
logger = logging.getLogger(__name__)


class TorHandler:
    """
    Asynchronous network handler for routing traffic through the Tor network.
    Utilizes aiohttp and aiohttp_socks for non-blocking, high-concurrency SOCKS5 proxying.
    Includes circuit breaking mechanisms to avoid dead or slow onion nodes.
    """

    def __init__(self) -> None:
        """Initializes the TorHandler with configuration state and circuit breaker dict."""
        self.session: Optional[aiohttp.ClientSession] = None
        self.tor_ip: Optional[str] = None
        self._failed_hosts: Dict[str, int] = {}
        self._lock: asyncio.Lock = asyncio.Lock()

        # Tor connectivity verification endpoint
        self._tor_check_url: str = "https://check.torproject.org/api/ip"

    async def _create_session(self) -> aiohttp.ClientSession:
        """
        Creates an asynchronous aiohttp session with a SOCKS5 proxy connector.
        
        Returns:
            aiohttp.ClientSession: The configured asynchronous HTTP session.
        """
        connector = ProxyConnector.from_url(settings.tor_proxy_url)
        headers = {
            "User-Agent": settings.USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1"
        }
        return aiohttp.ClientSession(connector=connector, headers=headers)

    def _get_host(self, url: str) -> str:
        """
        Extracts the hostname (netloc) from a given URL.
        
        Args:
            url (str): The full URL string.
            
        Returns:
            str: The hostname extracted from the URL.
        """
        return urlparse(url).netloc

    def _get_timeout(self, url: str, explicit_timeout: Optional[int] = None) -> int:
        """
        Determines the appropriate timeout based on whether the URL is an onion service or clearnet.
        
        Args:
            url (str): The target URL.
            explicit_timeout (Optional[int]): User-defined timeout overriding defaults.
            
        Returns:
            int: Timeout value in seconds.
        """
        if explicit_timeout is not None:
            return explicit_timeout
        if ".onion" in url:
            return settings.ONION_TIMEOUT
        return settings.CLEARNET_TIMEOUT

    async def is_host_dead(self, url: str) -> bool:
        """
        Checks if the host is flagged as dead by the circuit breaker logic.
        
        Args:
            url (str): The target URL.
            
        Returns:
            bool: True if host has exceeded the failure threshold, False otherwise.
        """
        host = self._get_host(url)
        async with self._lock:
            return self._failed_hosts.get(host, 0) >= settings.CIRCUIT_BREAKER_THRESHOLD

    async def _record_failure(self, url: str) -> None:
        """
        Records a network failure for a specific host, incrementing its failure count.
        
        Args:
            url (str): The target URL.
        """
        host = self._get_host(url)
        async with self._lock:
            self._failed_hosts[host] = self._failed_hosts.get(host, 0) + 1

    async def _record_success(self, url: str) -> None:
        """
        Records a successful network operation, resetting the failure count for the host.
        
        Args:
            url (str): The target URL.
        """
        host = self._get_host(url)
        async with self._lock:
            self._failed_hosts.pop(host, None)

    async def reset_circuit_breaker(self) -> None:
        """Resets the circuit breaker by clearing the failed hosts registry."""
        async with self._lock:
            self._failed_hosts.clear()

    async def get_dead_hosts(self) -> List[str]:
        """
        Retrieves the list of hosts that have exceeded the failure threshold.
        
        Returns:
            List[str]: A list of dead hostnames.
        """
        async with self._lock:
            return [h for h, c in self._failed_hosts.items() if c >= settings.CIRCUIT_BREAKER_THRESHOLD]

    async def verify_tor_connection(self) -> bool:
        """
        Verifies the proxy connection and checks if the network exit node is part of the Tor network.
        
        Returns:
            bool: True if Tor connection is verified and operational, False otherwise.
        """
        console.print("\n[bold cyan][ TOR ] Bağlantı doğrulanıyor (Asenkron)...[/bold cyan]")
        console.print(f"  [dim]→ Deneniyor: {settings.tor_proxy_url}[/dim]")

        test_session = await self._create_session()
        timeout = aiohttp.ClientTimeout(total=20)

        try:
            async with test_session.get(self._tor_check_url, timeout=timeout) as response:
                response.raise_for_status()
                data = await response.json()

                if data.get("IsTor", False):
                    self.tor_ip = data.get("IP", "Bilinmiyor")
                    self.session = test_session  # Keep session active
                    console.print(f"  [bold green]✓ Tor bağlantısı aktif | Çıkış IP: {self.tor_ip}[/bold green]")
                    return True
                else:
                    console.print("  [yellow]✗ Proxy yanıt verdi ama Tor ağında değil.[/yellow]")

        except asyncio.TimeoutError:
            console.print(f"  [red]✗ Zaman aşımı: {settings.tor_proxy_url}[/red]")
        except aiohttp.ClientError as e:
            console.print(f"  [red]✗ Bağlantı reddedildi veya hata oluştu: {e}[/red]")
        except Exception as e:
            console.print(f"  [red]✗ Beklenmeyen sistem hatası: {e}[/red]")

        # Close session on failure
        await test_session.close()
        console.print("\n[bold red][ HATA ] Tor servisi asenkron bağlantısı kurulamadı.[/bold red]")
        console.print("[dim]Docker üzerinde 'torproxy' servisinin ayakta olduğundan veya yerel makinede çalıştığından emin olun.[/dim]\n")
        return False

    async def _execute_request(self, method: str, url: str, explicit_timeout: Optional[int] = None, **kwargs) -> Optional[aiohttp.ClientResponse]:
        """
        Core engine to execute HTTP methods asynchronously through the established Tor session.
        Implements automatic retries and exponential backoff.
        
        Args:
            method (str): HTTP method (e.g., 'GET', 'POST').
            url (str): The target URL.
            explicit_timeout (Optional[int]): Override default timeout.
            kwargs: Additional arguments passed to the HTTP request.
            
        Returns:
            Optional[aiohttp.ClientResponse]: The HTTP response object or None if failed.
        """
        if not self.session:
            console.print("[bold red][ HATA ] Asenkron Tor oturumu başlatılmadı. Lütfen verify_tor_connection çağrın.[/bold red]")
            return None

        if await self.is_host_dead(url):
            host = self._get_host(url)
            console.print(f"  [dim yellow]⊘ Atlanıyor (Circuit Breaker devrede): {host}[/dim yellow]")
            return None

        effective_timeout = self._get_timeout(url, explicit_timeout)
        client_timeout = aiohttp.ClientTimeout(total=effective_timeout)

        for attempt in range(1, settings.MAX_RETRIES + 1):
            try:
                request_method = getattr(self.session, method.lower())
                async with request_method(url, timeout=client_timeout, **kwargs) as response:
                    response.raise_for_status()
                    # To allow reading the payload outside this scope, we read it to buffer.
                    # Or depending on design, we return the content directly if needed.
                    # Given typical requests structure emulation, we will return a response object,
                    # however reading it completely is required in async context manager.
                    await response.read()
                    
                    await self._record_success(url)
                    return response

            except asyncio.TimeoutError:
                host = self._get_host(url)
                console.print(f"  [yellow]⏱ Zaman aşımı ({attempt}/{settings.MAX_RETRIES}): {host}[/yellow]")
            except aiohttp.ClientResponseError as e:
                console.print(f"  [yellow]⚠ HTTP Hatası ({e.status}): {url[:80]}...[/yellow]")
                # We do not retry 4xx errors usually, except 429
                if e.status not in [429, 500, 502, 503, 504]:
                    await self._record_failure(url)
                    return None
            except aiohttp.ClientError as e:
                host = self._get_host(url)
                console.print(f"  [yellow]⚡ Bağlantı hatası ({attempt}/{settings.MAX_RETRIES}): {host} | Hata: {e}[/yellow]")
            except Exception as e:
                console.print(f"  [red]✗ Beklenmeyen hata: {e}[/red]")
                break
                
            # If we reached here, it means we failed and need to retry (if attempts left)
            if attempt < settings.MAX_RETRIES:
                await asyncio.sleep(settings.RETRY_BACKOFF * attempt)

        # After max retries
        await self._record_failure(url)
        return None

    async def get(self, url: str, timeout: Optional[int] = None, **kwargs) -> Optional[aiohttp.ClientResponse]:
        """Performs an asynchronous GET request."""
        return await self._execute_request('GET', url, timeout, **kwargs)

    async def post(self, url: str, timeout: Optional[int] = None, **kwargs) -> Optional[aiohttp.ClientResponse]:
        """Performs an asynchronous POST request."""
        return await self._execute_request('POST', url, timeout, **kwargs)

    async def close(self) -> None:
        """Closes the underlying asynchronous HTTP session gracefully."""
        if self.session:
            await self.session.close()
            self.session = None
            self.tor_ip = None
