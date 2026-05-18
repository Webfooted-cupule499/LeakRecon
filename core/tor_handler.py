import asyncio
import logging
from typing import Optional, List, Dict
from urllib.parse import urlparse

import aiohttp
from aiohttp_socks import ProxyConnector

from config import settings

logger = logging.getLogger(__name__)


class TorHandler:
    """
    Enterprise-grade asynchronous network handler for Tor routing.
    
    Provides high-concurrency SOCKS5 proxying via aiohttp with built-in
    resilience, aggressive circuit breaking, and exponential backoff mechanisms.
    """

    def __init__(self) -> None:
        """Initializes the TorHandler with configuration state and circuit breaker metrics."""
        self.session: Optional[aiohttp.ClientSession] = None
        self.tor_ip: Optional[str] = None
        self._failed_hosts: Dict[str, int] = {}
        self._lock: asyncio.Lock = asyncio.Lock()

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
        Determines the appropriate timeout based on the target zone (clearnet vs onion).
        
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
        Evaluates the health status of a host based on the circuit breaker thresholds.
        
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
        Registers a network failure for a specific host, incrementing its fault counter.
        
        Args:
            url (str): The target URL.
        """
        host = self._get_host(url)
        async with self._lock:
            self._failed_hosts[host] = self._failed_hosts.get(host, 0) + 1

    async def _record_success(self, url: str) -> None:
        """
        Registers a successful network operation, resetting the fault counter for the host.
        
        Args:
            url (str): The target URL.
        """
        host = self._get_host(url)
        async with self._lock:
            self._failed_hosts.pop(host, None)

    async def reset_circuit_breaker(self) -> None:
        """Clears the circuit breaker registry, resetting all host fault states."""
        async with self._lock:
            self._failed_hosts.clear()

    async def get_dead_hosts(self) -> List[str]:
        """
        Retrieves the list of hosts currently blacklisted by the circuit breaker.
        
        Returns:
            List[str]: A list of dead hostnames.
        """
        async with self._lock:
            return [h for h, c in self._failed_hosts.items() if c >= settings.CIRCUIT_BREAKER_THRESHOLD]

    async def verify_tor_connection(self) -> bool:
        """
        Verifies the proxy connection and validates the Tor network exit node.
        
        Returns:
            bool: True if Tor connection is verified and operational, False otherwise.
        """
        logging.info("Verifying Tor connection asynchronously...")
        test_session = await self._create_session()
        timeout = aiohttp.ClientTimeout(total=20)

        try:
            async with test_session.get(settings.TOR_CHECK_URL, timeout=timeout) as response:
                response.raise_for_status()
                data = await response.json()

                if data.get("IsTor", False):
                    self.tor_ip = data.get("IP", "Unknown")
                    self.session = test_session
                    logging.info(f"Tor connection verified. Exit IP: {self.tor_ip}")
                    return True
                else:
                    logging.warning("Proxy responded, but it is not routing through the Tor network.")

        except asyncio.TimeoutError:
            logging.error(f"Timeout occurred while verifying proxy at {settings.tor_proxy_url}.")
        except aiohttp.ClientError as e:
            logging.error(f"Connection refused or error occurred: {e}")
        except Exception as e:
            logging.error(f"Unexpected system error during proxy verification: {e}")

        await test_session.close()
        logging.critical("Failed to establish asynchronous Tor connection.")
        return False

    async def _execute_request(self, method: str, url: str, explicit_timeout: Optional[int] = None, **kwargs) -> Optional[aiohttp.ClientResponse]:
        """
        Core engine to execute HTTP methods asynchronously through the established Tor session.
        Implements automatic retries, exponential backoff, and circuit breaking.
        
        Args:
            method (str): HTTP method (e.g., 'GET', 'POST').
            url (str): The target URL.
            explicit_timeout (Optional[int]): Override default timeout.
            kwargs: Additional arguments passed to the HTTP request.
            
        Returns:
            Optional[aiohttp.ClientResponse]: The HTTP response object or None if failed.
        """
        if not self.session:
            logging.error("Asynchronous Tor session not initialized. Call verify_tor_connection first.")
            return None

        if await self.is_host_dead(url):
            host = self._get_host(url)
            logging.debug(f"Request skipped (Circuit Breaker active) for host: {host}")
            return None

        effective_timeout = self._get_timeout(url, explicit_timeout)
        client_timeout = aiohttp.ClientTimeout(total=effective_timeout)

        for attempt in range(1, settings.MAX_RETRIES + 1):
            try:
                request_method = getattr(self.session, method.lower())
                async with request_method(url, timeout=client_timeout, **kwargs) as response:
                    response.raise_for_status()
                    await response.read()
                    await self._record_success(url)
                    return response

            except asyncio.TimeoutError:
                logging.warning(f"Timeout ({attempt}/{settings.MAX_RETRIES}) for host: {self._get_host(url)}")
            except aiohttp.ClientResponseError as e:
                logging.warning(f"HTTP Error ({e.status}) for URL: {url}")
                if e.status not in [429, 500, 502, 503, 504]:
                    await self._record_failure(url)
                    return None
            except aiohttp.ClientError as e:
                logging.warning(f"Connection Error ({attempt}/{settings.MAX_RETRIES}) for host: {self._get_host(url)}. Details: {e}")
            except Exception as e:
                logging.error(f"Unexpected error during request execution: {e}")
                break
                
            if attempt < settings.MAX_RETRIES:
                await asyncio.sleep(settings.RETRY_BACKOFF * attempt)

        await self._record_failure(url)
        return None

    async def get(self, url: str, timeout: Optional[int] = None, **kwargs) -> Optional[aiohttp.ClientResponse]:
        """
        Executes an asynchronous HTTP GET request.
        
        Args:
            url (str): The target URL.
            timeout (Optional[int]): Custom timeout override.
            kwargs: Additional aiohttp request parameters.
            
        Returns:
            Optional[aiohttp.ClientResponse]: The response object if successful, None otherwise.
        """
        return await self._execute_request('GET', url, timeout, **kwargs)

    async def post(self, url: str, timeout: Optional[int] = None, **kwargs) -> Optional[aiohttp.ClientResponse]:
        """
        Executes an asynchronous HTTP POST request.
        
        Args:
            url (str): The target URL.
            timeout (Optional[int]): Custom timeout override.
            kwargs: Additional aiohttp request parameters.
            
        Returns:
            Optional[aiohttp.ClientResponse]: The response object if successful, None otherwise.
        """
        return await self._execute_request('POST', url, timeout, **kwargs)

    async def close(self) -> None:
        """Terminates the asynchronous HTTP session gracefully and resets state."""
        if self.session:
            await self.session.close()
            self.session = None
            self.tor_ip = None
