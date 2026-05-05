import sys
import time
import threading
from urllib.parse import urlparse
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from rich.console import Console

console = Console()

TOR_PROXIES_SOCKS = [
    {"http": "socks5h://127.0.0.1:9050", "https": "socks5h://127.0.0.1:9050"},
    {"http": "socks5h://127.0.0.1:9150", "https": "socks5h://127.0.0.1:9150"},
]

TOR_CHECK_URL = "https://check.torproject.org/api/ip"

ONION_TIMEOUT = 25
CLEARNET_TIMEOUT = 15
MAX_RETRIES = 0
RETRY_BACKOFF = 0.5
CIRCUIT_BREAKER_THRESHOLD = 1

DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate",
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1",
}


class TorHandler:

    def __init__(self):
        self.session = None
        self.active_proxy = None
        self.tor_ip = None
        self._failed_hosts: dict[str, int] = {}
        self._host_lock = threading.Lock()

    def _create_session(self, proxy_dict: dict) -> requests.Session:
        session = requests.Session()
        session.proxies.update(proxy_dict)
        session.headers.update(DEFAULT_HEADERS)

        retry_strategy = Retry(
            total=MAX_RETRIES,
            backoff_factor=RETRY_BACKOFF,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "POST"],
        )
        adapter = HTTPAdapter(
            max_retries=retry_strategy,
            pool_connections=20,
            pool_maxsize=20,
        )
        session.mount("http://", adapter)
        session.mount("https://", adapter)

        return session

    def _get_host(self, url: str) -> str:
        return urlparse(url).netloc

    def _get_timeout(self, url: str, explicit_timeout: int | None = None) -> int:
        if explicit_timeout is not None:
            return explicit_timeout
        if ".onion" in url:
            return ONION_TIMEOUT
        return CLEARNET_TIMEOUT

    def is_host_dead(self, url: str) -> bool:
        host = self._get_host(url)
        with self._host_lock:
            return self._failed_hosts.get(host, 0) >= CIRCUIT_BREAKER_THRESHOLD

    def _record_failure(self, url: str):
        host = self._get_host(url)
        with self._host_lock:
            self._failed_hosts[host] = self._failed_hosts.get(host, 0) + 1

    def _record_success(self, url: str):
        host = self._get_host(url)
        with self._host_lock:
            self._failed_hosts.pop(host, None)

    def reset_circuit_breaker(self):
        with self._host_lock:
            self._failed_hosts.clear()

    def get_dead_hosts(self) -> list[str]:
        with self._host_lock:
            return [h for h, c in self._failed_hosts.items() if c >= CIRCUIT_BREAKER_THRESHOLD]

    def verify_tor_connection(self) -> bool:
        console.print("\n[bold cyan][ TOR ] Bağlantı doğrulanıyor...[/bold cyan]")

        for proxy_dict in TOR_PROXIES_SOCKS:
            proxy_addr = proxy_dict["http"]
            console.print(f"  [dim]→ Deneniyor: {proxy_addr}[/dim]")

            test_session = self._create_session(proxy_dict)

            try:
                response = test_session.get(TOR_CHECK_URL, timeout=20)
                data = response.json()

                if data.get("IsTor", False):
                    self.tor_ip = data.get("IP", "Bilinmiyor")
                    self.active_proxy = proxy_dict
                    self.session = self._create_session(proxy_dict)
                    console.print(
                        f"  [bold green]✓ Tor bağlantısı aktif | Çıkış IP: {self.tor_ip}[/bold green]"
                    )
                    return True
                else:
                    console.print(
                        f"  [yellow]✗ Proxy yanıt verdi ama Tor ağında değil.[/yellow]"
                    )

            except requests.exceptions.ConnectionError:
                console.print(
                    f"  [red]✗ Bağlantı reddedildi: {proxy_addr}[/red]"
                )
            except requests.exceptions.Timeout:
                console.print(
                    f"  [red]✗ Zaman aşımı: {proxy_addr}[/red]"
                )
            except Exception as e:
                console.print(f"  [red]✗ Hata: {e}[/red]")
            finally:
                test_session.close()

        console.print(
            "\n[bold red][ HATA ] Tor servisi bulunamadı.[/bold red]"
        )
        console.print(
            "[dim]Tor Browser veya Tor servisinin çalıştığından emin olun.[/dim]"
        )
        console.print(
            "[dim]  → Linux/macOS: sudo systemctl start tor[/dim]"
        )
        console.print(
            "[dim]  → Windows: Tor Browser'ı açın ve arka planda çalışır durumda bırakın.[/dim]\n"
        )
        return False

    def check_connection(self) -> bool:
        if not self.session:
            return False
        try:
            response = self.session.get(TOR_CHECK_URL, timeout=10)
            if response.status_code == 200 and response.json().get("IsTor", False):
                self.tor_ip = response.json().get("IP", self.tor_ip)
                return True
        except Exception:
            pass
        return False

    def get(self, url: str, timeout: int | None = None, **kwargs) -> requests.Response | None:
        if not self.session:
            console.print("[bold red][ HATA ] Tor oturumu başlatılmadı.[/bold red]")
            return None

        if self.is_host_dead(url):
            host = self._get_host(url)
            console.print(f"  [dim yellow]⊘ Atlanıyor (önceki hatalarda başarısız): {host}[/dim yellow]")
            return None

        effective_timeout = self._get_timeout(url, timeout)

        try:
            response = self.session.get(url, timeout=effective_timeout, **kwargs)
            response.raise_for_status()
            self._record_success(url)
            return response

        except requests.exceptions.Timeout:
            self._record_failure(url)
            host = self._get_host(url)
            console.print(f"  [yellow]⏱ Zaman aşımı: {host}[/yellow]")
            return None
        except requests.exceptions.ConnectionError:
            self._record_failure(url)
            host = self._get_host(url)
            console.print(f"  [yellow]⚡ Bağlantı hatası: {host}[/yellow]")
            return None
        except requests.exceptions.HTTPError as e:
            console.print(f"  [yellow]⚠ HTTP hatası ({e.response.status_code}): {url[:80]}...[/yellow]")
            return None
        except Exception as e:
            self._record_failure(url)
            console.print(f"  [red]✗ Beklenmeyen hata: {e}[/red]")
            return None

    def post(self, url: str, timeout: int | None = None, **kwargs) -> requests.Response | None:
        if not self.session:
            console.print("[bold red][ HATA ] Tor oturumu başlatılmadı.[/bold red]")
            return None

        if self.is_host_dead(url):
            host = self._get_host(url)
            console.print(f"  [dim yellow]⊘ Atlanıyor (önceki hatalarda başarısız): {host}[/dim yellow]")
            return None

        effective_timeout = self._get_timeout(url, timeout)

        try:
            response = self.session.post(url, timeout=effective_timeout, **kwargs)
            response.raise_for_status()
            self._record_success(url)
            return response

        except requests.exceptions.Timeout:
            self._record_failure(url)
            host = self._get_host(url)
            console.print(f"  [yellow]⏱ Zaman aşımı: {host}[/yellow]")
            return None
        except requests.exceptions.ConnectionError:
            self._record_failure(url)
            host = self._get_host(url)
            console.print(f"  [yellow]⚡ Bağlantı hatası: {host}[/yellow]")
            return None
        except requests.exceptions.HTTPError as e:
            console.print(f"  [yellow]⚠ HTTP hatası ({e.response.status_code}): {url[:80]}...[/yellow]")
            return None
        except Exception as e:
            self._record_failure(url)
            console.print(f"  [red]✗ Beklenmeyen hata: {e}[/red]")
            return None

    def close(self):
        if self.session:
            self.session.close()
            self.session = None
            self.active_proxy = None
