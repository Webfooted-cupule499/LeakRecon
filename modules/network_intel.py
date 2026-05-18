import socket
import struct
import time
import asyncio
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box
from modules.darkweb_scraper import DarkWebScraper, display_results

console = Console()

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995,
                1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 8888, 27017]

PORT_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 135: "MSRPC", 139: "NetBIOS", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S", 1433: "MSSQL",
    1521: "Oracle", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    5900: "VNC", 6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
    8888: "HTTP-Alt2", 27017: "MongoDB",
}


class NetworkIntel:

    def __init__(self, tor_handler):
        self.tor = tor_handler
        self.scraper = DarkWebScraper(tor_handler)
        from config import settings
        self._proxy_host = settings.TOR_PROXY_HOST
        self._proxy_port = settings.TOR_PROXY_PORT

    async def _socks5_connect(self, target_host: str, target_port: int, timeout: int = 10) -> bool:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self._proxy_host, self._proxy_port),
                timeout=timeout
            )

            writer.write(b"\x05\x01\x00")
            await writer.drain()
            resp = await asyncio.wait_for(reader.read(2), timeout=timeout)
            if resp != b"\x05\x00":
                writer.close()
                await writer.wait_closed()
                return False

            addr_bytes = target_host.encode("utf-8")
            req = b"\x05\x01\x00\x03" + bytes([len(addr_bytes)]) + addr_bytes + struct.pack("!H", target_port)
            writer.write(req)
            await writer.drain()

            resp = await asyncio.wait_for(reader.read(10), timeout=timeout)
            writer.close()
            await writer.wait_closed()
            return len(resp) >= 2 and resp[1] == 0x00

        except Exception:
            return False

    async def ip_geolocation(self, ip: str):
        console.print(f"\n[bold white][ GEO ] IP Geolocation sorgulanıyor: {ip}[/bold white]")
        start = time.time()

        try:
            response = await self.tor.get(f"http://ip-api.com/json/{ip}?lang=tr", timeout=30)
            if response and response.status == 200:
                data = await response.json()
                elapsed = time.time() - start

                table = Table(
                    title=f"[bold]IP GEOLOCATİON: {ip}[/bold]",
                    box=box.ROUNDED, show_lines=True,
                    border_style="cyan", header_style="bold cyan", width=70,
                )
                table.add_column("Alan", style="bold white", width=25)
                table.add_column("Değer", style="white", width=41)

                fields = [
                    ("IP", data.get("query", ip)),
                    ("Durum", data.get("status", "?")),
                    ("Ülke", data.get("country", "?")),
                    ("Ülke Kodu", data.get("countryCode", "?")),
                    ("Bölge", data.get("regionName", "?")),
                    ("Şehir", data.get("city", "?")),
                    ("Posta Kodu", data.get("zip", "?")),
                    ("Enlem", str(data.get("lat", "?"))),
                    ("Boylam", str(data.get("lon", "?"))),
                    ("Zaman Dilimi", data.get("timezone", "?")),
                    ("ISP", data.get("isp", "?")),
                    ("Organizasyon", data.get("org", "?")),
                    ("AS", data.get("as", "?")),
                ]
                for k, v in fields:
                    table.add_row(k, v)

                console.print()
                console.print(table)
                console.print(f"\n[dim]Süre: {elapsed:.1f}s | Tüm trafik Tor üzerinden[/dim]\n")
            else:
                console.print("[bold red][ HATA ] Geolocation yanıtı alınamadı.[/bold red]")
        except Exception as e:
            console.print(f"[bold red][ HATA ] {e}[/bold red]")

    async def reverse_dns(self, ip: str):
        console.print(f"\n[bold white][ DNS ] Reverse DNS sorgulanıyor: {ip}[/bold white]")

        try:
            loop = asyncio.get_running_loop()
            hostname, _, _ = await loop.run_in_executor(None, socket.gethostbyaddr, ip)
            console.print(Panel(
                f"[bold white]IP:[/bold white] {ip}\n[bold white]Hostname:[/bold white] [green]{hostname}[/green]",
                title="[bold cyan]REVERSE DNS[/bold cyan]",
                border_style="green", box=box.ROUNDED,
            ))
        except socket.herror:
            console.print(Panel(
                f"[bold white]IP:[/bold white] {ip}\n[bold white]Hostname:[/bold white] [yellow]Çözümlenemedi[/yellow]",
                title="[bold cyan]REVERSE DNS[/bold cyan]",
                border_style="yellow", box=box.ROUNDED,
            ))
        except Exception as e:
            console.print(f"[bold red][ HATA ] {e}[/bold red]")

    async def port_scan(self, target: str, ports: list[int] | None = None):
        scan_ports = ports or COMMON_PORTS
        console.print(f"\n[bold white][ PORT ] Port taraması başlatılıyor: {target}[/bold white]")
        console.print(f"[dim]  {len(scan_ports)} port taranacak (Tor SOCKS üzerinden)[/dim]\n")

        start = time.time()
        open_ports = []
        closed_count = 0

        for port in scan_ports:
            service = PORT_SERVICES.get(port, "Unknown")
            console.print(f"  [dim]→ {port}/{service}...[/dim]", end="")

            is_open = await self._socks5_connect(target, port, timeout=10)
            if is_open:
                open_ports.append((port, service))
                console.print(f" [bold green]AÇIK[/bold green]")
            else:
                closed_count += 1
                console.print(f" [dim]kapalı[/dim]")

        elapsed = time.time() - start

        console.print()
        table = Table(
            title=f"[bold]PORT TARAMA SONUÇLARI: {target}[/bold]",
            box=box.ROUNDED, show_lines=True,
            border_style="cyan", header_style="bold cyan", width=60,
        )
        table.add_column("Port", style="bold", width=10, justify="center")
        table.add_column("Servis", style="white", width=20)
        table.add_column("Durum", width=15, justify="center")

        if open_ports:
            for port, service in open_ports:
                table.add_row(str(port), service, "[bold green]● AÇIK[/bold green]")
        else:
            table.add_row("-", "-", "[dim]Açık port bulunamadı[/dim]")

        console.print(table)
        console.print(
            f"\n[dim]Açık: {len(open_ports)} | Kapalı: {closed_count} | "
            f"Süre: {elapsed:.1f}s | Tor SOCKS proxy[/dim]\n"
        )

    async def tor_exit_check(self, ip: str):
        console.print(f"\n[bold white][ TOR ] Tor çıkış düğümü kontrolü: {ip}[/bold white]")

        try:
            response = await self.tor.get(
                "https://check.torproject.org/torbulkexitlist", timeout=30
            )
            if response and response.status == 200:
                text = await response.text()
                exit_nodes = text.strip().split("\n")
                exit_nodes = [line.strip() for line in exit_nodes if not line.startswith("#")]

                if ip in exit_nodes:
                    console.print(Panel(
                        f"[bold red]⚠  {ip} bir Tor çıkış düğümüdür![/bold red]\n"
                        f"[dim]Toplam bilinen çıkış düğümü: {len(exit_nodes)}[/dim]",
                        title="[bold cyan]TOR EXIT NODE[/bold cyan]",
                        border_style="red", box=box.ROUNDED,
                    ))
                else:
                    console.print(Panel(
                        f"[bold green]✓  {ip} bir Tor çıkış düğümü değildir.[/bold green]\n"
                        f"[dim]Toplam bilinen çıkış düğümü: {len(exit_nodes)}[/dim]",
                        title="[bold cyan]TOR EXIT NODE[/bold cyan]",
                        border_style="green", box=box.ROUNDED,
                    ))
            else:
                console.print("[bold red][ HATA ] Tor exit list alınamadı.[/bold red]")
        except Exception as e:
            console.print(f"[bold red][ HATA ] {e}[/bold red]")

    async def ip_reputation(self, ip: str):
        console.print(f"\n[bold white][ İTİBAR ] IP dark web itibar analizi: {ip}[/bold white]")
        start = time.time()
        results = await self.scraper.search(ip, dork="blacklist abuse spam malware botnet")
        elapsed = time.time() - start
        display_results(ip, "IP İtibar Analizi", results, elapsed)

    async def fetch_headers(self, url: str):
        console.print(f"\n[bold white][ HEADER ] HTTP header çekiliyor: {url}[/bold white]")

        try:
            response = await self.tor.get(url, timeout=30)
            if response:
                table = Table(
                    title=f"[bold]HTTP HEADERS[/bold]",
                    box=box.ROUNDED, show_lines=True,
                    border_style="cyan", header_style="bold cyan", width=90,
                )
                table.add_column("Header", style="bold white", width=30)
                table.add_column("Değer", style="white", width=56)

                table.add_row("Status Code", f"[bold green]{response.status}[/bold green]")
                for key, value in response.headers.items():
                    table.add_row(key, value[:80])

                console.print()
                console.print(table)
                console.print()
            else:
                console.print("[bold red][ HATA ] Yanıt alınamadı.[/bold red]")
        except Exception as e:
            console.print(f"[bold red][ HATA ] {e}[/bold red]")

    async def whois_lookup(self, target: str):
        console.print(f"\n[bold white][ WHOIS ] WHOIS sorgulanıyor: {target}[/bold white]")

        try:
            response = await self.tor.get(f"https://whois.arin.net/rest/ip/{target}.json", timeout=30)
            if response and response.status == 200:
                data = await response.json()
                net = data.get("net", {})

                table = Table(
                    title="[bold]WHOIS SONUÇLARI[/bold]",
                    box=box.ROUNDED, show_lines=True,
                    border_style="cyan", header_style="bold cyan", width=70,
                )
                table.add_column("Alan", style="bold white", width=25)
                table.add_column("Değer", style="white", width=41)

                handle = net.get("handle", {})
                name = net.get("name", {})
                ref = net.get("ref", {})
                start_addr = net.get("startAddress", {})
                end_addr = net.get("endAddress", {})

                table.add_row("Handle", handle.get("$", "?") if isinstance(handle, dict) else str(handle))
                table.add_row("İsim", name.get("$", "?") if isinstance(name, dict) else str(name))
                table.add_row("Referans", ref.get("$", "?") if isinstance(ref, dict) else str(ref))
                table.add_row("Başlangıç IP", start_addr.get("$", "?") if isinstance(start_addr, dict) else str(start_addr))
                table.add_row("Bitiş IP", end_addr.get("$", "?") if isinstance(end_addr, dict) else str(end_addr))

                console.print()
                console.print(table)
                console.print()
            else:
                response2 = await self.tor.get(f"https://rdap.org/domain/{target}", timeout=30)
                if response2 and response2.status == 200:
                    data = await response2.json()
                    table = Table(
                        title="[bold]WHOIS / RDAP SONUÇLARI[/bold]",
                        box=box.ROUNDED, show_lines=True,
                        border_style="cyan", header_style="bold cyan", width=70,
                    )
                    table.add_column("Alan", style="bold white", width=25)
                    table.add_column("Değer", style="white", width=41)

                    table.add_row("Domain", data.get("ldhName", target))
                    table.add_row("Durum", ", ".join(data.get("status", ["?"])))

                    for event in data.get("events", []):
                        table.add_row(event.get("eventAction", "?"), event.get("eventDate", "?"))

                    console.print()
                    console.print(table)
                    console.print()
                else:
                    console.print("[bold red][ HATA ] WHOIS bilgisi alınamadı.[/bold red]")
        except Exception as e:
            console.print(f"[bold red][ HATA ] {e}[/bold red]")
