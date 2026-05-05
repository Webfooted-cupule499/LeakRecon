import os
import time
from bs4 import BeautifulSoup
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

console = Console()


class OnionScanner:

    def __init__(self, tor_handler):
        self.tor = tor_handler

    def _ensure_url(self, url: str) -> str:
        if not url.startswith("http"):
            return f"http://{url}"
        return url

    def check_status(self, onion_url: str):
        onion_url = self._ensure_url(onion_url)
        console.print(f"\n  [bold white][ ONION ] Durum kontrolü: {onion_url}[/bold white]")
        start = time.time()

        try:
            resp = self.tor.get(onion_url, timeout=60)
            elapsed = time.time() - start

            if resp:
                console.print(Panel(
                    f"[bold green]● ÇEVRİMİÇİ[/bold green]\n\n"
                    f"  [white]URL:[/white] {onion_url}\n"
                    f"  [white]Status Code:[/white] {resp.status_code}\n"
                    f"  [white]Yanıt Süresi:[/white] {elapsed:.2f}s\n"
                    f"  [white]Content-Length:[/white] {len(resp.content)} byte",
                    title="[bold cyan]ONION DURUM[/bold cyan]",
                    border_style="green", box=box.ROUNDED,
                ))
            else:
                console.print(Panel(
                    f"[bold red]● ÇEVRİMDIŞI[/bold red]\n\n"
                    f"  [white]URL:[/white] {onion_url}\n"
                    f"  [white]Deneme Süresi:[/white] {time.time() - start:.2f}s",
                    title="[bold cyan]ONION DURUM[/bold cyan]",
                    border_style="red", box=box.ROUNDED,
                ))
        except Exception as e:
            console.print(f"  [bold red][ HATA ] {e}[/bold red]")

    def http_headers(self, onion_url: str):
        onion_url = self._ensure_url(onion_url)
        console.print(f"\n  [bold white][ HEADER ] Onion HTTP headers: {onion_url}[/bold white]")

        try:
            resp = self.tor.get(onion_url, timeout=60)
            if resp:
                table = Table(
                    title="[bold]ONION HTTP HEADERS[/bold]",
                    box=box.ROUNDED, show_lines=True,
                    border_style="cyan", header_style="bold cyan", width=90,
                )
                table.add_column("Header", style="bold white", width=30)
                table.add_column("Değer", style="white", width=56)

                table.add_row("Status Code", f"[bold]{resp.status_code}[/bold]")
                for key, val in resp.headers.items():
                    table.add_row(key, val[:80])

                console.print()
                console.print(table)
            else:
                console.print("  [bold red][ HATA ] Yanıt alınamadı.[/bold red]")
        except Exception as e:
            console.print(f"  [bold red][ HATA ] {e}[/bold red]")

    def page_meta(self, onion_url: str):
        onion_url = self._ensure_url(onion_url)
        console.print(f"\n  [bold white][ META ] Sayfa meta bilgileri: {onion_url}[/bold white]")

        try:
            resp = self.tor.get(onion_url, timeout=60)
            if resp:
                soup = BeautifulSoup(resp.text, "lxml")
                title = soup.title.string.strip() if soup.title and soup.title.string else "Yok"
                desc = ""
                keywords = ""
                generator = ""

                for meta in soup.find_all("meta"):
                    name = (meta.get("name") or meta.get("property") or "").lower()
                    content = meta.get("content", "")
                    if name == "description":
                        desc = content
                    elif name == "keywords":
                        keywords = content
                    elif name == "generator":
                        generator = content

                table = Table(
                    title="[bold]SAYFA META BİLGİLERİ[/bold]",
                    box=box.ROUNDED, show_lines=True,
                    border_style="cyan", header_style="bold cyan", width=80,
                )
                table.add_column("Alan", style="bold white", width=25)
                table.add_column("Değer", style="white", width=51)

                table.add_row("URL", onion_url)
                table.add_row("Başlık", title)
                table.add_row("Açıklama", desc or "[dim]Yok[/dim]")
                table.add_row("Anahtar Kelimeler", keywords or "[dim]Yok[/dim]")
                table.add_row("Generator", generator or "[dim]Yok[/dim]")
                table.add_row("Link Sayısı", str(len(soup.find_all("a"))))
                table.add_row("Görsel Sayısı", str(len(soup.find_all("img"))))
                table.add_row("Form Sayısı", str(len(soup.find_all("form"))))
                table.add_row("Script Sayısı", str(len(soup.find_all("script"))))

                console.print()
                console.print(table)
            else:
                console.print("  [bold red][ HATA ] Yanıt alınamadı.[/bold red]")
        except Exception as e:
            console.print(f"  [bold red][ HATA ] {e}[/bold red]")

    def detect_tech(self, onion_url: str):
        onion_url = self._ensure_url(onion_url)
        console.print(f"\n  [bold white][ TECH ] Teknoloji tespiti: {onion_url}[/bold white]")

        try:
            resp = self.tor.get(onion_url, timeout=60)
            if resp:
                techs = []
                headers = resp.headers
                html = resp.text.lower()

                if headers.get("Server"):
                    techs.append(("Sunucu", headers["Server"]))
                if headers.get("X-Powered-By"):
                    techs.append(("Framework", headers["X-Powered-By"]))
                if headers.get("Content-Type"):
                    techs.append(("Content-Type", headers["Content-Type"]))

                if "wp-content" in html or "wordpress" in html:
                    techs.append(("CMS", "WordPress"))
                elif "joomla" in html:
                    techs.append(("CMS", "Joomla"))
                elif "drupal" in html:
                    techs.append(("CMS", "Drupal"))
                if "jquery" in html:
                    techs.append(("JS", "jQuery"))
                if "react" in html or "__next" in html:
                    techs.append(("JS", "React / Next.js"))
                if "vue" in html:
                    techs.append(("JS", "Vue.js"))
                if "bootstrap" in html:
                    techs.append(("CSS", "Bootstrap"))
                if "flask" in html or "werkzeug" in (headers.get("Server", "").lower()):
                    techs.append(("Backend", "Flask / Werkzeug"))
                if "django" in html:
                    techs.append(("Backend", "Django"))
                if "nginx" in (headers.get("Server", "").lower()):
                    techs.append(("Proxy", "Nginx"))
                if "apache" in (headers.get("Server", "").lower()):
                    techs.append(("Proxy", "Apache"))

                if headers.get("Content-Security-Policy"):
                    techs.append(("CSP", headers["Content-Security-Policy"][:60]))
                if headers.get("Strict-Transport-Security"):
                    techs.append(("HSTS", headers["Strict-Transport-Security"]))
                if headers.get("X-Frame-Options"):
                    techs.append(("X-Frame-Options", headers["X-Frame-Options"]))

                table = Table(
                    title="[bold]TEKNOLOJİ TESPİTİ[/bold]",
                    box=box.ROUNDED, show_lines=True,
                    border_style="cyan", header_style="bold cyan", width=80,
                )
                table.add_column("Kategori", style="bold white", width=25)
                table.add_column("Değer", style="white", width=51)

                if techs:
                    for cat, val in techs:
                        table.add_row(cat, val)
                else:
                    table.add_row("[dim]—[/dim]", "[dim]Tespit edilen teknoloji yok[/dim]")

                console.print()
                console.print(table)
            else:
                console.print("  [bold red][ HATA ] Yanıt alınamadı.[/bold red]")
        except Exception as e:
            console.print(f"  [bold red][ HATA ] {e}[/bold red]")

    def bulk_scan(self, file_path: str):
        if not os.path.isfile(file_path):
            console.print(f"  [bold red][ HATA ] Dosya bulunamadı: {file_path}[/bold red]")
            return

        with open(file_path, "r", encoding="utf-8") as f:
            urls = [line.strip() for line in f if line.strip() and not line.startswith("#")]

        if not urls:
            console.print("  [bold yellow]Dosyada geçerli onion adresi bulunamadı.[/bold yellow]")
            return

        console.print(f"\n  [bold white][ TOPLU ] {len(urls)} onion taranıyor...[/bold white]\n")

        table = Table(
            title="[bold]TOPLU ONION TARAMA[/bold]",
            box=box.ROUNDED, show_lines=True,
            border_style="cyan", header_style="bold cyan", width=100,
        )
        table.add_column("#", style="dim", width=4, justify="center")
        table.add_column("Onion Adresi", style="white", width=60)
        table.add_column("Durum", width=14, justify="center")
        table.add_column("Yanıt", width=14, justify="center")

        for idx, url in enumerate(urls, 1):
            url = self._ensure_url(url)
            console.print(f"    [dim]→ [{idx}/{len(urls)}] {url}[/dim]")
            start = time.time()

            try:
                resp = self.tor.get(url, timeout=45)
                elapsed = time.time() - start
                if resp:
                    table.add_row(str(idx), url, "[bold green]● AÇIK[/bold green]", f"{elapsed:.1f}s")
                else:
                    table.add_row(str(idx), url, "[bold red]● KAPALI[/bold red]", "-")
            except Exception:
                table.add_row(str(idx), url, "[yellow]● HATA[/yellow]", "-")

        console.print()
        console.print(table)

    def download_page(self, onion_url: str, output_path: str = ""):
        onion_url = self._ensure_url(onion_url)
        console.print(f"\n  [bold white][ İNDİR ] Sayfa indiriliyor: {onion_url}[/bold white]")

        try:
            resp = self.tor.get(onion_url, timeout=60)
            if resp:
                if not output_path:
                    safe = onion_url.replace("http://", "").replace("https://", "")
                    safe = "".join(c if c.isalnum() or c in ".-_" else "_" for c in safe)
                    output_path = f"output_{safe[:50]}.html"

                with open(output_path, "w", encoding="utf-8") as f:
                    f.write(resp.text)

                console.print(Panel(
                    f"[bold green]✓ Sayfa kaydedildi[/bold green]\n\n"
                    f"  [white]URL:[/white] {onion_url}\n"
                    f"  [white]Dosya:[/white] {output_path}\n"
                    f"  [white]Boyut:[/white] {len(resp.text)} karakter",
                    title="[bold cyan]SAYFA İNDİRME[/bold cyan]",
                    border_style="green", box=box.ROUNDED,
                ))
            else:
                console.print("  [bold red][ HATA ] Yanıt alınamadı.[/bold red]")
        except Exception as e:
            console.print(f"  [bold red][ HATA ] {e}[/bold red]")

    def extract_links(self, onion_url: str):
        onion_url = self._ensure_url(onion_url)
        console.print(f"\n  [bold white][ LINK ] Link çıkarılıyor: {onion_url}[/bold white]")

        try:
            resp = self.tor.get(onion_url, timeout=60)
            if resp:
                soup = BeautifulSoup(resp.text, "lxml")
                links = []

                for a in soup.find_all("a", href=True):
                    href = a["href"]
                    text = a.get_text(strip=True)[:40]
                    if href.startswith(("http", "/", "#")):
                        links.append((href, text))

                table = Table(
                    title=f"[bold]ÇIKARILAN LİNKLER ({len(links)} adet)[/bold]",
                    box=box.ROUNDED, show_lines=True,
                    border_style="cyan", header_style="bold cyan", width=100,
                )
                table.add_column("#", style="dim", width=4, justify="center")
                table.add_column("URL", style="white", width=60)
                table.add_column("Metin", style="dim", width=32)

                for idx, (href, text) in enumerate(links[:50], 1):
                    is_onion = "[bold cyan]" if ".onion" in href else ""
                    end = "[/bold cyan]" if ".onion" in href else ""
                    table.add_row(str(idx), f"{is_onion}{href[:58]}{end}", text)

                console.print()
                console.print(table)

                if len(links) > 50:
                    console.print(f"  [dim]... ve {len(links) - 50} link daha[/dim]")
            else:
                console.print("  [bold red][ HATA ] Yanıt alınamadı.[/bold red]")
        except Exception as e:
            console.print(f"  [bold red][ HATA ] {e}[/bold red]")

    def save_text(self, onion_url: str):
        onion_url = self._ensure_url(onion_url)
        console.print(f"\n  [bold white][ TEXT ] Düz metin çıkarılıyor: {onion_url}[/bold white]")

        try:
            resp = self.tor.get(onion_url, timeout=60)
            if resp:
                soup = BeautifulSoup(resp.text, "lxml")
                text = soup.get_text(separator="\n", strip=True)

                safe = onion_url.replace("http://", "").replace("https://", "")
                safe = "".join(c if c.isalnum() or c in ".-_" else "_" for c in safe)
                filename = f"text_{safe[:50]}.txt"

                with open(filename, "w", encoding="utf-8") as f:
                    f.write(text)

                console.print(Panel(
                    f"[bold green]✓ Metin kaydedildi[/bold green]\n\n"
                    f"  [white]Dosya:[/white] {filename}\n"
                    f"  [white]Boyut:[/white] {len(text)} karakter\n"
                    f"  [white]Satır:[/white] {text.count(chr(10)) + 1}",
                    title="[bold cyan]METİN ÇIKARMA[/bold cyan]",
                    border_style="green", box=box.ROUNDED,
                ))
            else:
                console.print("  [bold red][ HATA ] Yanıt alınamadı.[/bold red]")
        except Exception as e:
            console.print(f"  [bold red][ HATA ] {e}[/bold red]")
