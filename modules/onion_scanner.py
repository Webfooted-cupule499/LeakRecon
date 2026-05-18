import os
import time
import asyncio
from typing import Any, List, Tuple, Optional

from bs4 import BeautifulSoup
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

console = Console()


class OnionScanner:
    """
    Onion hidden service analysis module.

    Provides status checking, header analysis, metadata extraction,
    technology detection, link extraction, and bulk scanning capabilities
    for .onion addresses through the Tor network.
    """

    def __init__(self, tor_handler: Any) -> None:
        """
        Initializes the OnionScanner module.

        Args:
            tor_handler: The TorHandler instance for proxied network operations.
        """
        self.tor = tor_handler

    def _ensure_url(self, url: str) -> str:
        """
        Normalizes a URL to include the HTTP scheme if absent.

        Args:
            url (str): The raw URL input.

        Returns:
            str: The normalized URL with scheme.
        """
        if not url.startswith("http"):
            return f"http://{url}"
        return url

    async def check_status(self, onion_url: str) -> None:
        """
        Checks the availability and response metrics of an onion service.

        Args:
            onion_url (str): The .onion URL to check.
        """
        onion_url = self._ensure_url(onion_url)
        console.print(f"\n  [bold white][ ONION ] Status check: {onion_url}[/bold white]")
        start = time.time()

        try:
            response = await self.tor.get(onion_url, timeout=60)
            elapsed = time.time() - start

            if response:
                content = await response.read()
                console.print(Panel(
                    f"[bold green]ONLINE[/bold green]\n\n"
                    f"  [white]URL:[/white] {onion_url}\n"
                    f"  [white]Status Code:[/white] {response.status}\n"
                    f"  [white]Response Time:[/white] {elapsed:.2f}s\n"
                    f"  [white]Content-Length:[/white] {len(content)} bytes",
                    title="[bold cyan]ONION STATUS[/bold cyan]",
                    border_style="green", box=box.ROUNDED,
                ))
            else:
                console.print(Panel(
                    f"[bold red]OFFLINE[/bold red]\n\n"
                    f"  [white]URL:[/white] {onion_url}\n"
                    f"  [white]Attempt Duration:[/white] {time.time() - start:.2f}s",
                    title="[bold cyan]ONION STATUS[/bold cyan]",
                    border_style="red", box=box.ROUNDED,
                ))
        except Exception as e:
            console.print(f"  [bold red][ ERROR ] {e}[/bold red]")

    async def http_headers(self, onion_url: str) -> None:
        """
        Retrieves and displays HTTP response headers from an onion service.

        Args:
            onion_url (str): The .onion URL to analyze.
        """
        onion_url = self._ensure_url(onion_url)
        console.print(f"\n  [bold white][ HEADER ] Onion HTTP headers: {onion_url}[/bold white]")

        try:
            response = await self.tor.get(onion_url, timeout=60)
            if response:
                table = Table(
                    title="[bold]ONION HTTP HEADERS[/bold]",
                    box=box.ROUNDED, show_lines=True,
                    border_style="cyan", header_style="bold cyan", width=90,
                )
                table.add_column("Header", style="bold white", width=30)
                table.add_column("Value", style="white", width=56)

                table.add_row("Status Code", f"[bold]{response.status}[/bold]")
                for key, val in response.headers.items():
                    table.add_row(key, val[:80])

                console.print()
                console.print(table)
            else:
                console.print("  [bold red][ ERROR ] No response received.[/bold red]")
        except Exception as e:
            console.print(f"  [bold red][ ERROR ] {e}[/bold red]")

    async def page_meta(self, onion_url: str) -> None:
        """
        Extracts and displays page metadata from an onion service.

        Args:
            onion_url (str): The .onion URL to analyze.
        """
        onion_url = self._ensure_url(onion_url)
        console.print(f"\n  [bold white][ META ] Page metadata: {onion_url}[/bold white]")

        try:
            response = await self.tor.get(onion_url, timeout=60)
            if response:
                text = await response.text()
                soup = BeautifulSoup(text, "lxml")
                title = soup.title.string.strip() if soup.title and soup.title.string else "N/A"
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
                    title="[bold]PAGE METADATA[/bold]",
                    box=box.ROUNDED, show_lines=True,
                    border_style="cyan", header_style="bold cyan", width=80,
                )
                table.add_column("Field", style="bold white", width=25)
                table.add_column("Value", style="white", width=51)

                table.add_row("URL", onion_url)
                table.add_row("Title", title)
                table.add_row("Description", desc or "[dim]N/A[/dim]")
                table.add_row("Keywords", keywords or "[dim]N/A[/dim]")
                table.add_row("Generator", generator or "[dim]N/A[/dim]")
                table.add_row("Links", str(len(soup.find_all("a"))))
                table.add_row("Images", str(len(soup.find_all("img"))))
                table.add_row("Forms", str(len(soup.find_all("form"))))
                table.add_row("Scripts", str(len(soup.find_all("script"))))

                console.print()
                console.print(table)
            else:
                console.print("  [bold red][ ERROR ] No response received.[/bold red]")
        except Exception as e:
            console.print(f"  [bold red][ ERROR ] {e}[/bold red]")

    async def detect_tech(self, onion_url: str) -> None:
        """
        Performs passive technology fingerprinting on an onion service.

        Args:
            onion_url (str): The .onion URL to analyze.
        """
        onion_url = self._ensure_url(onion_url)
        console.print(f"\n  [bold white][ TECH ] Technology detection: {onion_url}[/bold white]")

        try:
            response = await self.tor.get(onion_url, timeout=60)
            if response:
                techs: List[Tuple[str, str]] = []
                headers = response.headers
                html = (await response.text()).lower()

                if headers.get("Server"):
                    techs.append(("Server", headers["Server"]))
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
                    title="[bold]TECHNOLOGY DETECTION[/bold]",
                    box=box.ROUNDED, show_lines=True,
                    border_style="cyan", header_style="bold cyan", width=80,
                )
                table.add_column("Category", style="bold white", width=25)
                table.add_column("Value", style="white", width=51)

                if techs:
                    for cat, val in techs:
                        table.add_row(cat, val)
                else:
                    table.add_row("[dim]-[/dim]", "[dim]No technologies detected[/dim]")

                console.print()
                console.print(table)
            else:
                console.print("  [bold red][ ERROR ] No response received.[/bold red]")
        except Exception as e:
            console.print(f"  [bold red][ ERROR ] {e}[/bold red]")

    async def bulk_scan(self, file_path: str) -> None:
        """
        Performs bulk availability scanning from a file containing onion URLs.

        Args:
            file_path (str): Path to the text file containing one URL per line.
        """
        if not os.path.isfile(file_path):
            console.print(f"  [bold red][ ERROR ] File not found: {file_path}[/bold red]")
            return

        with open(file_path, "r", encoding="utf-8") as f:
            urls = [line.strip() for line in f if line.strip() and not line.startswith("#")]

        if not urls:
            console.print("  [bold yellow]No valid onion addresses found in file.[/bold yellow]")
            return

        console.print(f"\n  [bold white][ BULK ] Scanning {len(urls)} onion addresses...[/bold white]\n")

        table = Table(
            title="[bold]BULK ONION SCAN[/bold]",
            box=box.ROUNDED, show_lines=True,
            border_style="cyan", header_style="bold cyan", width=100,
        )
        table.add_column("#", style="dim", width=4, justify="center")
        table.add_column("Onion Address", style="white", width=60)
        table.add_column("Status", width=14, justify="center")
        table.add_column("Response", width=14, justify="center")

        for idx, url in enumerate(urls, 1):
            url = self._ensure_url(url)
            console.print(f"    [dim]-> [{idx}/{len(urls)}] {url}[/dim]")
            start = time.time()

            try:
                response = await self.tor.get(url, timeout=45)
                elapsed = time.time() - start
                if response:
                    table.add_row(str(idx), url, "[bold green]ONLINE[/bold green]", f"{elapsed:.1f}s")
                else:
                    table.add_row(str(idx), url, "[bold red]OFFLINE[/bold red]", "-")
            except Exception:
                table.add_row(str(idx), url, "[yellow]ERROR[/yellow]", "-")

        console.print()
        console.print(table)

    async def download_page(self, onion_url: str, output_path: str = "") -> None:
        """
        Downloads and saves the HTML source of an onion page.

        Args:
            onion_url (str): The .onion URL to download.
            output_path (str): Optional custom output file path.
        """
        onion_url = self._ensure_url(onion_url)
        console.print(f"\n  [bold white][ DOWNLOAD ] Downloading page: {onion_url}[/bold white]")

        try:
            response = await self.tor.get(onion_url, timeout=60)
            if response:
                text = await response.text()
                if not output_path:
                    safe = onion_url.replace("http://", "").replace("https://", "")
                    safe = "".join(c if c.isalnum() or c in ".-_" else "_" for c in safe)
                    output_path = f"output_{safe[:50]}.html"

                with open(output_path, "w", encoding="utf-8") as f:
                    f.write(text)

                console.print(Panel(
                    f"[bold green]Page saved successfully[/bold green]\n\n"
                    f"  [white]URL:[/white] {onion_url}\n"
                    f"  [white]File:[/white] {output_path}\n"
                    f"  [white]Size:[/white] {len(text)} characters",
                    title="[bold cyan]PAGE DOWNLOAD[/bold cyan]",
                    border_style="green", box=box.ROUNDED,
                ))
            else:
                console.print("  [bold red][ ERROR ] No response received.[/bold red]")
        except Exception as e:
            console.print(f"  [bold red][ ERROR ] {e}[/bold red]")

    async def extract_links(self, onion_url: str) -> None:
        """
        Extracts and tabulates all hyperlinks from an onion page.

        Args:
            onion_url (str): The .onion URL to crawl.
        """
        onion_url = self._ensure_url(onion_url)
        console.print(f"\n  [bold white][ LINK ] Extracting links: {onion_url}[/bold white]")

        try:
            response = await self.tor.get(onion_url, timeout=60)
            if response:
                text = await response.text()
                soup = BeautifulSoup(text, "lxml")
                links: List[Tuple[str, str]] = []

                for a in soup.find_all("a", href=True):
                    href = a["href"]
                    text_content = a.get_text(strip=True)[:40]
                    if href.startswith(("http", "/", "#")):
                        links.append((href, text_content))

                table = Table(
                    title=f"[bold]EXTRACTED LINKS ({len(links)} total)[/bold]",
                    box=box.ROUNDED, show_lines=True,
                    border_style="cyan", header_style="bold cyan", width=100,
                )
                table.add_column("#", style="dim", width=4, justify="center")
                table.add_column("URL", style="white", width=60)
                table.add_column("Text", style="dim", width=32)

                for idx, (href, text_content) in enumerate(links[:50], 1):
                    is_onion = "[bold cyan]" if ".onion" in href else ""
                    end = "[/bold cyan]" if ".onion" in href else ""
                    table.add_row(str(idx), f"{is_onion}{href[:58]}{end}", text_content)

                console.print()
                console.print(table)

                if len(links) > 50:
                    console.print(f"  [dim]... and {len(links) - 50} more links[/dim]")
            else:
                console.print("  [bold red][ ERROR ] No response received.[/bold red]")
        except Exception as e:
            console.print(f"  [bold red][ ERROR ] {e}[/bold red]")

    async def save_text(self, onion_url: str) -> None:
        """
        Extracts and saves the plain text content of an onion page.

        Args:
            onion_url (str): The .onion URL to process.
        """
        onion_url = self._ensure_url(onion_url)
        console.print(f"\n  [bold white][ TEXT ] Extracting plain text: {onion_url}[/bold white]")

        try:
            response = await self.tor.get(onion_url, timeout=60)
            if response:
                html = await response.text()
                soup = BeautifulSoup(html, "lxml")
                text = soup.get_text(separator="\n", strip=True)

                safe = onion_url.replace("http://", "").replace("https://", "")
                safe = "".join(c if c.isalnum() or c in ".-_" else "_" for c in safe)
                filename = f"text_{safe[:50]}.txt"

                with open(filename, "w", encoding="utf-8") as f:
                    f.write(text)

                console.print(Panel(
                    f"[bold green]Text saved successfully[/bold green]\n\n"
                    f"  [white]File:[/white] {filename}\n"
                    f"  [white]Size:[/white] {len(text)} characters\n"
                    f"  [white]Lines:[/white] {text.count(chr(10)) + 1}",
                    title="[bold cyan]TEXT EXTRACTION[/bold cyan]",
                    border_style="green", box=box.ROUNDED,
                ))
            else:
                console.print("  [bold red][ ERROR ] No response received.[/bold red]")
        except Exception as e:
            console.print(f"  [bold red][ ERROR ] {e}[/bold red]")
