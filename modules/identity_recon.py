import time
import asyncio
import json
from typing import List, Dict, Any, Optional

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from modules.darkweb_scraper import DarkWebScraper, ScanResult, display_results

console = Console()

DORKS: Dict[str, List[str]] = {
    "email": [
        '"{target}"',
        '"{target}" password',
        '"{target}" leak',
        '"{target}" breach',
        '"{target}" database',
        '"{target}" dump',
        '"{target}" credentials',
        '"{target}" hacked',
        '"{target}" pastebin',
        '"{target}" combolist',
    ],
    "username": [
        '"{target}"',
        '"{target}" account',
        '"{target}" profile',
        '"{target}" login',
        '"{target}" credentials',
        '"{target}" leak',
        '"{target}" hacked',
        '"{target}" doxxed',
        '"{target}" forum',
        '"{target}" darknet',
    ],
    "phone": [
        '"{target}"',
        '"{target}" leak',
        '"{target}" doxxed',
        '"{target}" info',
        '"{target}" owner',
        '"{target}" database',
        '"{target}" whatsapp',
        '"{target}" telegram',
    ],
    "name": [
        '"{target}"',
        '"{target}" personal',
        '"{target}" doxxed',
        '"{target}" info',
        '"{target}" address',
        '"{target}" leak',
        '"{target}" ssn',
        '"{target}" identity',
    ],
    "domain": [
        '"{target}"',
        '"{target}" breach',
        '"{target}" database',
        '"{target}" hack',
        '"{target}" leak',
        '"{target}" dump',
        '"{target}" credentials',
        '"{target}" sql injection',
        '"{target}" admin panel',
        '"{target}" vulnerability',
    ],
    "hash": [
        '"{target}"',
        '"{target}" password',
        '"{target}" crack',
        '"{target}" dehash',
        '"{target}" plaintext',
        '"{target}" rainbow',
    ],
    "social": [
        '"{target}" instagram',
        '"{target}" twitter',
        '"{target}" facebook',
        '"{target}" tiktok',
        '"{target}" discord',
        '"{target}" telegram',
        '"{target}" linkedin',
        '"{target}" darknet',
        '"{target}" doxxed',
        '"{target}" leak',
    ],
    "address": [
        '"{target}"',
        '"{target}" doxxed',
        '"{target}" owner',
        '"{target}" resident',
        '"{target}" personal info',
        '"{target}" leak',
    ],
}


API_SOURCES: Dict[str, Dict[str, Any]] = {
    "emailrep": {
        "name": "EmailRep.io",
        "url": "https://emailrep.io/{target}",
        "headers": {"Accept": "application/json"},
        "timeout": 15,
    },
    "breachdirectory": {
        "name": "BreachDirectory",
        "url": "https://breachdirectory.p.rapidapi.com/?func=auto&term={target}",
        "timeout": 15,
    },
}


class IdentityRecon:
    """
    Identity reconnaissance module for multi-vector OSINT profiling.

    Performs dork-based dark web searches combined with clearnet API intelligence
    gathering for email, username, phone, name, domain, and hash targets.
    """

    def __init__(self, tor_handler: Any) -> None:
        """
        Initializes the IdentityRecon module.

        Args:
            tor_handler: The TorHandler instance for proxied network operations.
        """
        self.tor = tor_handler
        self.scraper = DarkWebScraper(tor_handler)

    async def _check_api(self, name: str, url: str, timeout: int = 15, headers: Optional[Dict[str, str]] = None) -> Optional[Dict[str, Any]]:
        """
        Queries a clearnet API endpoint through Tor and returns parsed JSON.

        Args:
            name (str): Identifier for the API source.
            url (str): The API endpoint URL.
            timeout (int): Request timeout in seconds.
            headers (Optional[Dict[str, str]]): Additional HTTP headers.

        Returns:
            Optional[Dict[str, Any]]: Parsed JSON response or None on failure.
        """
        try:
            response = await self.tor.get(url, timeout=timeout, headers=headers)
            if response and response.status == 200:
                try:
                    return await response.json()
                except Exception:
                    return None
        except Exception:
            pass
        return None

    async def _run_email_apis(self, email: str) -> List[Dict[str, str]]:
        """
        Executes API-based intelligence checks for an email target.

        Args:
            email (str): The email address to investigate.

        Returns:
            List[Dict[str, str]]: List of API result dictionaries.
        """
        api_results: List[Dict[str, str]] = []

        console.print(f"\n[bold magenta][ API INTELLIGENCE ][/bold magenta]")

        console.print(f"  [dim cyan]-> EmailRep.io querying...[/dim cyan]")
        data = await self._check_api(
            "emailrep", f"https://emailrep.io/{email}",
            headers={"Accept": "application/json"},
        )
        if data:
            reputation = data.get("reputation", "?")
            suspicious = data.get("suspicious", False)
            details = data.get("details", {})
            cred_leaked = details.get("credentials_leaked", False)
            data_breach = details.get("data_breach", False)
            malicious = details.get("malicious_activity", False)
            blacklisted = details.get("blacklisted", False)
            profiles = details.get("profiles", [])
            references = data.get("references", 0)
            spam = details.get("spam", False)
            disposable = details.get("disposable", False)

            if cred_leaked or data_breach:
                status = "[bold red]LEAK DETECTED[/bold red]"
            elif suspicious or malicious:
                status = "[yellow]SUSPICIOUS[/yellow]"
            else:
                status = "[green]CLEAN[/green]"

            detail_parts = [f"Reputation: {reputation} | References: {references}"]
            if cred_leaked:
                detail_parts.append("[red]Credential leak detected[/red]")
            if data_breach:
                detail_parts.append("[red]Data breach record found[/red]")
            if blacklisted:
                detail_parts.append("[yellow]Blacklisted[/yellow]")
            if spam:
                detail_parts.append("[yellow]Spam record[/yellow]")
            if disposable:
                detail_parts.append("[yellow]Disposable email[/yellow]")
            if profiles:
                detail_parts.append(f"Profiles: {', '.join(profiles[:5])}")

            api_results.append({"source": "EmailRep.io", "status": status, "detail": "\n".join(detail_parts)})
            console.print(f"  [dim green]OK EmailRep.io: {reputation}[/dim green]")
        else:
            api_results.append({
                "source": "EmailRep.io",
                "status": "[dim]SKIPPED[/dim]",
                "detail": "[dim]API did not respond (anonymous access may be limited)[/dim]",
            })
            console.print(f"  [dim yellow]WARN EmailRep.io: No response[/dim yellow]")

        console.print(f"  [dim cyan]-> Email format validation...[/dim cyan]")
        if "@" in email:
            domain = email.split("@")[1]
            mx_data = await self._check_api("mx", f"https://dns.google/resolve?name={domain}&type=MX")
            if mx_data and mx_data.get("Answer"):
                api_results.append({
                    "source": "DNS/MX Check",
                    "status": "[green]VALID[/green]",
                    "detail": f"[dim]Domain {domain} has active MX records[/dim]",
                })
                console.print(f"  [dim green]OK MX record: {domain} active[/dim green]")
            else:
                api_results.append({
                    "source": "DNS/MX Check",
                    "status": "[yellow]UNCERTAIN[/yellow]",
                    "detail": f"[dim]Domain {domain} MX record not found[/dim]",
                })
                console.print(f"  [dim yellow]WARN MX record not found[/dim yellow]")

        return api_results

    def _display_api_table(self, api_results: List[Dict[str, str]]) -> None:
        """
        Renders API intelligence results as a formatted table.

        Args:
            api_results (List[Dict[str, str]]): List of API result dictionaries.
        """
        if not api_results:
            return
        table = Table(
            title="[bold]API INTELLIGENCE RESULTS[/bold]",
            box=box.ROUNDED, show_lines=True,
            border_style="bright_black", header_style="bold cyan", width=110,
        )
        table.add_column("#", style="dim", width=4, justify="center")
        table.add_column("Source", style="bold", width=20)
        table.add_column("Status", width=14, justify="center")
        table.add_column("Details", width=68)
        for idx, r in enumerate(api_results, 1):
            table.add_row(str(idx), r["source"], r["status"], r["detail"])
        console.print(table)
        console.print()

    async def _run_search(self, target: str, category: str, label: str) -> List[ScanResult]:
        """
        Executes a dork-based search across all configured sources.

        Args:
            target (str): The search target.
            category (str): The dork category key.
            label (str): Display label for the scan operation.

        Returns:
            List[ScanResult]: Aggregated scan results.
        """
        dorks = DORKS.get(category, ['"{target}"'])
        all_results: List[ScanResult] = []
        api_results: List[Dict[str, str]] = []

        console.print(f"\n[bold white][ SCAN ] {label}: {target}[/bold white]")

        if category == "email":
            api_results = await self._run_email_apis(target)

        console.print(f"\n[dim]  {len(dorks)} dork queries to process...[/dim]")
        start = time.time()

        with Progress(
            SpinnerColumn("dots"),
            TextColumn("[bold cyan]{task.description}"),
            BarColumn(bar_width=30),
            TextColumn("[dim]{task.completed}/{task.total}"),
            TimeElapsedColumn(),
            console=console, transient=True,
        ) as progress:
            task = progress.add_task(f"  Dork Scan", total=len(dorks))

            for dork_template in dorks:
                dork = dork_template.replace("{target}", target)
                console.print(f"\n[dim]  Dork: {dork}[/dim]")
                results = await self.scraper.search(target=dork, sources="all")
                all_results.extend(results)
                progress.advance(task)

        elapsed = time.time() - start

        if api_results:
            self._display_api_table(api_results)

        display_results(target, label, all_results, elapsed)
        return all_results

    async def search_email(self, target: str) -> List[ScanResult]:
        """Performs email-based OSINT reconnaissance."""
        return await self._run_search(target, "email", "E-posta OSINT")

    async def search_username(self, target: str) -> List[ScanResult]:
        """Performs username-based profiling across dark web sources."""
        return await self._run_search(target, "username", "Kullanıcı Adı Profilleme")

    async def search_phone(self, target: str) -> List[ScanResult]:
        """Performs phone number tracking across dark web sources."""
        return await self._run_search(target, "phone", "Telefon Numarası İzleme")

    async def search_name(self, target: str) -> List[ScanResult]:
        """Performs name-based reconnaissance across dark web sources."""
        return await self._run_search(target, "name", "İsim Araştırma")

    async def search_domain(self, target: str) -> List[ScanResult]:
        """Performs domain/organization reconnaissance across dark web sources."""
        return await self._run_search(target, "domain", "Domain / Organizasyon")

    async def search_hash(self, target: str) -> List[ScanResult]:
        """Performs hash lookup across dark web sources."""
        return await self._run_search(target, "hash", "Hash Kontrolü")

    async def search_social(self, target: str) -> List[ScanResult]:
        """Performs social media handle reconnaissance across dark web sources."""
        return await self._run_search(target, "social", "Sosyal Medya Handle")

    async def search_address(self, target: str) -> List[ScanResult]:
        """Performs physical address reconnaissance across dark web sources."""
        return await self._run_search(target, "address", "Fiziksel Adres Arama")
