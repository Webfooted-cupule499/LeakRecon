import time
import asyncio
from typing import List, Dict, Any

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from modules.darkweb_scraper import DarkWebScraper, ScanResult, display_results

console = Console()

CREDENTIAL_DORKS: Dict[str, List[str]] = {
    "email_leak": [
        '"{target}" password',
        '"{target}" leak dump',
        '"{target}" credentials',
        '"{target}" combo',
        '"{target}" database breach',
        '"{target}" hacked account',
        '"{target}" plaintext',
        '"{target}" infostealer',
    ],
    "user_pass": [
        '"{target}" password',
        '"{target}" login credentials',
        '"{target}" account hack',
        '"{target}" user:pass',
        '"{target}" credential leak',
        '"{target}" stolen account',
    ],
    "combo": [
        '"{target}" combolist',
        '"{target}" combo list',
        '"{target}" user:pass',
        '"{target}" email:pass',
        '"{target}" combo leak',
        '"{target}" credential dump',
        '"{target}" stealer log',
    ],
    "database": [
        '"{target}" SQL dump',
        '"{target}" database leak',
        '"{target}" .sql dump',
        '"{target}" table users',
        '"{target}" breach data',
        '"{target}" db dump download',
        '"{target}" mysql dump',
        '"{target}" mongodb leak',
    ],
    "paste": [
        '"{target}" paste',
        '"{target}" pastebin',
        '"{target}" ghostbin',
        '"{target}" leaked',
        '"{target}" rentry',
        '"{target}" paste.ee',
        '"{target}" hastebin',
    ],
    "hash": [
        '"{target}"',
        '"{target}" crack',
        '"{target}" dehash',
        '"{target}" decrypt',
        '"{target}" rainbow',
        '"{target}" plaintext password',
        '"{target}" hash lookup',
    ],
    "stealer": [
        '"{target}" stealer log',
        '"{target}" redline',
        '"{target}" raccoon stealer',
        '"{target}" vidar',
        '"{target}" infostealer',
        '"{target}" browser saved password',
    ],
    "forum": [
        '"{target}" forum leak',
        '"{target}" darknet forum',
        '"{target}" underground market',
        '"{target}" exploit forum',
        '"{target}" cracked database',
    ],
}


class CredentialHunt:
    """
    Credential intelligence module for dark web leak detection.

    Searches across multiple dark web sources for credential leaks,
    combo lists, database dumps, paste sites, stealer logs, and forum posts.
    """

    def __init__(self, tor_handler: Any) -> None:
        """
        Initializes the CredentialHunt module.

        Args:
            tor_handler: The TorHandler instance for proxied network operations.
        """
        self.scraper = DarkWebScraper(tor_handler)

    async def _run_hunt(self, target: str, category: str, label: str) -> List[ScanResult]:
        """
        Executes a credential-specific dork search across all sources.

        Args:
            target (str): The search target (email, domain, hash, etc.).
            category (str): The dork category key.
            label (str): Display label for the scan operation.

        Returns:
            List[ScanResult]: Aggregated scan results.
        """
        dorks = CREDENTIAL_DORKS.get(category, ['"{target}"'])
        all_results: List[ScanResult] = []

        console.print(f"\n[bold white][ HUNT ] {label}: {target}[/bold white]")
        console.print(f"[dim]  {len(dorks)} dork queries to process...[/dim]")
        start = time.time()

        with Progress(
            SpinnerColumn("dots"),
            TextColumn("[bold cyan]{task.description}"),
            BarColumn(bar_width=30),
            TextColumn("[dim]{task.completed}/{task.total}"),
            TimeElapsedColumn(),
            console=console,
            transient=True,
        ) as progress:
            task = progress.add_task(f"  Credential Scan", total=len(dorks))

            for dork_template in dorks:
                dork = dork_template.replace("{target}", target)
                console.print(f"\n[dim]  Dork: {dork}[/dim]")
                results = await self.scraper.search(target=dork, sources="all")
                all_results.extend(results)
                progress.advance(task)

        elapsed = time.time() - start
        display_results(target, label, all_results, elapsed)
        return all_results

    async def email_leak(self, target: str) -> List[ScanResult]:
        """Searches for email credential leaks across dark web sources."""
        return await self._run_hunt(target, "email_leak", "E-posta Sızıntı Taraması")

    async def user_pass(self, target: str) -> List[ScanResult]:
        """Searches for user:password credential pairs."""
        return await self._run_hunt(target, "user_pass", "Kullanıcı:Parola Arama")

    async def combo_search(self, target: str) -> List[ScanResult]:
        """Searches for combo lists containing the target."""
        return await self._run_hunt(target, "combo", "Combo List Taraması")

    async def database_dump(self, target: str) -> List[ScanResult]:
        """Searches for database dumps containing the target."""
        return await self._run_hunt(target, "database", "Veritabanı Dump Arama")

    async def paste_search(self, target: str) -> List[ScanResult]:
        """Searches paste sites for sensitive data containing the target."""
        return await self._run_hunt(target, "paste", "Paste Site Taraması")

    async def hash_search(self, target: str) -> List[ScanResult]:
        """Searches for hash cracking results on dark web sources."""
        return await self._run_hunt(target, "hash", "Hash Arama")

    async def stealer_search(self, target: str) -> List[ScanResult]:
        """Searches for infostealer log references containing the target."""
        return await self._run_hunt(target, "stealer", "Stealer Log Taraması")

    async def forum_search(self, target: str) -> List[ScanResult]:
        """Searches underground forums for leak references."""
        return await self._run_hunt(target, "forum", "Forum Sızıntı Taraması")
