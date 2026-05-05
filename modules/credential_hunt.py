import time
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from modules.darkweb_scraper import DarkWebScraper, display_results

console = Console()

CREDENTIAL_DORKS = {
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

    def __init__(self, tor_handler):
        self.scraper = DarkWebScraper(tor_handler)

    def _run_hunt(self, target: str, category: str, label: str):
        dorks = CREDENTIAL_DORKS.get(category, ['"{target}"'])
        all_results = []

        console.print(f"\n[bold white][ HUNT ] {label}: {target}[/bold white]")
        console.print(f"[dim]  {len(dorks)} dork sorgusu taranacak...[/dim]")
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
            task = progress.add_task(f"  Credential Tarama", total=len(dorks))

            for dork_template in dorks:
                dork = dork_template.replace("{target}", target)
                console.print(f"\n[dim]  Dork: {dork}[/dim]")
                results = self.scraper.search(target=dork, sources="all")
                all_results.extend(results)
                progress.advance(task)

        elapsed = time.time() - start
        display_results(target, label, all_results, elapsed)
        return all_results

    def email_leak(self, target: str):
        return self._run_hunt(target, "email_leak", "E-posta Sızıntı Taraması")

    def user_pass(self, target: str):
        return self._run_hunt(target, "user_pass", "Kullanıcı:Parola Arama")

    def combo_search(self, target: str):
        return self._run_hunt(target, "combo", "Combo List Taraması")

    def database_dump(self, target: str):
        return self._run_hunt(target, "database", "Veritabanı Dump Arama")

    def paste_search(self, target: str):
        return self._run_hunt(target, "paste", "Paste Site Taraması")

    def hash_search(self, target: str):
        return self._run_hunt(target, "hash", "Hash Arama")

    def stealer_search(self, target: str):
        return self._run_hunt(target, "stealer", "Stealer Log Taraması")

    def forum_search(self, target: str):
        return self._run_hunt(target, "forum", "Forum Sızıntı Taraması")
