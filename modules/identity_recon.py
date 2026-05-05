import time
import json
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from modules.darkweb_scraper import DarkWebScraper, ScanResult, display_results

console = Console()

DORKS = {
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


API_SOURCES = {
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

    def __init__(self, tor_handler):
        self.tor = tor_handler
        self.scraper = DarkWebScraper(tor_handler)

    def _check_api(self, name: str, url: str, timeout: int = 15, headers: dict = None) -> dict | None:
        try:
            resp = self.tor.get(url, timeout=timeout, headers=headers)
            if resp and resp.status_code == 200:
                try:
                    return resp.json()
                except Exception:
                    return None
        except Exception:
            pass
        return None

    def _run_email_apis(self, email: str) -> list[dict]:
        api_results = []

        console.print(f"\n[bold magenta][ API İSTİHBARAT ][/bold magenta]")


        console.print(f"  [dim cyan]→ EmailRep.io kontrol ediliyor...[/dim cyan]")
        data = self._check_api(
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
                status = "[bold red]● SIZINTI[/bold red]"
            elif suspicious or malicious:
                status = "[yellow]● ŞÜPHELİ[/yellow]"
            else:
                status = "[green]● TEMİZ[/green]"

            detail_parts = [f"İtibar: {reputation} | Referans: {references}"]
            if cred_leaked:
                detail_parts.append("[red]✗ Credential sızıntısı tespit edildi[/red]")
            if data_breach:
                detail_parts.append("[red]✗ Veri ihlali kaydı bulundu[/red]")
            if blacklisted:
                detail_parts.append("[yellow]✗ Kara listede[/yellow]")
            if spam:
                detail_parts.append("[yellow]✗ Spam kaydı[/yellow]")
            if disposable:
                detail_parts.append("[yellow]✗ Tek kullanımlık e-posta[/yellow]")
            if profiles:
                detail_parts.append(f"Profiller: {', '.join(profiles[:5])}")

            api_results.append({"source": "EmailRep.io", "status": status, "detail": "\n".join(detail_parts)})
            console.print(f"  [dim green]✓ EmailRep.io: {reputation}[/dim green]")
        else:
            api_results.append({
                "source": "EmailRep.io",
                "status": "[dim]● ATILDI[/dim]",
                "detail": "[dim]API yanıt vermedi (anonim erişim sınırlı olabilir)[/dim]",
            })
            console.print(f"  [dim yellow]✗ EmailRep.io: Yanıt alınamadı[/dim yellow]")


        console.print(f"  [dim cyan]→ E-posta format doğrulaması...[/dim cyan]")
        if "@" in email:
            domain = email.split("@")[1]
            mx_data = self._check_api("mx", f"https://dns.google/resolve?name={domain}&type=MX")
            if mx_data and mx_data.get("Answer"):
                api_results.append({
                    "source": "DNS/MX Kontrolü",
                    "status": "[green]● GEÇERLİ[/green]",
                    "detail": f"[dim]Domain {domain} aktif MX kaydına sahip[/dim]",
                })
                console.print(f"  [dim green]✓ MX kaydı: {domain} aktif[/dim green]")
            else:
                api_results.append({
                    "source": "DNS/MX Kontrolü",
                    "status": "[yellow]● BELİRSİZ[/yellow]",
                    "detail": f"[dim]Domain {domain} MX kaydı bulunamadı[/dim]",
                })
                console.print(f"  [dim yellow]✗ MX kaydı bulunamadı[/dim yellow]")

        return api_results

    def _display_api_table(self, api_results: list[dict]):
        if not api_results:
            return
        table = Table(
            title="[bold]API İSTİHBARAT SONUÇLARI[/bold]",
            box=box.ROUNDED, show_lines=True,
            border_style="bright_black", header_style="bold cyan", width=110,
        )
        table.add_column("#", style="dim", width=4, justify="center")
        table.add_column("Kaynak", style="bold", width=20)
        table.add_column("Durum", width=14, justify="center")
        table.add_column("Detay", width=68)
        for idx, r in enumerate(api_results, 1):
            table.add_row(str(idx), r["source"], r["status"], r["detail"])
        console.print(table)
        console.print()

    def _run_search(self, target: str, category: str, label: str):
        dorks = DORKS.get(category, ['"{target}"'])
        all_results = []
        api_results = []

        console.print(f"\n[bold white][ TARAMA ] {label} taranıyor: {target}[/bold white]")


        if category == "email":
            api_results = self._run_email_apis(target)


        console.print(f"\n[dim]  {len(dorks)} dork sorgusu taranacak...[/dim]")
        start = time.time()

        with Progress(
            SpinnerColumn("dots"),
            TextColumn("[bold cyan]{task.description}"),
            BarColumn(bar_width=30),
            TextColumn("[dim]{task.completed}/{task.total}"),
            TimeElapsedColumn(),
            console=console, transient=True,
        ) as progress:
            task = progress.add_task(f"  Dork Tarama", total=len(dorks))

            for dork_template in dorks:
                dork = dork_template.replace("{target}", target)
                console.print(f"\n[dim]  Dork: {dork}[/dim]")
                results = self.scraper.search(target=dork, sources="all")
                all_results.extend(results)
                progress.advance(task)

        elapsed = time.time() - start

        if api_results:
            self._display_api_table(api_results)

        display_results(target, label, all_results, elapsed)
        return all_results

    def search_email(self, target: str):
        return self._run_search(target, "email", "E-posta OSINT")

    def search_username(self, target: str):
        return self._run_search(target, "username", "Kullanıcı Adı Profilleme")

    def search_phone(self, target: str):
        return self._run_search(target, "phone", "Telefon Numarası İzleme")

    def search_name(self, target: str):
        return self._run_search(target, "name", "İsim Araştırma")

    def search_domain(self, target: str):
        return self._run_search(target, "domain", "Domain / Organizasyon")

    def search_hash(self, target: str):
        return self._run_search(target, "hash", "Hash Kontrolü")

    def search_social(self, target: str):
        return self._run_search(target, "social", "Sosyal Medya Handle")

    def search_address(self, target: str):
        return self._run_search(target, "address", "Fiziksel Adres Arama")
