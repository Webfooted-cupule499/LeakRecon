import re
import time
import asyncio
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from modules.darkweb_scraper import DarkWebScraper, display_results

console = Console()

BTC_REGEX = re.compile(r"^(1|3|bc1)[a-zA-HJ-NP-Z0-9]{25,62}$")
ETH_REGEX = re.compile(r"^0x[0-9a-fA-F]{40}$")
XMR_REGEX = re.compile(r"^4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}$")

CRYPTO_DORKS = {
    "btc": [
        '"{target}"',
        '"{target}" bitcoin',
        '"{target}" wallet',
        '"{target}" transaction',
        '"{target}" scam',
        '"{target}" darknet market',
        '"{target}" mixer tumbler',
        '"{target}" stolen funds',
    ],
    "eth": [
        '"{target}"',
        '"{target}" ethereum',
        '"{target}" wallet',
        '"{target}" smart contract',
        '"{target}" scam',
        '"{target}" rug pull',
        '"{target}" stolen',
    ],
    "xmr": [
        '"{target}"',
        '"{target}" monero',
        '"{target}" wallet',
        '"{target}" payment',
        '"{target}" darknet',
        '"{target}" ransom payment',
    ],
    "wallet_assoc": [
        '"{target}" mixer',
        '"{target}" tumbler',
        '"{target}" exchange',
        '"{target}" marketplace',
        '"{target}" vendor',
        '"{target}" laundering',
    ],
    "ransomware": [
        '"{target}" ransomware',
        '"{target}" ransom',
        '"{target}" decrypt',
        '"{target}" payment demand',
        '"{target}" locked files',
        '"{target}" lockbit',
        '"{target}" conti',
    ],
}


class CryptoTracker:

    def __init__(self, tor_handler):
        self.tor = tor_handler
        self.scraper = DarkWebScraper(tor_handler)

    def _validate_address(self, address: str, crypto_type: str) -> bool:
        validators = {"btc": BTC_REGEX, "eth": ETH_REGEX, "xmr": XMR_REGEX}
        pattern = validators.get(crypto_type)
        if pattern:
            return bool(pattern.match(address))
        return True

    async def _check_btc_blockchain(self, address: str):
        console.print(f"\n[bold magenta][ BLOCKCHAİN API ][/bold magenta]")
        console.print(f"  [dim cyan]→ blockchain.info kontrol ediliyor...[/dim cyan]")
        try:
            response = await self.tor.get(f"https://blockchain.info/rawaddr/{address}?limit=5", timeout=15)
            if response and response.status == 200:
                data = await response.json()
                balance = data.get("final_balance", 0) / 1e8
                total_recv = data.get("total_received", 0) / 1e8
                total_sent = data.get("total_sent", 0) / 1e8
                n_tx = data.get("n_tx", 0)

                table = Table(
                    title="[bold]BTC ADRES BİLGİSİ[/bold]",
                    box=box.ROUNDED, show_lines=True,
                    border_style="cyan", header_style="bold cyan", width=70,
                )
                table.add_column("Alan", style="bold white", width=25)
                table.add_column("Değer", style="white", width=41)
                table.add_row("Adres", address[:20] + "..." + address[-8:])
                table.add_row("Bakiye", f"{balance:.8f} BTC")
                table.add_row("Toplam Alınan", f"{total_recv:.8f} BTC")
                table.add_row("Toplam Gönderilen", f"{total_sent:.8f} BTC")
                table.add_row("İşlem Sayısı", str(n_tx))
                console.print()
                console.print(table)
                console.print(f"  [dim green]✓ Blockchain verisi alındı[/dim green]")
            else:
                console.print(f"  [dim yellow]✗ Blockchain yanıt alınamadı[/dim yellow]")
        except Exception:
            console.print(f"  [dim yellow]✗ Blockchain API hatası[/dim yellow]")

    async def _check_btc_blockcypher(self, address: str):
        console.print(f"  [dim cyan]→ blockcypher.com kontrol ediliyor...[/dim cyan]")
        try:
            response = await self.tor.get(f"https://api.blockcypher.com/v1/btc/main/addrs/{address}/balance", timeout=15)
            if response and response.status == 200:
                data = await response.json()
                balance = data.get("balance", 0) / 1e8
                unconfirmed = data.get("unconfirmed_balance", 0) / 1e8
                n_tx = data.get("n_tx", 0)
                console.print(f"    [white]BlockCypher:[/white] Bakiye={balance:.8f} BTC | "
                              f"Onaysız={unconfirmed:.8f} BTC | İşlem={n_tx}")
        except Exception:
            pass

    async def _run_search(self, target: str, category: str, label: str, crypto_type: str = ""):
        if crypto_type and not self._validate_address(target, crypto_type):
            console.print(f"[bold red][ HATA ] Geçersiz {crypto_type.upper()} adres formatı.[/bold red]")
            return []

        dorks = CRYPTO_DORKS.get(category, ['"{target}"'])
        all_results = []

        console.print(f"\n[bold white][ KRİPTO ] {label}: {target[:20]}...{target[-8:]}[/bold white]")

        if crypto_type == "btc":
            await self._check_btc_blockchain(target)
            await self._check_btc_blockcypher(target)

        console.print(f"\n[dim]  {len(dorks)} dork sorgusu taranacak...[/dim]")
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
            task = progress.add_task(f"  Kripto Tarama", total=len(dorks))

            for dork_template in dorks:
                dork = dork_template.replace("{target}", target)
                console.print(f"\n[dim]  Dork: {dork[:60]}...[/dim]")
                results = await self.scraper.search(target=dork, sources="all")
                all_results.extend(results)
                progress.advance(task)

        elapsed = time.time() - start
        display_results(target, label, all_results, elapsed)
        return all_results

    async def search_btc(self, address: str):
        return await self._run_search(address, "btc", "Bitcoin Adres Arama", "btc")

    async def search_eth(self, address: str):
        return await self._run_search(address, "eth", "Ethereum Adres Arama", "eth")

    async def search_xmr(self, address: str):
        return await self._run_search(address, "xmr", "Monero Adres Arama", "xmr")

    async def wallet_association(self, address: str):
        return await self._run_search(address, "wallet_assoc", "Cüzdan İlişki Analizi")

    async def ransomware_check(self, address: str):
        return await self._run_search(address, "ransomware", "Ransomware Cüzdan Kontrolü")
