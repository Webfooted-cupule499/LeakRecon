import re
import time
import urllib.parse
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor, as_completed
from bs4 import BeautifulSoup
from rich.console import Console
from rich.table import Table
from rich.text import Text
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich import box

console = Console()

NO_RESULT_PATTERNS = [
    r"no\s+documents?\s+match",
    r"no\s+results?\s+found",
    r"did\s+not\s+match\s+any",
    r"0\s+results?",
    r"nothing\s+found",
    r"no\s+results?\s+for",
    r"no\s+pages?\s+found",
    r"your\s+search.*?did\s+not\s+return",
    r"could\s+not\s+find",
    r"no\s+matching",
    r"no\s+hits",
    r"we\s+did\s+not\s+find",
    r"nothing\s+matched",
]

EXCLUDED_ZONES = [
    "form", "input", "nav", "header", "footer",
    "div.search-bar", "div.search-form", "div.query-echo",
    "h1", "h2", "title", "label",
]


@dataclass
class ScanResult:
    source_name: str
    source_url: str
    found: bool
    matched_snippets: list[str] = field(default_factory=list)
    error: str | None = None


SEARCH_ENGINES = [
    {
        "name": "Ahmia",
        "base_url": "http://juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion",
        "search_path": "/search/?q={query}",
        "result_selector": "li.result",
        "link_selector": "a",
        "snippet_selector": "p",
        "timeout": 25,
    },
    {
        "name": "Ahmia (Web)",
        "base_url": "https://ahmia.fi",
        "search_path": "/search/?q={query}",
        "result_selector": "li.result",
        "link_selector": "a",
        "snippet_selector": "p",
        "timeout": 15,
    },
    {
        "name": "DuckDuckGo",
        "base_url": "https://html.duckduckgo.com",
        "search_path": "/html/?q={query}",
        "result_selector": "div.result",
        "link_selector": "a.result__a",
        "snippet_selector": "a.result__snippet",
        "timeout": 15,
    },
    {
        "name": "SearXNG",
        "base_url": "https://searx.be",
        "search_path": "/search?q={query}&categories=general&format=html",
        "result_selector": "article.result",
        "link_selector": "h3 a, a.url_header",
        "snippet_selector": "p.content",
        "timeout": 15,
    },
    {
        "name": "SearXNG-2",
        "base_url": "https://search.sapti.me",
        "search_path": "/search?q={query}&categories=general&format=html",
        "result_selector": "article.result",
        "link_selector": "h3 a, a.url_header",
        "snippet_selector": "p.content",
        "timeout": 15,
    },
]

PASTE_SITES = [
    {
        "name": "Ahmia Paste",
        "base_url": "http://juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion",
        "search_path": "/search/?q={query}&t=paste",
        "result_selector": "li.result",
        "link_selector": "a",
        "snippet_selector": "p",
        "timeout": 25,
    },
    {
        "name": "Ahmia Paste (Web)",
        "base_url": "https://ahmia.fi",
        "search_path": "/search/?q={query}&t=paste",
        "result_selector": "li.result",
        "link_selector": "a",
        "snippet_selector": "p",
        "timeout": 15,
    },
    {
        "name": "SearXNG Paste",
        "base_url": "https://searx.be",
        "search_path": "/search?q={query}+site%3Apastebin.com+OR+site%3Arentry.co+OR+site%3Apaste.ee&format=html",
        "result_selector": "article.result",
        "link_selector": "h3 a, a.url_header",
        "snippet_selector": "p.content",
        "timeout": 15,
    },
]

MAX_PARALLEL_WORKERS = 8


class DarkWebScraper:

    def __init__(self, tor_handler):
        self.tor = tor_handler

    def _sanitize_query(self, query: str) -> str:
        return urllib.parse.quote_plus(query.strip())

    def _is_false_positive(self, page_text: str) -> bool:
        text_lower = page_text.lower()
        for pattern in NO_RESULT_PATTERNS:
            if re.search(pattern, text_lower):
                return True
        return False

    def _strip_search_echo(self, soup: BeautifulSoup, target: str) -> str:
        for selector in EXCLUDED_ZONES:
            for tag in soup.select(selector):
                tag.decompose()
        return soup.get_text(separator=" ", strip=True)

    def _extract_context(self, text: str, target: str, window: int = 80) -> str | None:
        if not text:
            return None
        idx = text.lower().find(target.lower())
        if idx == -1:
            return None
        start = max(0, idx - window)
        end = min(len(text), idx + len(target) + window)
        snippet = text[start:end].strip()
        snippet = re.sub(r"\s+", " ", snippet)
        return f"...{snippet}..."

    def _search_source(self, source: dict, target: str) -> ScanResult:
        name = source["name"]
        encoded = self._sanitize_query(target)
        url = source["base_url"] + source["search_path"].format(query=encoded)
        timeout = source.get("timeout", 25)

        result = ScanResult(source_name=name, source_url=url, found=False)

        if self.tor.is_host_dead(url):
            result.error = "Atlandı (erişilemez)"
            return result

        try:
            response = self.tor.get(url, timeout=timeout)
            if response is None:
                result.error = "Yanıt alınamadı"
                return result
            if response.status_code != 200:
                result.error = f"HTTP {response.status_code}"
                return result

            soup = BeautifulSoup(response.text, "lxml")
            page_text = soup.get_text(separator=" ", strip=True)

            if self._is_false_positive(page_text):
                return result

            clean_soup = BeautifulSoup(response.text, "lxml")
            clean_text = self._strip_search_echo(clean_soup, target)
            target_lower = target.lower()

            if target_lower not in clean_text.lower():
                return result

            result_soup = BeautifulSoup(response.text, "lxml")
            result_elements = result_soup.select(source["result_selector"])

            if not result_elements:
                body_soup = BeautifulSoup(response.text, "lxml")
                stripped = self._strip_search_echo(body_soup, target)
                if target_lower in stripped.lower():
                    context = self._extract_context(stripped, target)
                    if context and not any(re.search(p, context.lower()) for p in NO_RESULT_PATTERNS):
                        result.found = True
                        result.matched_snippets.append(context)
                return result

            for element in result_elements:
                element_text = element.get_text(separator=" ", strip=True)
                if target_lower not in element_text.lower():
                    continue
                if element_text.lower().strip() == target_lower:
                    continue
                if any(re.search(p, element_text.lower()) for p in NO_RESULT_PATTERNS):
                    continue

                result.found = True
                links = element.select(source["link_selector"])
                for link in links:
                    href = link.get("href", "")
                    if href and href.startswith("http"):
                        result.matched_snippets.append(f"[link] {href}")
                        break

                snippets = element.select(source["snippet_selector"])
                for snippet_el in snippets:
                    snippet_text = snippet_el.get_text(separator=" ", strip=True)
                    if target_lower in snippet_text.lower():
                        context = self._extract_context(snippet_text, target)
                        if context:
                            result.matched_snippets.append(context)
                            break

                if not result.matched_snippets:
                    context = self._extract_context(element_text, target)
                    if context:
                        result.matched_snippets.append(context)

            return result
        except Exception as e:
            result.error = str(e)
            return result

    def _search_parallel(self, sources: list[dict], target: str, category_label: str) -> list[ScanResult]:
        results = []
        live_sources = []
        skipped_sources = []

        for src in sources:
            url = src["base_url"] + src["search_path"].format(query=self._sanitize_query(target))
            if self.tor.is_host_dead(url):
                skipped_sources.append(src)
                results.append(ScanResult(
                    source_name=src["name"], source_url=url, found=False,
                    error="Atlandı (erişilemez)",
                ))
            else:
                live_sources.append(src)

        if skipped_sources:
            skipped_names = ", ".join(s["name"] for s in skipped_sources)
            console.print(f"  [dim yellow]⊘ Atlanıyor: {skipped_names}[/dim yellow]")

        if not live_sources:
            return results

        with Progress(
            SpinnerColumn("dots"),
            TextColumn("[bold cyan]{task.description}"),
            BarColumn(bar_width=30),
            TextColumn("[dim]{task.completed}/{task.total}"),
            TimeElapsedColumn(),
            console=console, transient=True,
        ) as progress:
            task = progress.add_task(f"  {category_label}", total=len(live_sources))

            with ThreadPoolExecutor(max_workers=min(MAX_PARALLEL_WORKERS, len(live_sources))) as pool:
                futures = {pool.submit(self._search_source, src, target): src for src in live_sources}

                completed_futures = set()
                try:
                    for future in as_completed(futures, timeout=45):
                        completed_futures.add(future)
                        src = futures[future]
                        try:
                            result = future.result(timeout=5)
                            results.append(result)
                            if result.found:
                                console.print(f"  [bold red]● {src['name']}: TESPİT EDİLDİ[/bold red]")
                            elif result.error:
                                console.print(f"  [dim yellow]✗ {src['name']}: {result.error}[/dim yellow]")
                            else:
                                console.print(f"  [dim green]✓ {src['name']}: Temiz[/dim green]")
                        except Exception as e:
                            results.append(ScanResult(source_name=src["name"], source_url="", found=False, error=f"İşlem hatası: {e}"))
                            console.print(f"  [dim yellow]✗ {src['name']}: İşlem hatası[/dim yellow]")
                        progress.advance(task)

                except TimeoutError:
                    for future, src in futures.items():
                        if future not in completed_futures:
                            future.cancel()
                            self.tor._record_failure(src["base_url"] + src["search_path"].format(query="x"))
                            results.append(ScanResult(source_name=src["name"], source_url="", found=False, error="Zaman aşımı (atlandı)"))
                            console.print(f"  [dim yellow]⏱ {src['name']}: Zaman aşımı[/dim yellow]")
                            progress.advance(task)

        return results

    def search(self, target: str, dork: str = "", sources: str = "all") -> list[ScanResult]:
        query = f"{dork} {target}".strip() if dork else target
        all_results = []

        engines = SEARCH_ENGINES if sources in ("all", "engines") else []
        pastes = PASTE_SITES if sources in ("all", "pastes") else []

        if engines:
            console.print(f"\n[bold magenta][ ARAMA MOTORLARI ][/bold magenta]")
            all_results.extend(self._search_parallel(engines, query, "Arama Motorları"))

        if pastes:
            console.print(f"\n[bold magenta][ PASTE / FORUM SİTELERİ ][/bold magenta]")
            all_results.extend(self._search_parallel(pastes, query, "Paste Siteleri"))

        return all_results

    def scan_all(self, target: str, target_type: str = "") -> list[ScanResult]:
        return self.search(target)


def _consolidate_results(results: list[ScanResult]) -> list[ScanResult]:
    source_map: dict[str, ScanResult] = {}
    for r in results:
        name = r.source_name
        if name not in source_map:
            source_map[name] = ScanResult(
                source_name=name, source_url=r.source_url, found=r.found,
                matched_snippets=list(r.matched_snippets), error=r.error,
            )
        else:
            existing = source_map[name]
            if r.found:
                existing.found = True
                for s in r.matched_snippets:
                    if s not in existing.matched_snippets:
                        existing.matched_snippets.append(s)
                existing.error = None
            elif not existing.found:
                if not r.error and existing.error:
                    existing.error = None
                elif r.error and existing.error and "Atlandı" in existing.error and "Atlandı" not in r.error:
                    existing.error = r.error
    return list(source_map.values())


def display_results(target: str, label: str, results: list[ScanResult], elapsed: float):
    console.print("\n")
    consolidated = _consolidate_results(results)

    found_results = [r for r in consolidated if r.found]
    skipped_results = [r for r in consolidated if r.error and "Atlandı" in (r.error or "")]
    actual_errors = [r for r in consolidated if r.error and "Atlandı" not in (r.error or "")]
    clean_results = [r for r in consolidated if not r.found and not r.error]

    if found_results:
        console.print(Panel(
            Text("⚠  HEDEF VERİ TESPİT EDİLDİ — DİKKAT", style="bold red", justify="center"),
            border_style="red", box=box.DOUBLE_EDGE,
        ))
    else:
        console.print(Panel(
            Text("✓  HEDEF VERİ BULUNAMADI — TEMİZ", style="bold green", justify="center"),
            border_style="green", box=box.DOUBLE_EDGE,
        ))

    info = Table(show_header=False, box=box.SIMPLE, padding=(0, 2))
    info.add_column("K", style="bold cyan", width=20)
    info.add_column("V", style="white")
    info.add_row("Hedef", target)
    info.add_row("Kategori", label)
    info.add_row("Kaynak Sayısı", str(len(consolidated)))
    info.add_row("Toplam Sorgu", str(len(results)))
    info.add_row("Süre", f"{elapsed:.1f} saniye")
    console.print(info)
    console.print()

    table = Table(
        title="[bold]TARAMA SONUÇLARI[/bold]", box=box.ROUNDED,
        show_lines=True, border_style="bright_black",
        header_style="bold cyan", width=110,
    )
    table.add_column("#", style="dim", width=4, justify="center")
    table.add_column("Kaynak", style="bold", width=20)
    table.add_column("Durum", width=14, justify="center")
    table.add_column("Detay", width=68)

    for idx, r in enumerate(consolidated, 1):
        if r.found:
            status = "[bold red]● BULUNDU[/bold red]"
            parts = [f"[cyan]{s}[/cyan]" if s.startswith("[link]") else f"[dim]{s}[/dim]" for s in r.matched_snippets[:5]]
            detail = "\n".join(parts) if parts else "[dim]Eşleşme tespit edildi[/dim]"
        elif r.error and "Atlandı" in (r.error or ""):
            status = "[dim]● ERİŞİLEMEDİ[/dim]"
            detail = "[dim]Site çevrimdışı veya erişilemiyor[/dim]"
        elif r.error:
            status = "[yellow]● HATA[/yellow]"
            detail = f"[dim yellow]{r.error}[/dim yellow]"
        else:
            status = "[green]● TEMİZ[/green]"
            detail = "[dim]Eşleşme bulunamadı[/dim]"
        table.add_row(str(idx), r.source_name, status, detail)

    console.print(table)
    console.print()

    parts = [f"[green]Temiz: {len(clean_results)}[/green]"]
    if found_results:
        parts.append(f"[red]Tespit: {len(found_results)}[/red]")
    if actual_errors:
        parts.append(f"[yellow]Hata: {len(actual_errors)}[/yellow]")
    if skipped_results:
        parts.append(f"[dim]Erişilemedi: {len(skipped_results)}[/dim]")
    console.print(Panel(" │ ".join(parts), title="[bold]ÖZET[/bold]", border_style="bright_black", box=box.ROUNDED))
    console.print()


    try:
        from core import database as scan_db
        scan_id = scan_db.save_scan(target, label, results, elapsed)
        console.print(f"  [dim]💾 Sonuçlar veritabanına kaydedildi (ID: {scan_id})[/dim]")
    except Exception:
        pass
