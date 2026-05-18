import re
import time
import urllib.parse
import asyncio
from dataclasses import dataclass, field
from bs4 import BeautifulSoup
from rich.console import Console
from rich.table import Table
from rich.text import Text
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich import box
from typing import List, Optional, Dict, Any

from config import settings

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
    matched_snippets: List[str] = field(default_factory=list)
    error: Optional[str] = None


SEARCH_ENGINES = [
    {
        "name": "Ahmia",
        "base_url": "http://juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion",
        "search_path": "/search/?q={query}",
        "result_selector": "li.result",
        "link_selector": "a",
        "snippet_selector": "p",
        "timeout": settings.ONION_TIMEOUT,
    },
    {
        "name": "Ahmia (Web)",
        "base_url": "https://ahmia.fi",
        "search_path": "/search/?q={query}",
        "result_selector": "li.result",
        "link_selector": "a",
        "snippet_selector": "p",
        "timeout": settings.CLEARNET_TIMEOUT,
    },
    {
        "name": "DuckDuckGo (Onion)",
        "base_url": "https://duckduckgogg42xjoc72x3sjiapcmxgxzulfbgndmvd6z3g34x2w3ad.onion",
        "search_path": "/html/?q={query}",
        "result_selector": "div.result",
        "link_selector": "a.result__a",
        "snippet_selector": "a.result__snippet",
        "timeout": settings.ONION_TIMEOUT,
    },
    {
        "name": "SearXNG (Paulgo)",
        "base_url": "https://paulgo.io",
        "search_path": "/search?q={query}&categories=general&format=html",
        "result_selector": "article.result",
        "link_selector": "h3 a, a.url_header",
        "snippet_selector": "p.content",
        "timeout": settings.CLEARNET_TIMEOUT,
    },
    {
        "name": "SearXNG (Sapti)",
        "base_url": "https://search.sapti.me",
        "search_path": "/search?q={query}&categories=general&format=html",
        "result_selector": "article.result",
        "link_selector": "h3 a, a.url_header",
        "snippet_selector": "p.content",
        "timeout": settings.CLEARNET_TIMEOUT,
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
        "timeout": settings.ONION_TIMEOUT,
    },
    {
        "name": "Ahmia Paste (Web)",
        "base_url": "https://ahmia.fi",
        "search_path": "/search/?q={query}&t=paste",
        "result_selector": "li.result",
        "link_selector": "a",
        "snippet_selector": "p",
        "timeout": settings.CLEARNET_TIMEOUT,
    },
    {
        "name": "SearXNG Paste",
        "base_url": "https://paulgo.io",
        "search_path": "/search?q={query}+site%3Apastebin.com+OR+site%3Arentry.co+OR+site%3Apaste.ee&format=html",
        "result_selector": "article.result",
        "link_selector": "h3 a, a.url_header",
        "snippet_selector": "p.content",
        "timeout": settings.CLEARNET_TIMEOUT,
    },
]


class DarkWebScraper:
    """
    Enterprise-grade asynchronous Dark Web and Clearnet scraper.

    Utilizes aiohttp via TorHandler for concurrent OSINT data gathering
    with built-in false positive filtering and result consolidation.
    """

    def __init__(self, tor_handler: Any) -> None:
        """
        Initializes the DarkWebScraper module.

        Args:
            tor_handler: The TorHandler instance for proxied network operations.
        """
        self.tor = tor_handler
        self._semaphore = asyncio.Semaphore(settings.MAX_CONCURRENCY)

    def _sanitize_query(self, query: str) -> str:
        """URL-encodes a search query for safe transmission."""
        return urllib.parse.quote_plus(query.strip())

    def _is_false_positive(self, page_text: str) -> bool:
        """Determines if the page content indicates zero results."""
        text_lower = page_text.lower()
        for pattern in NO_RESULT_PATTERNS:
            if re.search(pattern, text_lower):
                return True
        return False

    def _strip_search_echo(self, soup: BeautifulSoup, target: str) -> str:
        """Removes search form echoes and navigation elements from parsed HTML."""
        for selector in EXCLUDED_ZONES:
            for tag in soup.select(selector):
                tag.decompose()
        return soup.get_text(separator=" ", strip=True)

    def _extract_context(self, text: str, target: str, window: int = 80) -> Optional[str]:
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

    async def _search_source(self, source: Dict[str, Any], target: str) -> ScanResult:
        name = source["name"]
        encoded = self._sanitize_query(target)
        url = source["base_url"] + source["search_path"].format(query=encoded)
        timeout = source.get("timeout", settings.ONION_TIMEOUT)

        result = ScanResult(source_name=name, source_url=url, found=False)

        if await self.tor.is_host_dead(url):
            result.error = "Atlandı (erişilemez)"
            return result

        async with self._semaphore:
            try:
                response = await self.tor.get(url, timeout=timeout)
                if response is None:
                    result.error = "Yanıt alınamadı veya bağlantı hatası"
                    return result
                if response.status != 200:
                    result.error = f"HTTP {response.status}"
                    return result

                html = await response.text()
                soup = BeautifulSoup(html, "lxml")
                page_text = soup.get_text(separator=" ", strip=True)

                if self._is_false_positive(page_text):
                    return result

                clean_soup = BeautifulSoup(html, "lxml")
                clean_text = self._strip_search_echo(clean_soup, target)
                target_lower = target.lower()

                if target_lower not in clean_text.lower():
                    return result

                result_soup = BeautifulSoup(html, "lxml")
                result_elements = result_soup.select(source["result_selector"])

                if not result_elements:
                    body_soup = BeautifulSoup(html, "lxml")
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
                result.error = f"İşlem hatası: {str(e)}"
                return result

    async def _search_parallel(self, sources: List[Dict[str, Any]], target: str, category_label: str) -> List[ScanResult]:
        results = []
        live_sources = []
        skipped_sources = []

        for src in sources:
            url = src["base_url"] + src["search_path"].format(query=self._sanitize_query(target))
            if await self.tor.is_host_dead(url):
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

        tasks = [self._search_source(src, target) for src in live_sources]

        with Progress(
            SpinnerColumn("dots"),
            TextColumn("[bold cyan]{task.description}"),
            BarColumn(bar_width=30),
            TextColumn("[dim]{task.completed}/{task.total}"),
            TimeElapsedColumn(),
            console=console, transient=True,
        ) as progress:
            task_id = progress.add_task(f"  {category_label}", total=len(live_sources))

            # Executing tasks asynchronously while updating progress
            for completed_task in asyncio.as_completed(tasks):
                try:
                    result = await completed_task
                    results.append(result)
                    if result.found:
                        console.print(f"  [bold red]● {result.source_name}: TESPİT EDİLDİ[/bold red]")
                    elif result.error:
                        console.print(f"  [dim yellow]✗ {result.source_name}: {result.error}[/dim yellow]")
                    else:
                        console.print(f"  [dim green]✓ {result.source_name}: Temiz[/dim green]")
                except Exception as e:
                    console.print(f"  [dim yellow]✗ Görev Hatası: {e}[/dim yellow]")
                progress.advance(task_id)

        return results

    async def search(self, target: str, dork: str = "", sources: str = "all") -> List[ScanResult]:
        query = f"{dork} {target}".strip() if dork else target
        all_results = []

        engines = SEARCH_ENGINES if sources in ("all", "engines") else []
        pastes = PASTE_SITES if sources in ("all", "pastes") else []

        if engines:
            console.print(f"\n[bold magenta][ ARAMA MOTORLARI ][/bold magenta]")
            res = await self._search_parallel(engines, query, "Arama Motorları")
            all_results.extend(res)

        if pastes:
            console.print(f"\n[bold magenta][ PASTE / FORUM SİTELERİ ][/bold magenta]")
            res = await self._search_parallel(pastes, query, "Paste Siteleri")
            all_results.extend(res)

        return all_results

    async def scan_all(self, target: str, target_type: str = "") -> List[ScanResult]:
        return await self.search(target)


def _consolidate_results(results: List[ScanResult]) -> List[ScanResult]:
    """Merges duplicate source results into a single consolidated list."""
    source_map: Dict[str, ScanResult] = {}
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


def display_results(target: str, label: str, results: List[ScanResult], elapsed: float) -> None:
    """Renders scan results as a formatted terminal table with summary statistics."""
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
