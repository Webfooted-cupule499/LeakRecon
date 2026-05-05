import sys
import os
import json
import time
import platform
import socket
from datetime import datetime

# Force UTF-8 encoding on Windows to prevent charmap errors with ASCII art
if os.name == "nt":
    os.system("chcp 65001 > nul 2>&1")
    sys.stdout.reconfigure(encoding="utf-8")

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

from core.tor_handler import TorHandler
from core.banner import (
    show_screen, clear_screen, print_banner, render_menu,
    get_input, ask_target, ask_optional,
    is_global_command, handle_global,
    wait_enter, print_error, print_success, print_info, print_warning,
    GLOBAL_HELP,
)
from modules.darkweb_scraper import DarkWebScraper, display_results
from modules.identity_recon import IdentityRecon
from modules.network_intel import NetworkIntel
from modules.onion_scanner import OnionScanner
from modules.credential_hunt import CredentialHunt
from modules.crypto_tracker import CryptoTracker

console = Console()

scan_history: list[dict] = []
tor_instance: TorHandler = None


def log_scan(category: str, target: str):
    scan_history.append({
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "category": category,
        "target": target,
    })


def process_choice(choice: str, menu_key: str) -> str | None:
    glob = is_global_command(choice)
    if glob == "back" or glob == "home":
        return "back"
    if glob == "exit":
        handle_global("exit", tor_instance)
        return None
    if glob:
        handle_global(glob, tor_instance)
        wait_enter()
        return "refresh"
    return None




def menu_darkweb(scraper: DarkWebScraper):
    while True:
        show_screen("darkweb")
        choice = get_input("darkweb")

        action = process_choice(choice, "darkweb")
        if action == "back":
            return
        if action == "refresh":
            continue

        prompts = {
            "1": ("E-posta adresi girin", "E-posta Arama"),
            "2": ("Kullanıcı adı girin", "Kullanıcı Adı Arama"),
            "3": ("Telefon numarası girin", "Telefon Arama"),
            "4": ("IP adresi girin", "IP Arama"),
            "5": ("Domain girin (ör: example.com)", "Domain Arama"),
            "6": ("Anahtar kelime girin", "Anahtar Kelime Arama"),
            "7": ("Dork sorgusu girin (ör: \"hedef\" site:.onion filetype:sql)", "Dork Arama"),
        }

        if choice == "8":
            targets_input = ask_target("Hedefleri virgülle ayırarak girin")
            if targets_input:
                targets = [t.strip() for t in targets_input.split(",") if t.strip()]
                for t in targets:
                    console.print(f"\n  [bold white]━━━ Hedef: {t} ━━━[/bold white]")
                    start = time.time()
                    results = scraper.scan_all(t)
                    display_results(t, "Çoklu Tarama", results, time.time() - start)
                    log_scan("Çoklu Tarama", t)
            wait_enter()
            continue

        if choice in prompts:
            prompt_text, label = prompts[choice]
            target = ask_target(prompt_text)
            if target:
                start = time.time()
                results = scraper.scan_all(target)
                display_results(target, label, results, time.time() - start)
                log_scan(label, target)
            wait_enter()
        else:
            print_error("Geçersiz seçim. Numara girin veya 'help' yazın.")
            time.sleep(1.5)




def menu_identity(identity: IdentityRecon):
    while True:
        show_screen("identity")
        choice = get_input("identity")

        action = process_choice(choice, "identity")
        if action == "back":
            return
        if action == "refresh":
            continue

        actions = {
            "1": ("E-posta adresi girin", identity.search_email, "E-posta OSINT"),
            "2": ("Kullanıcı adı girin", identity.search_username, "Kullanıcı Profilleme"),
            "3": ("Telefon numarası girin", identity.search_phone, "Telefon İzleme"),
            "4": ("İsim girin (ör: John Doe)", identity.search_name, "İsim Araştırma"),
            "5": ("Domain veya kurum adı girin", identity.search_domain, "Domain OSINT"),
            "6": ("Hash girin (MD5/SHA-256)", identity.search_hash, "Hash Kontrolü"),
            "7": ("Sosyal medya handle girin (ör: @user)", identity.search_username, "Sosyal Medya"),
            "8": ("Adres bilgisi girin", identity.search_name, "Fiziksel Adres"),
        }

        if choice in actions:
            prompt_text, func, label = actions[choice]
            target = ask_target(prompt_text)
            if target:
                func(target)
                log_scan(label, target)
            wait_enter()
        else:
            print_error("Geçersiz seçim.")
            time.sleep(1.5)




def menu_network(network: NetworkIntel):
    while True:
        show_screen("network")
        choice = get_input("network")

        action = process_choice(choice, "network")
        if action == "back":
            return
        if action == "refresh":
            continue

        if choice == "1":
            target = ask_target("IP adresi girin")
            if target:
                network.ip_geolocation(target)
                log_scan("IP Geolocation", target)
            wait_enter()

        elif choice == "2":
            target = ask_target("IP adresi girin")
            if target:
                network.reverse_dns(target)
                log_scan("Reverse DNS", target)
            wait_enter()

        elif choice == "3":
            target = ask_target("Hedef IP veya hostname girin")
            if target:
                port_input = ask_optional("Portlar (virgülle ayır, boş = yaygın 25 port)")
                ports = None
                if port_input:
                    try:
                        ports = [int(p.strip()) for p in port_input.split(",") if p.strip()]
                    except ValueError:
                        print_error("Geçersiz port formatı. Sayıları virgülle ayırın.")
                        wait_enter()
                        continue
                network.port_scan(target, ports)
                log_scan("Port Tarama", target)
            wait_enter()

        elif choice == "4":
            target = ask_target("IP adresi girin")
            if target:
                network.tor_exit_check(target)
                log_scan("Tor Exit Check", target)
            wait_enter()

        elif choice == "5":
            target = ask_target("IP adresi girin")
            if target:
                network.ip_reputation(target)
                log_scan("IP İtibar", target)
            wait_enter()

        elif choice == "6":
            target = ask_target("URL girin (http:// veya https://)")
            if target:
                network.fetch_headers(target)
                log_scan("HTTP Header", target)
            wait_enter()

        elif choice == "7":
            target = ask_target("IP veya domain girin")
            if target:
                network.whois_lookup(target)
                log_scan("WHOIS", target)
            wait_enter()

        elif choice == "8":
            target = ask_target("Domain girin (ör: example.com)")
            if target:
                console.print(f"\n  [bold white][ DNS ] DNS kayıtları sorgulanıyor: {target}[/bold white]")
                try:
                    records = []
                    for qtype in ["A", "AAAA", "MX", "NS", "TXT"]:
                        try:
                            if qtype == "A":
                                ips = socket.getaddrinfo(target, None, socket.AF_INET)
                                for ip in set(addr[4][0] for addr in ips):
                                    records.append((qtype, ip))
                            elif qtype == "AAAA":
                                ips = socket.getaddrinfo(target, None, socket.AF_INET6)
                                for ip in set(addr[4][0] for addr in ips):
                                    records.append((qtype, ip))
                        except socket.gaierror:
                            pass

                    resp = network.tor.get(f"https://dns.google/resolve?name={target}&type=MX", timeout=15)
                    if resp and resp.status_code == 200:
                        data = resp.json()
                        for answer in data.get("Answer", []):
                            records.append(("MX" if answer.get("type") == 15 else "DNS", answer.get("data", "?")))

                    resp = network.tor.get(f"https://dns.google/resolve?name={target}&type=NS", timeout=15)
                    if resp and resp.status_code == 200:
                        data = resp.json()
                        for answer in data.get("Answer", []):
                            records.append(("NS", answer.get("data", "?")))

                    table = Table(
                        title=f"[bold]DNS KAYITLARI: {target}[/bold]",
                        box=box.ROUNDED, show_lines=True,
                        border_style="cyan", header_style="bold cyan", width=70,
                    )
                    table.add_column("Tür", style="bold yellow", width=10, justify="center")
                    table.add_column("Değer", style="white", width=56)

                    if records:
                        for rtype, rval in records:
                            table.add_row(rtype, rval)
                    else:
                        table.add_row("-", "[dim]Kayıt bulunamadı[/dim]")

                    console.print()
                    console.print(table)
                except Exception as e:
                    print_error(str(e))
                log_scan("DNS Kayıt", target)
            wait_enter()

        elif choice == "9":
            target = ask_target("CIDR bloğu girin (ör: 192.168.1.0/24)")
            if target:
                console.print(f"\n  [bold white][ SUBNET ] Subnet tarama: {target}[/bold white]")
                try:
                    import ipaddress
                    net = ipaddress.ip_network(target, strict=False)
                    hosts = list(net.hosts())[:20]

                    console.print(f"  [dim]İlk {len(hosts)} host taranıyor (Tor SOCKS)...[/dim]\n")

                    table = Table(
                        title=f"[bold]SUBNET TARAMA: {target}[/bold]",
                        box=box.ROUNDED, show_lines=True,
                        border_style="cyan", header_style="bold cyan", width=60,
                    )
                    table.add_column("#", style="dim", width=4, justify="center")
                    table.add_column("IP", style="white", width=20)
                    table.add_column("Port 80", width=12, justify="center")
                    table.add_column("Port 443", width=12, justify="center")

                    for idx, ip in enumerate(hosts, 1):
                        ip_str = str(ip)
                        console.print(f"    [dim]→ {ip_str}[/dim]", end="")
                        p80 = network._socks5_connect(ip_str, 80, timeout=5)
                        p443 = network._socks5_connect(ip_str, 443, timeout=5)
                        s80 = "[green]AÇIK[/green]" if p80 else "[dim]kapalı[/dim]"
                        s443 = "[green]AÇIK[/green]" if p443 else "[dim]kapalı[/dim]"
                        table.add_row(str(idx), ip_str, s80, s443)
                        console.print(f"  {'✓' if p80 or p443 else '·'}")

                    console.print()
                    console.print(table)
                except ValueError as e:
                    print_error(f"Geçersiz CIDR formatı: {e}")
                except Exception as e:
                    print_error(str(e))
                log_scan("Subnet Tarama", target)
            wait_enter()

        else:
            print_error("Geçersiz seçim.")
            time.sleep(1.5)




def menu_onion(onion: OnionScanner):
    while True:
        show_screen("onion")
        choice = get_input("onion")

        action = process_choice(choice, "onion")
        if action == "back":
            return
        if action == "refresh":
            continue

        actions = {
            "1": ("check_status", ".onion adresi girin"),
            "2": ("http_headers", ".onion adresi girin"),
            "3": ("page_meta", ".onion adresi girin"),
            "4": ("detect_tech", ".onion adresi girin"),
            "7": ("extract_links", ".onion adresi girin"),
            "8": ("save_text", ".onion adresi girin"),
        }

        if choice in actions:
            method_name, prompt_text = actions[choice]
            target = ask_target(prompt_text)
            if target:
                getattr(onion, method_name)(target)
                log_scan(method_name, target)
            wait_enter()

        elif choice == "5":
            target = ask_target("Onion listesi dosya yolu girin")
            if target:
                onion.bulk_scan(target)
                log_scan("Toplu Onion", target)
            wait_enter()

        elif choice == "6":
            target = ask_target(".onion adresi girin")
            if target:
                out = ask_optional("Çıktı dosya adı (boş = otomatik)")
                onion.download_page(target, out or "")
                log_scan("Onion İndir", target)
            wait_enter()

        else:
            print_error("Geçersiz seçim.")
            time.sleep(1.5)




def menu_credential(cred: CredentialHunt):
    while True:
        show_screen("credential")
        choice = get_input("credential")

        action = process_choice(choice, "credential")
        if action == "back":
            return
        if action == "refresh":
            continue

        actions = {
            "1": ("email_leak", "E-posta adresi girin", "E-posta Leak"),
            "2": ("user_pass", "Kullanıcı adı girin", "User:Pass"),
            "3": ("combo_search", "Hedef veri girin (email, domain vb.)", "Combo List"),
            "4": ("database_dump", "Domain veya tablo adı girin", "DB Dump"),
            "5": ("paste_search", "Aranacak veri girin", "Paste Tarama"),
            "6": ("hash_search", "Hash girin (MD5/SHA-1/SHA-256)", "Hash Arama"),
            "7": ("stealer_search", "E-posta veya domain girin", "Stealer Log"),
            "8": ("forum_search", "Hedef veri girin", "Forum Sızıntı"),
        }

        if choice == "9":
            filepath = ask_target("E-posta listesi dosya yolu girin (.txt)")
            if filepath:
                if not os.path.isfile(filepath):
                    print_error(f"Dosya bulunamadı: {filepath}")
                else:
                    with open(filepath, "r", encoding="utf-8") as f:
                        emails = [l.strip() for l in f if l.strip() and "@" in l]
                    console.print(f"\n  [bold white]{len(emails)} e-posta taranacak...[/bold white]")
                    for idx, email in enumerate(emails, 1):
                        console.print(f"\n  [bold]━━━ [{idx}/{len(emails)}] {email} ━━━[/bold]")
                        cred.email_leak(email)
                        log_scan("Toplu E-posta Leak", email)
            wait_enter()

        elif choice == "10":
            domain = ask_target("Domain girin (ör: example.com)")
            if domain:
                cred.email_leak(f"@{domain}")
                log_scan("Wildcard Domain", domain)
            wait_enter()

        elif choice in actions:
            method_name, prompt_text, label = actions[choice]
            target = ask_target(prompt_text)
            if target:
                getattr(cred, method_name)(target)
                log_scan(label, target)
            wait_enter()

        else:
            print_error("Geçersiz seçim.")
            time.sleep(1.5)




def menu_crypto(crypto: CryptoTracker):
    while True:
        show_screen("crypto")
        choice = get_input("crypto")

        action = process_choice(choice, "crypto")
        if action == "back":
            return
        if action == "refresh":
            continue

        actions = {
            "1": ("search_btc", "Bitcoin adresi girin", "BTC Arama"),
            "2": ("search_eth", "Ethereum adresi girin (0x...)", "ETH Arama"),
            "3": ("search_xmr", "Monero adresi girin", "XMR Arama"),
            "4": ("wallet_association", "Cüzdan adresi girin", "Cüzdan İlişki"),
            "5": ("ransomware_check", "Cüzdan adresi girin", "Ransomware Check"),
            "6": ("wallet_association", "Cüzdan adresi girin", "Mixer/Tumbler"),
        }

        if choice in actions:
            method_name, prompt_text, label = actions[choice]
            target = ask_target(prompt_text)
            if target:
                getattr(crypto, method_name)(target)
                log_scan(label, target)
            wait_enter()
        else:
            print_error("Geçersiz seçim.")
            time.sleep(1.5)




def menu_tools(tor: TorHandler):
    from core import database as scan_db
    from core import reporter

    while True:
        show_screen("tools")
        choice = get_input("tools")

        action = process_choice(choice, "tools")
        if action == "back":
            return
        if action == "refresh":
            continue

        if choice == "1":
            console.print("  [dim]Durum kontrol ediliyor...[/dim]", end="\r")
            if tor.check_connection() and tor.active_proxy:
                proxy = tor.active_proxy.get("http", "?")
                console.print(Panel(
                    f"  [bold green]● Tor Bağlantısı Aktif[/bold green]\n\n"
                    f"  [white]Proxy:[/white]      {proxy}\n"
                    f"  [white]Çıkış IP:[/white]   {tor.tor_ip or '?'}\n"
                    f"  [white]Oturum:[/white]     Açık",
                    title="[bold cyan]TOR DURUMU[/bold cyan]",
                    border_style="green", box=box.ROUNDED,
                ))
            else:
                console.print(Panel(
                    "  [bold red]● Tor Bağlantısı Yok veya Koptu[/bold red]",
                    title="[bold cyan]TOR DURUMU[/bold cyan]",
                    border_style="red", box=box.ROUNDED,
                ))
            wait_enter()

        elif choice == "2":
            console.print("\n  [bold cyan][ TOR ] Yeni kimlik alınıyor...[/bold cyan]")
            try:
                from stem import Signal
                from stem.control import Controller
                control_port = 9051 if "9050" in str(tor.active_proxy) else 9151
                with Controller.from_port(port=control_port) as controller:
                    controller.authenticate()
                    controller.signal(Signal.NEWNYM)
                    print_success("Tor devresi yenilendi.")
                    time.sleep(3)
                    resp = tor.get("https://check.torproject.org/api/ip", timeout=15)
                    if resp:
                        new_ip = resp.json().get("IP", "?")
                        tor.tor_ip = new_ip
                        console.print(f"    [bold green]Yeni IP: {new_ip}[/bold green]")
            except ImportError:
                print_warning("'stem' kütüphanesi gerekli: pip install stem")
            except Exception as e:
                print_error(f"Devre yenilemesi başarısız: {e}")
            wait_enter()

        elif choice == "3":
            console.print("\n  [bold cyan][ TEST ] Proxy test ediliyor...[/bold cyan]")
            tor.verify_tor_connection()
            wait_enter()

        elif choice == "4":
            history = scan_db.get_history(limit=50)
            if not history:
                print_warning("Henüz veritabanında tarama kaydı yok.")
            else:
                table = Table(
                    title="[bold]TARAMA GEÇMİŞİ (Veritabanı)[/bold]",
                    box=box.ROUNDED, show_lines=True,
                    border_style="cyan", header_style="bold cyan", width=110,
                )
                table.add_column("ID", style="dim", width=5, justify="center")
                table.add_column("Tarih", style="white", width=20)
                table.add_column("Kategori", style="bold yellow", width=22)
                table.add_column("Hedef", style="white", width=30)
                table.add_column("Tespit", style="red", width=7, justify="center")
                table.add_column("Temiz", style="green", width=7, justify="center")
                table.add_column("Süre", style="dim", width=8, justify="center")

                for scan in history:
                    table.add_row(
                        str(scan["id"]),
                        scan["timestamp"],
                        scan["category"],
                        scan["target"][:28],
                        str(scan["found_count"]),
                        str(scan["clean_count"]),
                        f"{scan['duration']:.1f}s",
                    )

                console.print()
                console.print(table)
            wait_enter()

        elif choice == "5":
            scan_id = ask_target("Tarama ID girin")
            if scan_id and scan_id.isdigit():
                detail = scan_db.get_scan_detail(int(scan_id))
                if not detail:
                    print_error(f"ID {scan_id} bulunamadı.")
                else:
                    scan = detail["scan"]
                    console.print(Panel(
                        f"  [white]Hedef:[/white]    {scan['target']}\n"
                        f"  [white]Kategori:[/white] {scan['category']}\n"
                        f"  [white]Tarih:[/white]    {scan['timestamp']}\n"
                        f"  [white]Süre:[/white]     {scan['duration']:.1f}s\n"
                        f"  [white]Kaynak:[/white]   {scan['source_count']} | Sorgu: {scan['query_count']}",
                        title=f"[bold cyan]TARAMA #{scan['id']}[/bold cyan]",
                        border_style="cyan", box=box.ROUNDED,
                    ))

                    table = Table(
                        box=box.ROUNDED, show_lines=True,
                        border_style="bright_black", header_style="bold cyan", width=100,
                    )
                    table.add_column("#", style="dim", width=4, justify="center")
                    table.add_column("Kaynak", style="bold", width=20)
                    table.add_column("Durum", width=14, justify="center")
                    table.add_column("Detay", width=58)

                    for idx, r in enumerate(detail["results"], 1):
                        if r["found"]:
                            status = "[bold red]● BULUNDU[/bold red]"
                            snippets = ""
                            if r["snippets"]:
                                try:
                                    snips = json.loads(r["snippets"])
                                    snippets = "\n".join(snips[:3])
                                except Exception:
                                    snippets = r["snippets"]
                            detail_text = snippets or "Eşleşme tespit edildi"
                        elif r["error"]:
                            status = "[yellow]● HATA[/yellow]"
                            detail_text = r["error"]
                        else:
                            status = "[green]● TEMİZ[/green]"
                            detail_text = "Eşleşme bulunamadı"
                        table.add_row(str(idx), r["source_name"], status, detail_text)

                    console.print(table)
            wait_enter()

        elif choice == "6":
            target = ask_target("Fark analizi için hedef girin")
            if target:
                diff = scan_db.get_scan_diff(target)
                if not diff:
                    print_warning("Bu hedef için en az 2 tarama gerekli.")
                else:
                    console.print(Panel(
                        f"  [white]Son Tarama:[/white]     {diff['latest']['timestamp']}\n"
                        f"  [white]Önceki Tarama:[/white]  {diff['previous']['timestamp']}\n\n"
                        f"  [bold red]Yeni Tespitler:[/bold red]  {len(diff['new_findings'])}\n"
                        f"  [bold green]Çözülenler:[/bold green]     {len(diff['resolved'])}\n"
                        f"  [dim]Değişmeyen:[/dim]     {len(diff['unchanged'])}",
                        title="[bold cyan]FARK ANALİZİ[/bold cyan]",
                        border_style="cyan", box=box.ROUNDED,
                    ))
                    if diff["new_findings"]:
                        console.print("\n  [bold red]⚠ YENİ TESPİTLER:[/bold red]")
                        for r in diff["new_findings"]:
                            console.print(f"    [red]● {r['source_name']}[/red]")
                    if diff["resolved"]:
                        console.print("\n  [bold green]✓ ÇÖZÜLEN TESPİTLER:[/bold green]")
                        for r in diff["resolved"]:
                            console.print(f"    [green]● {r['source_name']}[/green]")
            wait_enter()

        elif choice == "7":
            stats = scan_db.get_stats()
            table = Table(
                title="[bold]GENEL İSTATİSTİKLER[/bold]",
                box=box.ROUNDED, show_lines=True,
                border_style="cyan", header_style="bold cyan", width=60,
            )
            table.add_column("Metrik", style="bold white", width=30)
            table.add_column("Değer", style="white", width=26)
            table.add_row("Toplam Tarama", str(stats["total_scans"]))
            table.add_row("Toplam Tespit", str(stats["total_findings"]))
            table.add_row("Benzersiz Hedef", str(stats["unique_targets"]))
            console.print()
            console.print(table)

            if stats["categories"]:
                cat_table = Table(
                    title="[bold]KATEGORİ DAĞILIMI[/bold]",
                    box=box.ROUNDED, border_style="bright_black",
                    header_style="bold cyan", width=60,
                )
                cat_table.add_column("Kategori", style="yellow", width=30)
                cat_table.add_column("Tarama Sayısı", style="white", width=26, justify="center")
                for cat in stats["categories"]:
                    cat_table.add_row(cat["category"], str(cat["c"]))
                console.print(cat_table)
            wait_enter()

        elif choice == "8":
            path = reporter.export_html()
            print_success(f"HTML rapor oluşturuldu: {path}")
            wait_enter()

        elif choice == "9":
            path = reporter.export_json()
            print_success(f"JSON dosyası oluşturuldu: {path}")
            wait_enter()

        elif choice == "10":
            path = reporter.export_csv()
            print_success(f"CSV dosyası oluşturuldu: {path}")
            wait_enter()

        elif choice == "11":
            confirm = ask_target("Tüm geçmiş silinecek. Emin misiniz? (evet/hayır)")
            if confirm and confirm.lower() in ("evet", "e", "yes", "y"):
                scan_db.clear_history()
                print_success("Veritabanı tamamen temizlendi.")
            else:
                print_info("İptal edildi.")
            wait_enter()

        elif choice == "12":
            table = Table(
                title="[bold]SİSTEM BİLGİSİ[/bold]",
                box=box.ROUNDED, show_lines=True,
                border_style="cyan", header_style="bold cyan", width=60,
            )
            table.add_column("Alan", style="bold white", width=22)
            table.add_column("Değer", style="white", width=34)
            table.add_row("Platform", platform.platform())
            table.add_row("Python", platform.python_version())
            table.add_row("İşlemci", platform.processor() or "?")
            table.add_row("Hostname", platform.node())
            table.add_row("Tor Proxy", tor.active_proxy.get("http", "?") if tor.active_proxy else "Yok")
            table.add_row("Tor IP", tor.tor_ip or "?")

            stats = scan_db.get_stats()
            table.add_row("Veritabanı Tarama", str(stats["total_scans"]))
            table.add_row("Oturum Başlangıcı", datetime.now().strftime("%H:%M:%S"))

            console.print()
            console.print(table)
            wait_enter()

        else:
            print_error("Geçersiz seçim.")
            time.sleep(1.5)




def main():
    global tor_instance

    clear_screen()
    print_banner()
    console.print()

    tor = TorHandler()
    if not tor.verify_tor_connection():
        console.print("\n  [bold red]Tor servisi bulunamadı. Program sonlandırılıyor.[/bold red]\n")
        sys.exit(1)

    tor_instance = tor


    from core import database as scan_db
    scan_db.init_db()

    scraper = DarkWebScraper(tor)
    identity = IdentityRecon(tor)
    network = NetworkIntel(tor)
    onion = OnionScanner(tor)
    cred = CredentialHunt(tor)
    crypto = CryptoTracker(tor)

    print_success("LeakRecon hazır.")
    time.sleep(1)

    while True:
        show_screen("main")
        choice = get_input("leakrecon")

        glob = is_global_command(choice)
        if glob == "exit":
            handle_global("exit", tor)
        elif glob == "back" or glob == "home":
            continue
        elif glob:
            handle_global(glob, tor)
            wait_enter()
            continue

        routes = {
            "1": lambda: menu_darkweb(scraper),
            "2": lambda: menu_identity(identity),
            "3": lambda: menu_network(network),
            "4": lambda: menu_onion(onion),
            "5": lambda: menu_credential(cred),
            "6": lambda: menu_crypto(crypto),
            "7": lambda: menu_tools(tor),
        }

        if choice in routes:
            try:
                routes[choice]()
            except KeyboardInterrupt:
                console.print("\n  [bold yellow]İşlem iptal edildi (Ctrl+C). Ana menüye dönülüyor...[/bold yellow]")
                time.sleep(1)
            except Exception as e:
                print_error(f"Beklenmeyen bir hata oluştu: {e}")
                time.sleep(2)
        else:
            print_error("Geçersiz seçim. Numara girin veya 'help' yazın.")
            time.sleep(1.5)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n\n  [bold yellow]Oturum sonlandırıldı (Ctrl+C).[/bold yellow]")
        if tor_instance:
            tor_instance.close()
        sys.exit(0)
    except Exception as e:
        console.print(f"\n\n  [bold red]Kritik hata: {e}[/bold red]")
        if tor_instance:
            tor_instance.close()
        sys.exit(1)
