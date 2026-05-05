import os
import sys
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.columns import Columns
from rich import box

console = Console()

BANNER = """[bold red]
  ██╗     ███████╗ █████╗ ██╗  ██╗██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
  ██║     ██╔════╝██╔══██╗██║ ██╔╝██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
  ██║     █████╗  ███████║█████╔╝ ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
  ██║     ██╔══╝  ██╔══██║██╔═██╗ ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
  ███████╗███████╗██║  ██║██║  ██╗██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
  ╚══════╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝[/bold red]
[dim white]           Dark Web Leak Intelligence · OSINT Reconnaissance Framework[/dim white]
[dim]          ─── Tüm trafik Tor ağı üzerinden · Clearnet API kullanılmaz ───[/dim]"""


MENUS = {
    "main": {
        "title": "ANA MENÜ",
        "icon": "◈",
        "items": [
            ("1", "🌐 Dark Web Arama", "Onion arama motorlarında genel anahtar kelime taraması"),
            ("2", "👤 Kimlik İstihbaratı", "E-posta, kullanıcı adı, telefon, isim OSINT araştırması"),
            ("3", "🔌 Ağ İstihbaratı", "IP analizi, port tarama, DNS, WHOIS, Tor düğüm kontrolü"),
            ("4", "🧅 Onion Tarayıcı", ".onion site durum, header, meta, teknoloji analizi"),
            ("5", "🔑 Credential Avı", "Sızıntı veritabanı, paste site, combo list taraması"),
            ("6", "₿  Kripto İzleme", "Bitcoin, Ethereum, Monero adres ve cüzdan takibi"),
            ("7", "⚙  Araçlar & Ayarlar", "Tor durumu, kimlik değişimi, geçmiş, dışa aktarma"),
        ],
    },
    "darkweb": {
        "title": "DARK WEB ARAMA",
        "icon": "🌐",
        "items": [
            ("1", "E-posta Adresi Ara", "Dark web arama motorlarında e-posta taraması"),
            ("2", "Kullanıcı Adı Ara", "Kullanıcı adını tüm onion kaynaklarda tara"),
            ("3", "Telefon Numarası Ara", "Telefon numarasını dark web'de tara"),
            ("4", "IP Adresi Ara", "IP adresini dark web sızıntılarında ara"),
            ("5", "Domain Ara", "Domain adını dark web'de tara"),
            ("6", "Özel Anahtar Kelime", "Serbest metin ile dark web taraması"),
            ("7", "Gelişmiş Dork Arama", "Özel dork sorgusu ile hedefli arama"),
            ("8", "Çoklu Hedef Tara", "Birden fazla hedefi tek seferde tara"),
        ],
    },
    "identity": {
        "title": "KİMLİK İSTİHBARATI",
        "icon": "👤",
        "items": [
            ("1", "E-posta OSINT", "E-postaya bağlı hesap ve sızıntı taraması"),
            ("2", "Kullanıcı Adı Profilleme", "Dark web kullanıcı profil araştırması"),
            ("3", "Telefon Numarası İzleme", "Telefona bağlı verileri tara"),
            ("4", "İsim Araştırma", "Gerçek isim ile dark web araştırması"),
            ("5", "Domain / Organizasyon", "Kurum veya domain sızıntı taraması"),
            ("6", "Parola Hash Kontrolü", "SHA-256/MD5 hash dark web taraması"),
            ("7", "Sosyal Medya Handle", "Dark web'de sosyal medya hesap araştırması"),
            ("8", "Fiziksel Adres Arama", "Adres bilgisi ile doxxing kontrolü"),
        ],
    },
    "network": {
        "title": "AĞ İSTİHBARATI",
        "icon": "🔌",
        "items": [
            ("1", "IP Geolocation", "IP coğrafi konum tespiti (Tor üzerinden)"),
            ("2", "Reverse DNS", "IP'den hostname çözümleme"),
            ("3", "Port Tarama", "Hedef IP açık port taraması (Tor SOCKS)"),
            ("4", "Tor Exit Node Kontrolü", "IP'nin Tor çıkış düğümü olup olmadığını kontrol"),
            ("5", "IP İtibar Analizi", "IP dark web itibar araştırması"),
            ("6", "HTTP Header Çekme", "URL HTTP başlık bilgilerini çek (Tor)"),
            ("7", "WHOIS Sorgusu", "Domain/IP WHOIS bilgisi sorgula (Tor)"),
            ("8", "DNS Kayıt Sorgusu", "DNS A/MX/NS kayıtlarını sorgula"),
            ("9", "Subnet Tarama", "CIDR bloğundaki aktif hostları tara"),
        ],
    },
    "onion": {
        "title": "ONION TARAYICI",
        "icon": "🧅",
        "items": [
            ("1", "Durum Kontrolü", ".onion erişilebilirlik testi"),
            ("2", "HTTP Header Analizi", "Onion HTTP header bilgileri"),
            ("3", "Sayfa Meta Bilgisi", "Title, meta tag, link/form sayısı"),
            ("4", "Teknoloji Tespiti", "Sunucu teknolojisi tespiti (Server, CMS, JS)"),
            ("5", "Toplu Onion Tarama", "Dosyadan onion listesi yükle ve toplu tara"),
            ("6", "Sayfa Kaynağı İndir", "Onion sayfa HTML kaynağını kaydet"),
            ("7", "Link Çıkarıcı", "Sayfadaki tüm linkleri listele"),
            ("8", "Screenshot (Kaynak)", "Sayfa metnini düz metin olarak kaydet"),
        ],
    },
    "credential": {
        "title": "CREDENTIAL AVI",
        "icon": "🔑",
        "items": [
            ("1", "E-posta Sızıntı Taraması", "E-posta dark web sızıntı taraması"),
            ("2", "Kullanıcı:Parola Arama", "Credential çiftleri dark web arama"),
            ("3", "Combo List Taraması", "Combo list ve dump dosya arama"),
            ("4", "Veritabanı Dump Arama", "SQL dump / veritabanı sızıntı tarama"),
            ("5", "Paste Site Taraması", "Dark web paste sitelerinde hassas veri arama"),
            ("6", "Hash Arama", "Parola hash dark web tarama"),
            ("7", "Stealer Log Taraması", "Redline, Raccoon, Vidar stealer log tarama"),
            ("8", "Forum Sızıntı Taraması", "Underground forum ve market sızıntı arama"),
            ("9", "Toplu E-posta Tarama", "Dosyadan e-posta listesi yükle ve toplu tara"),
            ("10", "Wildcard Domain Tarama", "*@domain.com şeklinde tüm e-postaları tara"),
        ],
    },
    "crypto": {
        "title": "KRİPTO İZLEME",
        "icon": "₿",
        "items": [
            ("1", "Bitcoin Adres Arama", "BTC adresi dark web tarama"),
            ("2", "Ethereum Adres Arama", "ETH adresi dark web tarama"),
            ("3", "Monero Adres Arama", "XMR adresi dark web tarama"),
            ("4", "Cüzdan İlişki Analizi", "Cüzdan marketplace bağlantı analizi"),
            ("5", "Ransomware Cüzdan Kontrolü", "Bilinen ransomware cüzdan taraması"),
            ("6", "Mixer/Tumbler Tespiti", "Cüzdan mixing servis bağlantı taraması"),
        ],
    },
    "tools": {
        "title": "ARAÇLAR & AYARLAR",
        "icon": "⚙",
        "items": [
            ("1", "Tor Bağlantı Durumu", "Aktif Tor bağlantı detayları"),
            ("2", "Yeni Tor Kimliği", "Tor devresini yenile (yeni çıkış IP)"),
            ("3", "Proxy Bağlantı Testi", "Tor proxy erişilebilirlik testi"),
            ("4", "Tarama Geçmişi", "Veritabanındaki tüm tarama kayıtları"),
            ("5", "Tarama Detayı", "Belirli bir taramanın detaylı sonuçları"),
            ("6", "Fark Analizi", "Aynı hedefin iki taraması arasındaki fark"),
            ("7", "İstatistikler", "Genel tarama istatistikleri"),
            ("8", "HTML Rapor Oluştur", "Profesyonel HTML istihbarat raporu"),
            ("9", "JSON Dışa Aktar", "Sonuçları JSON formatında kaydet"),
            ("10", "CSV Dışa Aktar", "Sonuçları CSV formatında kaydet"),
            ("11", "Geçmişi Temizle", "Veritabanını tamamen sıfırla"),
            ("12", "Sistem Bilgisi", "Python, Tor, platform bilgileri"),
        ],
    },
}

GLOBAL_HELP = """
[bold cyan]╔═══════════════════════════════════════════════════════════════════════╗[/bold cyan]
[bold cyan]║                         GLOBAL KOMUTLAR                             ║[/bold cyan]
[bold cyan]╠═══════════════════════════════════════════════════════════════════════╣[/bold cyan]
[bold cyan]║[/bold cyan]  [bold yellow]help[/bold yellow]    [dim]/ [/dim][bold yellow]h[/bold yellow]       Bu yardım ekranını gösterir                   [bold cyan]║[/bold cyan]
[bold cyan]║[/bold cyan]  [bold yellow]back[/bold yellow]    [dim]/ [/dim][bold yellow]b[/bold yellow]       Bir önceki menüye döner                       [bold cyan]║[/bold cyan]
[bold cyan]║[/bold cyan]  [bold yellow]home[/bold yellow]              Ana menüye döner                             [bold cyan]║[/bold cyan]
[bold cyan]║[/bold cyan]  [bold yellow]clear[/bold yellow]   [dim]/ [/dim][bold yellow]cls[/bold yellow]     Ekranı temizler                               [bold cyan]║[/bold cyan]
[bold cyan]║[/bold cyan]  [bold yellow]status[/bold yellow]            Tor bağlantı durumunu gösterir               [bold cyan]║[/bold cyan]
[bold cyan]║[/bold cyan]  [bold yellow]exit[/bold yellow]    [dim]/ [/dim][bold yellow]q[/bold yellow]       Programdan çıkar                              [bold cyan]║[/bold cyan]
[bold cyan]╠═══════════════════════════════════════════════════════════════════════╣[/bold cyan]
[bold cyan]║[/bold cyan]  [dim]Menülerde numara girerek seçim yapın.                              [/dim][bold cyan]║[/bold cyan]
[bold cyan]║[/bold cyan]  [dim]Bu komutlar her menü seviyesinde çalışır.                         [/dim][bold cyan]║[/bold cyan]
[bold cyan]╚═══════════════════════════════════════════════════════════════════════╝[/bold cyan]
"""


def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")


def print_banner():
    console.print(BANNER)


def print_separator():
    console.print("[dim]─" * 75 + "[/dim]")


def render_menu(menu_key: str):
    menu = MENUS[menu_key]
    items = menu["items"]

    table = Table(
        box=box.HEAVY_EDGE,
        border_style="bright_cyan",
        show_lines=True,
        width=78,
        title=f"[bold bright_white]{menu['icon']}  {menu['title']}[/bold bright_white]",
        title_style="bold bright_cyan",
        padding=(0, 1),
    )
    table.add_column("No", style="bold bright_yellow", width=4, justify="center")
    table.add_column("Komut", style="bold white", width=28)
    table.add_column("Açıklama", style="dim white", width=40)

    for key, name, desc in items:
        table.add_row(key, name, desc)

    console.print(table)
    console.print(
        "[dim]  Numarayı girin │ [bold]help[/bold] = yardım │ "
        "[bold]back[/bold] = geri │ [bold]exit[/bold] = çıkış[/dim]"
    )


def show_screen(menu_key: str):
    clear_screen()
    print_banner()
    console.print()
    render_menu(menu_key)
    console.print()


def get_input(label: str) -> str:
    try:
        val = console.input(f"  [bold red]{label}[/bold red] [bold white]›[/bold white] ").strip()
        return val
    except (EOFError, KeyboardInterrupt):
        console.print()
        return "exit"


def ask_target(prompt_text: str) -> str | None:
    try:
        val = console.input(f"    [bold cyan]» {prompt_text}:[/bold cyan] ").strip()
        return val if val else None
    except (EOFError, KeyboardInterrupt):
        console.print()
        return None


def ask_optional(prompt_text: str) -> str | None:
    try:
        val = console.input(f"    [dim cyan]» {prompt_text} (Enter = atla):[/dim cyan] ").strip()
        return val if val else None
    except (EOFError, KeyboardInterrupt):
        console.print()
        return None


def is_global_command(cmd: str) -> str | None:
    c = cmd.lower()
    if c in ("help", "h", "?"):
        return "help"
    if c in ("back", "b", "geri", "0"):
        return "back"
    if c in ("home", "ana"):
        return "home"
    if c in ("clear", "cls", "temizle"):
        return "clear"
    if c in ("exit", "quit", "q", "çıkış"):
        return "exit"
    if c in ("status", "durum"):
        return "status"
    return None


def handle_global(cmd: str, tor=None) -> bool:
    if cmd == "help":
        console.print(GLOBAL_HELP)
        return True
    if cmd == "clear":
        clear_screen()
        print_banner()
        console.print()
        return True
    if cmd == "exit":
        console.print("\n[bold yellow]  Oturum kapatılıyor...[/bold yellow]\n")
        if tor:
            tor.close()
        sys.exit(0)
    if cmd == "status":
        console.print("  [dim]Durum kontrol ediliyor...[/dim]", end="\r")
        if tor and tor.check_connection() and tor.active_proxy:
            proxy = tor.active_proxy.get("http", "?")
            console.print(Panel(
                f"[bold green]● Tor Aktif[/bold green]  │  "
                f"Proxy: [white]{proxy}[/white]  │  "
                f"IP: [white]{tor.tor_ip or '?'}[/white]",
                border_style="green", box=box.ROUNDED,
            ))
        else:
            console.print(Panel(
                "[bold red]● Tor Bağlantısı Yok veya Koptu[/bold red]",
                border_style="red", box=box.ROUNDED,
            ))
        return True
    return False


def wait_enter():
    try:
        console.input("\n  [dim]Devam etmek için Enter'a basın...[/dim]")
    except (EOFError, KeyboardInterrupt):
        pass


def print_error(msg: str):
    console.print(f"  [bold red]✗ {msg}[/bold red]")


def print_success(msg: str):
    console.print(f"  [bold green]✓ {msg}[/bold green]")


def print_info(msg: str):
    console.print(f"  [bold cyan]ℹ {msg}[/bold cyan]")


def print_warning(msg: str):
    console.print(f"  [bold yellow]⚠ {msg}[/bold yellow]")
