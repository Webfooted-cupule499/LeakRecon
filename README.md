<div align="center">

```text
  ██╗     ███████╗ █████╗ ██╗  ██╗██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
  ██║     ██╔════╝██╔══██╗██║ ██╔╝██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
  ██║     █████╗  ███████║█████╔╝ ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
  ██║     ██╔══╝  ██╔══██║██╔═██╗ ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
  ███████╗███████╗██║  ██║██║  ██╗██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
  ╚══════╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
```

**Dark Web Leak Intelligence & OSINT Reconnaissance Framework**

LeakRecon is a modular, high-performance, pure-Python cybersecurity framework designed for deep OSINT and leak intelligence gathering exclusively over the Tor network. It provides automated reconnaissance capabilities without relying on external clearnet APIs that could compromise operational security.

</div>

---

## 🛡️ Core Philosophy: 100% Tor-Routed

Operational security is the foundation of LeakRecon. **No requests are made over the clearnet.** Every DNS resolution, API call, scraper request, and ping is forcefully routed through a local Tor SOCKS5 proxy. This ensures complete anonymity and prevents accidental leakage of target information to third-party endpoints. 

## ⚡ Features & Capabilities

LeakRecon is divided into several powerful modules, all accessible through a seamless interactive CLI framework:

### 1. 🌐 Dark Web Search Engine Scraper
A multi-threaded scraper engine that queries top Onion search engines simultaneously.
- Search by email, username, phone number, IP, domain, or raw dorks.
- Bulk scanning support via text files.
- Automatically handles Tor captchas and timeouts.

### 2. 👤 Identity Intelligence (OSINT)
Correlate human targets with data breaches and digital footprints.
- **E-Mail OSINT**: Scrape paste sites and databases for email associations.
- **Username Profiling**: Track threat actor aliases across underground forums.
- **Phone Number Tracing**: Identify leaked records tied to cellular numbers.
- **Hash Lookup**: Reverse lookup MD5/SHA-256 hashes against dark web rainbow tables.

### 3. 🔌 Network Forensics
Investigate infrastructure without touching it directly from your real IP.
- **Tor-Routed Port Scanner**: Scan targets entirely over the Tor network using custom socket proxies.
- **DNS & Reverse DNS**: Resolve A/AAAA/MX/TXT records anonymously.
- **IP Reputation**: Check if an IP belongs to a botnet, C2 server, or Tor Exit Node.
- **Subnet Scanning**: Scan an entire CIDR block for live hosts and common web ports (80/443).

### 4. 🧅 Deep Onion Scanner
Analyze hidden services dynamically.
- **Accessibility Checks**: Verify if a `.onion` service is alive.
- **Technology Fingerprinting**: Detect the underlying CMS, server, and JS libraries running behind the onion.
- **Link Extraction**: Crawl and extract all internal/external links from a hidden service.
- **Source Downloading**: Download the raw HTML of any onion site securely.

### 5. 🔑 Credential Hunting
Actively hunt for exposed data.
- **Stealer Logs**: Search for Redline, Raccoon, and Vidar stealer dumps.
- **Database Leaks**: Hunt for `.sql` dumps and compromised database schemas.
- **Combo Lists**: Search for `user:pass` and `email:pass` distributions.

### 6. ₿ Crypto & Blockchain Tracking
Investigate cryptocurrency addresses for illicit activities.
- **Wallet Association**: Map Bitcoin (BTC), Ethereum (ETH), and Monero (XMR) addresses to known darknet markets.
- **Ransomware Tracking**: Check addresses against known ransomware syndicates.
- **Mixer/Tumbler Detection**: Identify if funds are being obfuscated through coin mixers.

### 7. 📊 Reporting & Database
All scans are automatically saved.
- **SQLite Storage**: Everything is preserved in a local `.db` file.
- **Diff Analysis**: Compare a new scan with a previous scan of the same target to find *new* leaks.
- **Exporting**: Generate beautiful HTML dashboards, JSON APIs, or CSV files of your findings.

---

## 🚀 Installation

### Prerequisites
- **Python 3.10+**
- **Tor Service**: Tor must be installed and running in the background.

#### Setting up Tor (Linux / Kali / Ubuntu)
```bash
sudo apt update
sudo apt install tor
sudo systemctl enable tor
sudo systemctl start tor
```

#### Setting up Tor (Windows / macOS)
The easiest way is to download and run the [Tor Browser](https://www.torproject.org/download/). Keep it open in the background, and LeakRecon will automatically hook into its proxy port (9150).

### Installing LeakRecon

1. Clone the repository:
```bash
git clone https://github.com/yourusername/LeakRecon.git
cd LeakRecon
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

---

## 🎯 Usage

Start the interactive CLI:
```bash
python main.py
```

### Global Commands
You can type these at **any** prompt to control the framework:
- `help` / `h`: Show the global help menu.
- `back` / `b`: Return to the previous menu.
- `home`: Return to the main menu.
- `clear` / `cls`: Clear the terminal screen.
- `status`: Check real-time Tor connectivity and IP.
- `exit` / `q`: Safely close the application and destroy Tor sessions.

---

## ⚠️ Disclaimer

LeakRecon is developed exclusively for **educational purposes, authorized security research, and threat intelligence**. 

The developer assumes no responsibility for any unauthorized, illegal, or malicious use of this tool. This framework interacts with public data and dark web indexes. Always ensure you have explicit permission before investigating any infrastructure, domain, or identity that does not belong to you.

**Use responsibly.**
