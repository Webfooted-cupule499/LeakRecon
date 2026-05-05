<div align="center">

# LeakRecon

**Dark Web Leak Intelligence & OSINT Reconnaissance Framework**

LeakRecon is a modular, pure-Python cybersecurity framework designed for deep OSINT and leak intelligence gathering exclusively over the Tor network. It provides automated reconnaissance capabilities without relying on external clearnet APIs that could compromise operational security.

</div>

## Features

- **100% Tor-Routed Traffic**: All requests are routed through SOCKS5 Tor proxies (9050/9150). No direct internet exposure.
- **Dark Web Search**: Built-in scraper for querying multiple onion search engines simultaneously.
- **Identity Intelligence**: Search for emails, usernames, phone numbers, and physical addresses across underground sources.
- **Network Forensics**: Perform Tor-routed IP geolocation, port scanning, WHOIS lookups, and reverse DNS.
- **Credential Hunting**: Hunt for compromised credentials, database dumps, stealer logs (Redline, Raccoon, Vidar), and pastebin leaks.
- **Crypto Tracking**: Investigate Bitcoin, Ethereum, and Monero addresses, analyzing wallet associations and ransomware links.
- **Onion Analysis**: Check accessibility, fetch HTTP headers, extract links, and analyze technologies used by hidden services.
- **Reporting System**: Automatically logs all scans into a local SQLite database and generates comprehensive HTML, JSON, and CSV reports.

## Prerequisites

- **Python 3.10+**
- **Tor Service**: Tor must be installed and running in the background.
  - Linux: `sudo apt install tor && sudo systemctl start tor`
  - Windows/macOS: Run the Tor Browser in the background.

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/LeakRecon.git
cd LeakRecon
```

2. Install the required dependencies:
```bash
pip install -r requirements.txt
```

## Usage

Start the interactive CLI framework:
```bash
python main.py
```

### Global Commands
Inside the framework, you can use the following commands at any prompt:
- `help` / `h`: Show the global help menu.
- `back` / `b`: Return to the previous menu.
- `home`: Return to the main menu.
- `clear` / `cls`: Clear the terminal screen.
- `status`: Check the real-time Tor connection status.
- `exit` / `q`: Safely close the application and Tor sessions.

## Disclaimer

This tool is developed for educational purposes, authorized security research, and threat intelligence. The developer assumes no responsibility for any unauthorized or illegal use of this tool. Always ensure you have explicit permission before investigating any infrastructure or identity that does not belong to you.
