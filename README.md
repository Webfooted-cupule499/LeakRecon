<div align="center">
  <img src="img/banner.png" alt="LeakRecon Banner" width="800">
  
  # LeakRecon
  **High-Performance Asynchronous OSINT & Dark Web Intelligence Framework**
  
  [![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
  [![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
  [![Asyncio](https://img.shields.io/badge/asyncio-supported-brightgreen.svg)](https://docs.python.org/3/library/asyncio.html)
  [![Docker](https://img.shields.io/badge/docker-ready-blue.svg)](https://www.docker.com/)

</div>

---

## 📌 Overview

**LeakRecon** is an enterprise-grade, highly scalable asynchronous OSINT (Open Source Intelligence) framework. Designed for security professionals, penetration testers, and threat analysts, LeakRecon automates deep investigations across the Surface Web and the Dark Web. By leveraging modern Python capabilities (`asyncio`, `aiohttp`) over a secure SOCKS5 Tor proxy circuit, the framework executes massive distributed queries without sacrificing anonymity.

From tracking cryptocurrency transactions related to ransomware to uncovering compromised credentials and charting identity footprints, LeakRecon centralizes advanced reconnaissance into a unified, visually stunning CLI interface.

![LeakRecon Interactive CLI](img/cmd.png)
*LeakRecon's Interactive Command Line Interface.*

---

## 🚀 Core Architecture & Features

LeakRecon has been entirely rewritten to transition from a legacy synchronous threaded model to a pure, non-blocking asynchronous event loop architecture.

### 🛡️ Strict Anonymity (Zero-Leak Proxy)
All outbound network operations are rigorously routed through the Tor network. LeakRecon employs internal circuit-breaker mechanisms and dynamic Tor identity refreshing. If the Tor proxy fails, the engine instantly halts execution to prevent accidental IP leaks. 

### ⚡ High-Performance Concurrency
Powered by `aiohttp` and `asyncio.Semaphore`, the framework executes bulk dorking, port scanning, and API scraping concurrently. This drastically reduces execution times during large-scale footprinting operations, effectively utilizing maximum requests-per-second (RPS) limits without triggering rate-limits.

### 🗄️ Professional Database & Reporting Engine
LeakRecon persists all scan findings locally via a thread-safe SQLite backend. It provides advanced historical tracking, chronological scan diffing (to monitor targets over time), and exporting capabilities. Generate high-quality intelligence reports in multiple formats:
- **HTML:** Interactive, dark-themed reports suitable for executive delivery.
- **PDF:** Polished, static document formats powered by `pdfkit` and `wkhtmltopdf`.
- **JSON/CSV:** Raw data exports for SIEM and custom data pipeline integrations.

![LeakRecon HTML Report](img/leak.png)
*Example of a generated comprehensive HTML Intelligence Report.*

---

## 🧩 Reconnaissance Modules

LeakRecon operates through several highly specialized modules, each focused on a unique vector of intelligence.

![LeakRecon Scan Result](img/result.png)
*Real-time username testing and identity profiling via CLI.*

1. **Dark Web Scraper (`modules/darkweb_scraper.py`)**
   - Conducts concurrent dork searches across deep web repositories, paste sites, and Tor-native search engines (e.g., Ahmia, Onion DuckDuckGo).
   - Utilizes advanced false-positive detection algorithms to extract precise target snippets.

2. **Identity Profiling (`modules/identity_recon.py`)**
   - Scans massive datasets for compromised emails, usernames, and physical addresses.
   - Extracts associated hashes and cross-references them against known breaches.

3. **Network Intelligence (`modules/network_intel.py`)**
   - Conducts asynchronous subnet tracking and asynchronous TCP SOCKS5 port enumeration over Tor.
   - Executes DNS, WHOIS, and IP reputation analytics without directly touching the target.

4. **Onion Surface Analyzer (`modules/onion_scanner.py`)**
   - Analyzes bulk `.onion` endpoints for live status, extracts hidden metadata, and performs deep technological fingerprinting.
   - Downloads and isolates `.onion` site resources safely.

5. **Credential Hunting (`modules/credential_hunt.py`)**
   - Hunts for specific user/password combinations across Stealer Logs, combolists, and pastebins.

6. **Crypto Tracker (`modules/crypto_tracker.py`)**
   - Maps blockchain forensics for Bitcoin, Ethereum, and Monero.
   - Correlates wallets to known illicit activities, ransomware variants, and mixer/tumbler services.

---

## 🛠️ Installation & Deployment

LeakRecon provides two seamless deployment strategies. Docker is highly recommended to guarantee absolute network isolation and zero-dependency friction.

### Method 1: Docker Compose (Recommended)

Requires [Docker](https://docs.docker.com/get-docker/) and [Docker Compose](https://docs.docker.com/compose/install/).

```bash
# 1. Clone the repository
git clone https://github.com/egnake/LeakRecon.git
cd LeakRecon

# 2. Setup the environment configuration
cp .env.example .env

# 3. Build the isolated Tor proxy and App containers
docker-compose up -d --build

# 4. Attach to the interactive console
docker exec -it leakrecon_app python main.py
```

### Method 2: Local Python Environment

Requires Python 3.10+ and an active local Tor proxy service.

```bash
# 1. Clone the repository
git clone https://github.com/egnake/LeakRecon.git
cd LeakRecon

# 2. Create and activate a virtual environment
python3 -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# 3. Install required async dependencies
pip install -r requirements.txt

# 4. Setup configuration
cp .env.example .env
```

**⚠️ Important Requirement for PDF Reports:**
If you intend to generate PDF reports locally, you must install `wkhtmltopdf` on your host machine:
- **Debian/Ubuntu:** `sudo apt install wkhtmltopdf`
- **macOS:** `brew install homebrew/cask/wkhtmltopdf`
- **Windows:** Download from the [wkhtmltopdf website](https://wkhtmltopdf.org/) and add it to your system PATH.

**Start the Framework:**
Ensure your Tor daemon or Tor Browser is running (Ports `9050` or `9150`), check the `.env` settings, and run:
```bash
python main.py
```

---

## ⚙️ Configuration (`.env`)

You can precisely tune the async engine by modifying the `.env` file:

```ini
# --- Tor Proxy Configuration ---
# 9050 for Standalone Tor, 9150 for Tor Browser Background
TOR_PROXY_HOST=127.0.0.1
TOR_PROXY_PORT=9150

# --- Engine Constraints ---
# Maximum concurrent asyncio connections
MAX_CONCURRENCY=20

# Timeouts & Retries
ONION_TIMEOUT=30
CLEARNET_TIMEOUT=15
MAX_RETRIES=3
RETRY_BACKOFF=1.5
CIRCUIT_BREAKER_THRESHOLD=2
```

---

## 🧪 Testing

LeakRecon incorporates a `pytest` suite designed to validate core mechanics, proxy handling, and configuration integrity without polluting external environments.

```bash
# Ensure dev-dependencies are installed
pip install pytest pytest-asyncio

# Execute the test suite
pytest tests/
```

---

## ⚖️ Legal Disclaimer

**LeakRecon is engineered strictly for authorized security auditing, academic research, and lawful threat intelligence operations.**

- 🚫 You **MUST NOT** utilize this tool to attack, scan, or scrape targets for which you do not possess explicit, written, and mutual consent.
- 🚫 The author (**egnake**) assumes **ZERO LIABILITY** for misuse, data damage, or illegal activities conducted via this software.
- ⚖️ By downloading, cloning, or executing LeakRecon, you agree to adhere to all applicable local, state, and international cyber laws.

---
<div align="center">
  <i>Developed with precision by <b>Egnake</b></i><br>
  Available under the <a href="LICENSE">MIT License</a>.
</div>
