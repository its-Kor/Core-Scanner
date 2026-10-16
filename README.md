# Network Port Scanner (v1.2)

A lightweight, zero-dependency TCP port scanner written in pure Python. Designed for predictable execution, clear state classification (`open`, `closed`, `no_response`), and low-impact network verification.

---

## 🎯 Operational Use Cases

* **🔴 Red Team / Pentesting (Living off the Land):** Runs entirely on Python's standard library (`socket`, `concurrent.futures`, `errno`, `json`). Can be deployed on restricted pivot hosts without installing external packages or requiring root/`sudo` privileges.
* **🟣 Purple Team (Detection & SIEM Calibration):** Generates a unique `Run ID` and strict `UTC Timestamp` on every execution, making it trivial to correlate scan activity against firewall logs, WAF alerts, and SIEM events. Compare standard concurrency against `--gentle` mode to test rate-limiting thresholds.
* **🔵 Blue Team / SecOps (Safe Surface Auditing):** Distinguishes between actively refused connections (`closed` / `ECONNREFUSED`) and firewall drops (`no_response` / timeout). Includes a confirmation prompt, `--gentle` mode for production-safe checks, and structured JSON export for baseline diffing.

---

## ✨ Key Features (v1.2)

* **Zero External Dependencies:** Uses only Python 3 standard libraries.
* **Three-State Port Classification:** Accurately separates `open`, `closed` (host active, port refused), and `no_response` (filtered/timeout).
* **Bounded Concurrency:** Powered by `ThreadPoolExecutor` with configurable worker limits (`1-100`) and deterministic output ordering.
* **Low-Impact Mode (`--gentle`):** Automatically caps concurrency to `3 workers` and enforces a minimum `2.0s` timeout to avoid stressing fragile or production services.
* **Flexible Target & Port Parsing:** Accepts bare IPs, domains, or full URLs, plus individual ports and ranges (e.g., `22,80,443,8000-8010`).
* **Privacy by Default:** No telemetry or automatic disk writes. Reports are only saved when explicitly requested via `-o / --output`.

---

## 🚀 Installation & Usage

### 1. Clone the repository:
```bash
git clone https://github.com/its-Kor/v1.0---Core-Scanner.git
```

### 2. Access the directory:
```bash
cd v1.0---Core-Scanner
```

### 3. Run the scanner:

**Interactive mode (default top 15 ports):**
```bash
python3 main.py
```

**CLI mode with custom ports and range:**
```bash
python3 main.py -t 127.0.0.1 -p 22,80,443,8000-8010
```

**Low-impact mode for production/sensitive targets:**
```bash
python3 main.py -t example.com --gentle
```

**Automated execution with JSON report export:**
```bash
python3 main.py -t 192.168.1.1 -p 1-1024 -w 30 -y -o report.json
```

---

## ⚙️ CLI Options

| Flag | Description | Default |
| :--- | :--- | :--- |
| `-t`, `--target` | Target IP address, hostname, or URL | Interactive prompt |
| `-p`, `--ports` | Comma-separated ports and/or ranges (e.g., `22,80,8000-8010`) | 15 common ports |
| `-w`, `--workers` | Number of concurrent threads (`1-100`) | `20` |
| `--timeout` | Socket connection timeout in seconds | `1.0` |
| `--gentle` | Low-impact mode (caps at `3` workers, min `2.0s` timeout) | `False` |
| `-y`, `--yes` | Skip interactive permission confirmation prompt | `False` |
| `-o`, `--output` | Export structured scan results to a JSON file | `None` |

---

## 🖥️ Example Output

```text
=============================================
           NETWORK PORT SCANNER v1.2         
=============================================

[*] Run 9f4a2c1b at 2026-10-16 17:19:45 UTC
[*] Target: localhost (127.0.0.1)
[*] 15 ports | workers=3 | timeout=2.0s
[?] Do you have permission to scan this target? [y/N] y
---------------------------------------------
[+] Port 22   /TCP : OPEN  (ssh)
[+] Port 80   /TCP : OPEN  (http)
[+] Port 8080 /TCP : OPEN  (http-alt)
---------------------------------------------
[*] Scan completed in 0.04s! 3 open, 12 closed, 0 no response.
=============================================
```

---

## ⚠️ Legal Disclaimer

This tool is developed strictly for **educational purposes, authorized security auditing, and lab environments**. Scanning targets without prior mutual consent may be illegal in your jurisdiction. The author assumes no liability and is not responsible for any misuse or damage caused by this program. Always obtain explicit permission before scanning any network or host.
