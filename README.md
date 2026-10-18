# Core-Scanner

![Python 3.8+](https://img.shields.io/badge/python-3.8%2B-blue.svg)
![Dependencies](https://img.shields.io/badge/dependencies-zero%20(stdlib)-brightgreen.svg)
![Version](https://img.shields.io/badge/release-v1.7-orange.svg)
![License](https://img.shields.io/badge/license-MIT-lightgrey.svg)

A dependency-free TCP port scanner and service surface auditor built entirely on the **Python standard library**, focused on honest socket states, TLS inspection, operator safety, and structured reporting.

```text
=============================================
           NETWORK PORT SCANNER v1.7         
=============================================

[*] Run a1b2c3d4 at 2026-10-18 14:30:00 UTC
[*] Target: example.com (93.184.216.34)
[*] 100 ports | workers=20 | timeout=1.0s | banners=on+probe

[+] Port 22   /TCP : OPEN (ssh)   - 18.40ms | SSH-2.0-OpenSSH_8.9p1 Ubuntu-3
[+] Port 80   /TCP : OPEN (http)  - 17.92ms | HTTP/1.1 301 Moved Permanently
[+] Port 443  /TCP : OPEN (https) - 18.15ms [TLSv1.3/TLS_AES_256_GCM_SHA384] | HTTP/1.1 200 OK
[+] Port 6379 /TCP : OPEN (unknown) - 19.04ms
    [!] Redis exposed: verify 'protected-mode' and 'requirepass'.
---------------------------------------------
[*] Scan completed in 1.42s! 4 open, 94 closed, 2 no response.
```

---

## Key Features

* **Core Scanning Engine**
  * **100% Standard Library:** Zero external dependencies (`pip install` is never required).
  * **Honest Socket States:** Distinguishes between `open`, `closed` (`ECONNREFUSED`), and `no_response` (filtered/timeout), recording per-port RTT in milliseconds (`rtt_ms`).
  * **Adaptive Timeout & Gentle Mode:** Dynamically shrinks timeouts toward observed open-port RTTs (`--adaptive-timeout`), or throttles concurrency for sensitive networks (`--gentle`, `--shuffle`).
  * **Batch & CIDR Expansion:** Accepts single hosts, URLs, CIDR blocks (`192.168.1.0/28` capped at 1,024 hosts for safety), or target lists (`-i`).

* **Service & TLS Inspection**
  * **Passive Banner Grabbing (`--banners`):** Read-only capture of spontaneous service greetings (SSH, FTP, SMTP) without sending extra packets.
  * **Real TLS Handshake:** Negotiates TLS on encrypted ports (`443`, `8443`, `993`, etc.) to report the exact protocol version and cipher suite (`TLSv1.3/TLS_AES_256_GCM_SHA384`).
  * **TLS-Safe Active Probing (`--probe`):** Coaxes quiet services (HTTP, Redis, SMTP) with minimal stdlib payloads—sent *after* the TLS handshake on encrypted ports.
  * **Passive Hardening Advisories:** Automatically flags commonly exposed risk ports (Telnet, SMB, unencrypted Docker socket, Redis, databases) with triage notes.

* **Reporting & Baseline Auditing**
  * **Multi-Format Export:** Outputs flat, append-friendly records to **JSON**, **CSV** (`--csv`), and human-readable **Markdown** (`--md`).
  * **Baseline Diffing (`--diff`):** Compares current results against a previous JSON report to highlight newly opened (`+`) or newly closed (`-`) ports.

---

## Quick Start

```bash
# 1. Interactive mode or default quick scan (15 common ports)
python3 main.py -t 192.168.1.10

# 2. Scan top 100 ports with TLS inspection, active probing, and adaptive timeout
python3 main.py -t example.com --top-100 --probe --adaptive-timeout -y

# 3. Scan a CIDR subnet or target file in randomized order and export a Markdown report
python3 main.py -t 192.168.1.0/28 --top-100 --shuffle -y --md report.md
python3 main.py -i targets.txt --top-100 -y -o baseline.json

# 4. Compare today's surface against a previous baseline report
python3 main.py -t example.com --top-100 -y --diff baseline.json
```

---

## CLI Options

| Flag | Description |
| :--- | :--- |
| `-t`, `--target` | IP, domain, URL, or CIDR block to scan (prompts interactively if omitted) |
| `-i`, `--input-file` | File with one target per line (hosts, URLs, or CIDR blocks; `#` comments supported) |
| `-p`, `--ports` | Custom ports/ranges, e.g. `22,80,443` or `1-1024` |
| `--top-100` | Scan a curated list of 100 commonly exposed TCP ports |
| `--top-1000` | Scan IANA well-known ports `1-1000` |
| `--timeout` | Socket timeout ceiling in seconds (default: `1.0`) |
| `-w`, `--workers` | Concurrent worker threads, `1-100` (default: `20`) |
| `--gentle` | Low-impact profile: caps workers at `3` and extends timeout to `>= 2.0s` |
| `--shuffle` | Randomize port scan order on the wire (output remains sorted ascending) |
| `--adaptive-timeout` | Shrink timeout toward the rolling average RTT of `open` ports |
| `--banners` | Passively read service banners and perform TLS version/cipher inspection |
| `--probe`, `--active` | Send minimal protocol-specific probe when passive read is empty (implies `--banners`) |
| `-o`, `--output` | Write scan results to disk (JSON by default) |
| `--csv` | Format `-o` output as CSV instead of JSON |
| `--md` | Generate a human-readable Markdown assessment report |
| `--diff` | Compare current scan against a previous JSON report (`-o`) |
| `-y`, `--yes` | Skip the interactive authorization confirmation prompt |

---

## Architecture & Scope Decisions

* **Zero Third-Party Dependencies:** `python-nmap` and external libraries are deliberately excluded so the scanner runs on any clean Python 3.8+ environment.
* **No Hand-Rolled ASN.1 Parser:** Rather than maintaining a fragile custom DER parser for X.509 certificates under `CERT_NONE`, the scanner reliably reports negotiated TLS versions/ciphers and delegates deep certificate chain auditing to dedicated tools (`openssl x509`, `testssl.sh`, `sslyze`).

---

## Roadmap (v1.8)

- [ ] **Banner & report sanitization** — strip ANSI escapes/control bytes; escape backticks in `--md` and formula prefixes (`=`, `+`, `-`, `@`) in `--csv`
- [ ] **Fail-fast output check** — validate that `-o` and `--md` directories exist and are writable before scanning
- [ ] **TLS handshake timeout cap** — apply `BANNER_TIMEOUT` before `wrap_socket()` so non-TLS ports never stall for the full `--timeout`
- [ ] **Richer protocol parsing** — HTTP `Host:` header, `Location:` redirects, and `<title>`; passive MySQL version decoding; Redis `PING` probe
- [ ] **Opportunistic TLS fallback** — retry with a TLS handshake when `--probe` gets no plaintext reply on non-standard ports
- [ ] **Smart CIDR & port handling** — exclude `.0`/`.255` on IPv4 subnets `< /31` and preserve explicit ports passed via `-t host:port`
- [ ] **Dual-stack IPv4/IPv6** — resolve targets via `getaddrinfo()` with automatic `AF_INET` / `AF_INET6` socket selection
- [ ] **Targeted retries (`--retries`)** — retry only `no_response` ports on lossy/VPN links without re-probing `open` or `closed` ports
- [ ] **Instant `Ctrl+C` & scope-aware `--diff`** — cancel queued worker futures immediately on interrupt and ignore untested baseline ports in `--diff`

---

## Testing & Responsible Use

Run the unit test suite using standard library `unittest`:
```bash
python3 test_main.py
```

> **Warning:** Only scan systems you own or have explicit, written authorization to test.

<div align="center">
  
  ### ☕ Support My Work & Security Projects
  
  <p>If my tools or contributions in Red/Blue/Purple Team have been useful to you, consider supporting with a private and decentralized Bitcoin donation.</p>

  <a href="https://trocador.app/anonpay/?ticker_to=btc&network_to=Mainnet&address=bc1q78nt9g3katjlwd0gx7rt8f2lfh7g0dz70kah7c&donation=True&simple_mode=False&email=cripto.swimwear205@passmail.net&buttonbgcolor=9c27b0&bgcolor=0f111aff&direct=True" target="_blank">
    <img src="https://img.shields.io/badge/Support_with-Bitcoin_(AnonPay)-9c27b0?style=for-the-badge&logo=bitcoin&logoColor=white" alt="Donate with Bitcoin via AnonPay">
  </a>

</div>