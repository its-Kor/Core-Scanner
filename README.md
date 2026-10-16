# Network Port Scanner

A dependency-free TCP port scanner built incrementally, with a focus on
correctness, operator safety, and explicit consent before scanning anything.

## Features

- **Zero third-party dependencies** — Python standard library only, runs
  anywhere `python3` runs.
- **Honest port states** — every port is reported as `open`, `closed`
  (actively refused) or `no_response` (timeout), never a plain `True/False`.
- **Concurrent scanning** — `ThreadPoolExecutor`-based, with a validated
  worker limit (`-w/--workers`, 1-100) to avoid exhausting file descriptors.
- **Gentle mode** (`--gentle`) — automatically caps workers at 3 and raises
  the timeout, for scanning sensitive environments with less network noise.
- **Explicit authorization check** — asks for confirmation before sending
  any packet, unless `-y/--yes` is passed.
- **Flexible port selection** — a custom list/range (`-p`), or a built-in
  profile (`--top-100`, `--top-1000`).
- **Batch targets from a file** (`-i/--input-file`) — scan a whole list of
  IPs, domains or simple CIDR blocks in one run, instead of one at a time.
- **RTT per port** — every scan reports the connection's round-trip time
  in milliseconds (`rtt_ms`), always on, at no extra network cost.
- **Passive banner grabbing** (`--banners`, opt-in) — on open ports, does
  one short, read-only check for whatever the service sends unprompted
  (SSH/FTP/SMTP greetings, etc.). Off by default; never sends a probe.
- **Optional export** — JSON (default) or CSV (`--csv`), written to disk
  only when `-o/--output` is explicitly given. Nothing is saved by default.
- **Interactive fallback** — if `-t/--target` is omitted, the scanner just
  asks for it instead of crashing.

## Requirements

- Python 3.8+ — no `pip install` needed.

## Usage

```bash
# Interactive fallback (no arguments needed)
python3 main.py

# Default quick scan (15 common ports)
python3 main.py -t 192.168.1.10

# Custom ports / ranges
python3 main.py -t example.com -p 22,80,443
python3 main.py -t example.com -p 1-1024

# Built-in port profiles
python3 main.py -t example.com --top-100 -y
python3 main.py -t example.com --top-1000 -y

# Low-impact scan of a sensitive target
python3 main.py -t example.com --gentle -y

# Batch scan every target listed in a file
python3 main.py -i targets.txt --top-100 -y

# Grab a passive banner on open ports (SSH/FTP/SMTP greetings, etc.)
python3 main.py -t example.com --banners -y

# Save results
python3 main.py -t example.com --top-100 -y -o report.json
python3 main.py -t example.com --top-100 -y -o report.csv --csv
```

## Options

| Flag | Description |
|---|---|
| `-t`, `--target` | IP or domain to scan (prompts interactively if omitted) |
| `-i`, `--input-file` | File with one target per line (IPs, domains, or simple CIDR blocks) |
| `-p`, `--ports` | Ports/ranges, e.g. `22,80,443` or `1-1024` |
| `--top-100` | Scan a curated list of 100 common ports |
| `--top-1000` | Scan ports 1-1000 |
| `--timeout` | Socket timeout in seconds (default `1.0`) |
| `-w`, `--workers` | Concurrent workers, 1-100 (default `20`) |
| `--gentle` | Low-impact mode: fewer workers, longer timeout |
| `-y`, `--yes` | Skip the permission confirmation prompt |
| `--banners` | Passively read a short service banner on open ports |
| `-o`, `--output` | Save results to this path |
| `--csv` | Save `-o` results as CSV instead of JSON |

`-p`, `--top-100` and `--top-1000` are mutually exclusive, and so are
`-t` and `-i`.

### Target file format (`-i/--input-file`)

One target per line. Bare hosts, `host:port`, full URLs, and simple CIDR
blocks (e.g. `192.168.1.0/30`) are all accepted. `#` starts a comment,
blank lines are ignored, and duplicates are removed automatically:

```
# targets.txt
10.0.0.5
staging.example.com
192.168.1.0/30   # expands to 4 individual IPs
```

A single CIDR block is capped at 1024 expanded hosts as a safety net —
a typo like `/8` instead of `/28` will raise a clear error instead of
silently scanning millions of addresses.

### Report schema (`-o`)

Both JSON and CSV are built from the same flat list of per-port records,
so scanning several targets just appends more records -- nothing about
an earlier target is ever overwritten:

```json
{
  "run_id": "a1b2c3d4",
  "results": [
    {
      "target": "192.168.1.50",
      "ip": "192.168.1.50",
      "port": 22,
      "state": "open",
      "service": "ssh",
      "rtt_ms": 4.12,
      "banner": "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5"
    }
  ]
}
```

`banner` is `null` unless `--banners` was passed. The CSV has the same
columns as top-level keys here, one row per record.

## Testing

```bash
python3 test_main.py
```

## ⚠️ Responsible use

Only scan systems you own or have explicit, documented authorization to
test. Unauthorized scanning may be illegal depending on your jurisdiction.
The permission prompt is there as a safeguard, not a substitute for actual
authorization.

## Project principles

- **100% standard library** — no runtime dependency ever required.
- **Zero telemetry** — nothing is sent anywhere; everything stays local.
- **Explicit-only writes** — no file is written unless `-o` is passed.
- **Honest socket states** — `open` / `closed` / `no_response`, always.
- **Interactive fallback** — the CLI never hard-fails for a missing `-t`.

## Roadmap

- [x] Robust target parsing (host, host:port, full URL)
- [x] Port state distinction (open/closed/no_response)
- [x] Configurable timeout constant
- [x] `argparse`-based CLI with interactive fallback
- [x] Concurrent scanning (`ThreadPoolExecutor`)
- [x] Gentle mode + run ID/UTC header
- [x] Permission confirmation prompt
- [x] JSON export
- [x] CSV export
- [x] Port profiles (`--top-100` / `--top-1000`)
- [x] Batch targets from file (`-i`/`--input-file`)
- [x] RTT (latency) metrics per port
- [x] Lightweight, opt-in passive banner grabbing (`--banners`)
- [ ] Dynamic timeout auto-tuning based on rolling average RTT

<div align="center">
  
  ### ☕ Support My Work & Security Projects
  
  <p>If my tools or contributions in Red/Blue/Purple Team have been useful to you, consider supporting with a private and decentralized Bitcoin donation.</p>

  <a href="https://trocador.app/anonpay/?ticker_to=btc&network_to=Mainnet&address=bc1q78nt9g3katjlwd0gx7rt8f2lfh7g0dz70kah7c&donation=True&simple_mode=False&email=cripto.swimwear205@passmail.net&buttonbgcolor=9c27b0&bgcolor=0f111aff&direct=True" target="_blank">
    <img src="https://img.shields.io/badge/Support_with-Bitcoin_(AnonPay)-9c27b0?style=for-the-badge&logo=bitcoin&logoColor=white" alt="Donate with Bitcoin via AnonPay">
  </a>

</div>