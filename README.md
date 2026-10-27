# Core-Scanner v1.7

[![Python 3.8+](https://img.shields.io/badge/python-3.8%2B-blue.svg)](#requirements)
[![Standard library](https://img.shields.io/badge/dependencies-stdlib-green.svg)](#requirements)
[![License: MIT](https://img.shields.io/badge/license-MIT-lightgrey.svg)](LICENSE)

A CLI tool for observing TCP ports and service exposure on systems **under explicit authorization**. It supports optional banner/TLS inspection and JSON, CSV, and Markdown reporting, with no external runtime dependencies.

## Requirements

- Python 3.8 or later, as specified by the project's compatibility contract. The test suite for this release was run on **Python 3.13.5 / Linux**. The full 102-test suite also passed on **Python 3.15 / Windows 11**.
- Python standard library only; `requirements.txt` lists no installation dependencies.
- `uv` is optional for selecting a Python interpreter and running the CLI. The code also works directly with `python`.
- Documented authorization for all targets being assessed. Do not use public domains as demonstration targets without permission.

## Project Structure

```text
Core-Scanner/
├── main.py                  # entry point and backward-compatible public facade
├── core_scanner/
│   ├── __init__.py
│   ├── config.py            # port, timeout, and resource-limit constants
│   ├── models.py            # ScanResult, DiffResult, cancellation exceptions
│   ├── targets.py           # parsing, CIDR, validation, DNS after consent
│   ├── network.py           # TCP sockets, TLS, banners, connection states
│   ├── scheduler.py         # ThreadPoolExecutor with a bounded task window
│   ├── baseline.py          # JSON loading/validation, conservative diff
│   ├── reports.py           # JSON, CSV, Markdown, sanitization, safe writes
│   └── cli.py               # argparse and target/port selection
├── tests/
│   ├── test_main.py         # 88 regression tests preserved from Phase 3
│   └── test_architecture.py # additional architecture/contract tests
├── README.md
├── requirements.txt
├── .gitignore
└── LICENSE
```

`main.py` **deliberately retains CLI orchestration**: existing consumers and tests use `mock.patch.object(main, "scan_port" / "parse_args" / "resolve_address" / "scan_ports_bounded" / "save_results", ...)`. Simply re-exporting these names would not preserve call-site bindings if orchestration were imported from another module. The implementation is therefore split into modules, while its integration points remain patchable through `main` without circular imports.

**Dependencies between modules** (arrows indicate which module imports which):

```text
main -> cli, targets, network, scheduler, reports, baseline, models, config
cli -> targets, config
network -> models, config
scheduler -> models, config
targets -> config
reports -> baseline, config
baseline -> models, config
models, config -> standard library
```

## Running the Scanner (PowerShell / Windows 11)

From the repository root, using Python managed by uv:

```powershell
uv python find
uv run --no-project --offline python -B main.py --help
uv run --no-project --offline python -B -m unittest discover -s tests -v
```

Without uv, after selecting a compatible Python interpreter:

```powershell
python -B main.py --help
python -B -m unittest discover -s tests -v
```

With **authorization** for the laboratory targets, local examples:

```powershell
# No active probes; prompts for authorization interactively
uv run --no-project --offline python -B main.py -t 127.0.0.1 -p 22,80,443

# IPv6 loopback, explicit ports, no banner collection
uv run --no-project --offline python -B main.py -t ::1 -p 80,443

# Keep scan results in a local directory ignored by Git.
# Reports may contain IP addresses, open ports, and service banners.
New-Item -ItemType Directory -Force -Path scan-results | Out-Null

# New reports: destination files must NOT already exist; JSON + Markdown
uv run --no-project --offline python -B main.py -t 127.0.0.1 -p 80 -o scan-results/baseline.json --md scan-results/summary.md

# Compare with a valid baseline; preserve the original scope
uv run --no-project --offline python -B main.py -t 127.0.0.1 -p 80 --diff scan-results/baseline.json
```

`-y / --yes` only skips the prompt; it **does not constitute proof of authorization**. Project policy requires consent before DNS resolution, either collected through the interactive CLI or affirmed by the operator with `-y`.

## CLI Options

| Option | Behavior |
| --- | --- |
| `-t`, `--target` / `-i`, `--input-file` | IP/hostname/URL/CIDR target or UTF-8 target list (mutually exclusive) |
| `-p`, `--ports` / `--top-100` / `--top-1000` | Custom ports, curated set, or ports 1–1000 (mutually exclusive) |
| `--timeout`, `-w`, `--workers` | TCP timeout (0.2–30 s), workers (1–100) |
| `--gentle`, `--shuffle`, `--adaptive-timeout` | Reduced-concurrency profile, randomized order, adaptive timeout reduction |
| `--banners`, `--probe` (`--active`) | Passive banner/TLS inspection; optional, bounded active probing |
| `-o`, `--output`, `--csv`, `--md` | JSON/CSV and Markdown reports |
| `--diff` | Compare against a previous JSON report using conservative state transitions |
| `-y`, `--yes` | Skip the prompt after local validation and before DNS resolution |

**Scope limits:** 1,024 addresses per CIDR, 1,024 unique targets per run, 4,096 ports, and 262,144 target–port combinations; target files are limited to 1 MiB and 8,192 lines. Hostnames are normalized using IDNA; IPv6 is supported; IPv6 zone identifiers are not accepted. Ports embedded in URLs do not override `--ports`.

## Reports and Baseline Diff

- **JSON:** fields `run_id`, `target`, `ip`, `port`, `state`, `service`, `rtt_ms`, `tls_info`, `banner`, and `advisory`; the original banner is retained with safe JSON escaping. Previously generated valid v1.7 reports remain supported.
- **CSV:** potentially formula-interpreted prefixes are neutralized; dangerous control characters receive a literal representation. Exercise additional care when opening reports in external applications.
- **Markdown/terminal:** ANSI sequences, control characters, and presentation syntax from service-provided content are neutralized; structured data is not altered by this formatting.
- **Previous JSON reports:** structural and type validation, duplicate detection, a 256 MiB size limit, a 262,144-record limit, and a maximum nesting depth of 16.
- **Diff:** `closed -> open` and `open -> closed` are confirmed transitions; differing states involving `no_response`, `error`, or `unknown` produce inconclusive comparisons. An `open` port absent from the baseline is a **first observation**, not proof that it has recently opened. Ports that were not scanned are not reported as closed.
- **No overwriting:** existing destination files must not be overwritten. Publication through a temporary file and an exclusive hardlink (`os.link`) depends on filesystem support. Separate JSON and Markdown outputs do not form a single transaction. Review destination paths and permissions before running, especially on NTFS volumes or network shares.

## Concurrency and TLS Inspection

The task window (`ThreadPoolExecutor.submit` + `wait`) maintains at most `2 × workers` submitted futures per target at any time, with backpressure and cooperative cancellation. `Ctrl+C` during a scan prevents incomplete results from being published (exit code `130`); unexpected worker exceptions result in exit code `1`. Blocked socket operations finish within their applicable timeouts, not instantaneously.

TCP timeout: `--timeout`; TLS handshake: 1 s; banner/probe: 0.75 s per operation or the probe's shared deadline. Duration measurements use a monotonic clock. TLS negotiation intentionally uses `CERT_NONE` to observe encryption on services with self-signed or expired certificates; it **does not validate certificates or server identity**. Only configured direct-TLS ports receive a handshake; automatic STARTTLS is not supported.

`no_response` indicates a timeout or a known reachability error; `closed` means a confirmed refusal; `error` covers unclassified error codes; and `open` means the TCP connection was accepted. TLS failure does not change an observed TCP `open` state. Synchronous DNS resolution still depends on the operating system's resolver.

## Development, Compatibility, and Testing

Run the tests **without public targets**:

```powershell
uv run --no-project --offline python -B -m unittest discover -s tests -v
uv run --no-project --offline python -B main.py --help
python -B -m compileall -q .
git status --short
git diff --check
```

The tests use mocks, import subprocesses, and controlled loopback connections. The architecture preserves `main.ScanResult` (five fields), `main.DiffResult` (historical tuple-unpacking behavior), CLI signatures, and substitutions made with `mock.patch.object(main, ...)`. `main.scan_port` and `main.load_previous_report` have explicit wrappers that forward local changes to `TLS_PORTS` and JSON limits in tests. Importing modules does not request input, perform DNS resolution, or start a scan.

**Compatibility caveat:** `__module__` values and the defining locations of data contracts changed when the modules were extracted. Newly pickled objects may require the new structure and may not be loadable by older code; backward compatibility of serialized Python objects is not guaranteed. Existing valid **JSON** contracts remain supported.

Contributions: preserve CLI/JSON contracts and resource limits; add a regression test for each change; run all tests before committing; review staged files for secrets; and make commits manually. Do not use `reset`, `rebase`, force pushes, or authorship changes without a deliberate decision.

## License

MIT — see [LICENSE](LICENSE). The license file and author identity have been preserved.


---

<div align="center">
  
  ### ☕ Support My Work & Security Projects
  
  <p>If my tools or contributions in Red/Blue/Purple Team have been useful to you, consider supporting with a private and decentralized Bitcoin donation.</p>

  <a href="https://trocador.app/anonpay/?ticker_to=btc&network_to=Mainnet&address=bc1q78nt9g3katjlwd0gx7rt8f2lfh7g0dz70kah7c&donation=True&simple_mode=False&email=cripto.swimwear205@passmail.net&buttonbgcolor=9c27b0&bgcolor=0f111aff&direct=True" target="_blank">
    <img src="https://img.shields.io/badge/Support_with-Bitcoin_(AnonPay)-9c27b0?style=for-the-badge&logo=bitcoin&logoColor=white" alt="Donate with Bitcoin via AnonPay">
  </a>

</div>
