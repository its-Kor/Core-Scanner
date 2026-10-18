#!/usr/bin/env python3
import argparse
import csv
import errno
import ipaddress
import json
import random
import socket
import ssl
import sys
import threading
import time
import uuid
from collections import namedtuple
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from urllib.parse import urlparse

# ---------------------------------------------------------------
# CONSTANTS
# ---------------------------------------------------------------
TIMEOUT = 1.0  # seconds to wait per port
DEFAULT_PORTS = [21, 22, 23, 25, 53, 80, 110, 139, 443, 445,
                  3306, 3389, 5432, 8080, 8443]

# Curated list of 100 commonly-seen / frequently-scanned TCP ports
# (classic well-known services + widely used application ports).
# Not an exact copy of any specific vendor's proprietary ranking.
TOP_100_PORTS = [
    20, 21, 22, 23, 25, 53, 67, 68, 69, 80,
    88, 110, 111, 119, 123, 135, 137, 138, 139, 143,
    161, 162, 179, 194, 389, 443, 445, 464, 465, 500,
    512, 513, 514, 515, 520, 540, 548, 554, 587, 593,
    623, 631, 636, 646, 691, 860, 873, 902, 989, 990,
    993, 995, 1025, 1026, 1027, 1028, 1029, 1080, 1194, 1241,
    1311, 1337, 1433, 1434, 1521, 1723, 1755, 1812, 1813, 1883,
    2000, 2049, 2082, 2083, 2086, 2087, 2095, 2096, 2222, 2375,
    3000, 3128, 3268, 3306, 3389, 3690, 4444, 4500, 4567, 4899,
    5000, 5060, 5432, 5900, 5985, 5986, 6379, 6667, 7000, 8080,
]

# Deliberately simple and transparent definition: the 1000 lowest-numbered
# ports (1-1000). This covers essentially every IANA "well-known" port and
# is easy to verify/reason about -- it is NOT a statistically-ranked
# frequency list like some third-party tools ship.
TOP_1000_PORTS = list(range(1, 1001))

# Safety cap for batch target files / CIDR blocks: a typo like "/8"
# instead of "/28" must never silently blow up into a scan of millions
# of hosts. Anything larger than this is rejected with a clear error.
MAX_HOSTS_PER_CIDR = 1024

# Dedicated, short timeout for banner reads (passive or active). Kept
# independent of the connection --timeout (which --gentle extends): a
# banner, when a service sends one, arrives almost instantly.
BANNER_TIMEOUT = 0.75
BANNER_MAX_BYTES = 256
BANNER_MAX_LEN = 200

# Ports that speak TLS directly (as opposed to plaintext-then-STARTTLS,
# which this tool does not attempt). Banner/probe logic performs a real
# TLS handshake on these before trying to read or send anything, instead
# of throwing plaintext HTTP at an encrypted socket.
TLS_PORTS = {443, 465, 636, 989, 990, 993, 995, 2083, 2087, 2096, 5986, 8443}

# Minimal, protocol-appropriate payloads used ONLY when --probe is passed
# and passive listening got nothing back. For TLS_PORTS, this is sent
# AFTER the TLS handshake, over the encrypted stream. No exploitation,
# no third-party library -- just stdlib sockets/ssl.
ACTIVE_PROBE_PAYLOADS = {
    21: b"\r\n",                     # FTP: a nudge often re-sends the banner
    23: b"\r\n",                     # Telnet
    25: b"EHLO scanner\r\n",         # SMTP
    80: b"HEAD / HTTP/1.0\r\n\r\n",
    443: b"HEAD / HTTP/1.0\r\n\r\n",
    6379: b"INFO server\r\n",        # Redis
    8000: b"HEAD / HTTP/1.0\r\n\r\n",
    8080: b"HEAD / HTTP/1.0\r\n\r\n",
    8443: b"HEAD / HTTP/1.0\r\n\r\n",
}
ACTIVE_PROBE_FALLBACK = b"\r\n"

# Passive, well-known hardening reminders for commonly-exposed service
# ports. Purely informational text, no exploit content -- the kind of
# note any CIS-style hardening checklist already carries.
PORT_SECURITY_NOTES = {
    21: "Plaintext FTP: check for anonymous login and cleartext credentials.",
    23: "Telnet exposed: cleartext remote admin; prefer SSH.",
    139: "NetBIOS Session Service: verify SMB segmentation and null-session restrictions.",
    445: "SMB over TCP: verify SMB signing requirement and patch level.",
    2375: "Unencrypted Docker daemon socket: critical risk if reachable without TLS.",
    3306: "MySQL/MariaDB exposed: verify network ACLs and authentication.",
    3389: "RDP exposed: verify Network Level Authentication (NLA) and TLS enforcement.",
    5432: "PostgreSQL exposed: review pg_hba.conf and TLS requirements.",
    5900: "VNC exposed: verify authentication strength and encryption.",
    6379: "Redis exposed: verify 'protected-mode' and 'requirepass'.",
}

# Adaptive timeout bounds: it can only ever shrink the operator's chosen
# --timeout down towards real observed latency, never exceed it, and
# never drop below this floor no matter how fast the network looks.
ADAPTIVE_TIMEOUT_FLOOR = 0.2
ADAPTIVE_TIMEOUT_MARGIN = 4.0   # new timeout = margin * observed avg RTT
ADAPTIVE_TIMEOUT_ALPHA = 0.3    # EMA smoothing factor

# state:     'open' / 'closed' (refused) / 'no_response' (timeout/error)
# rtt_ms:    round-trip time of the connection attempt itself, in ms
# banner:    short passive/active read of service data, or None
# tls_info:  "TLSv1.x/CIPHER_NAME" for ports in TLS_PORTS, else None
# advisory:  a PORT_SECURITY_NOTES hint for this port, or None
ScanResult = namedtuple("ScanResult", ["state", "rtt_ms", "banner", "tls_info", "advisory"])


class AdaptiveTimeout:
    """Thread-safe exponential moving average of REAL observed RTTs,
    sourced ONLY from OPEN ports (not closed ones). This matters: some
    networks have an edge firewall that answers closed ports with an
    almost-instant RST, while real open services sit behind a slower
    internal hop -- feeding both into the same average would bias the
    timeout down based on the firewall's speed, not the service's, and
    could start starving genuinely slow (but open) ports later in the
    scan. The value only ever moves between ADAPTIVE_TIMEOUT_FLOOR and
    the operator's original --timeout -- it can make a scan faster,
    never slower than what was explicitly requested."""

    def __init__(self, ceiling):
        self._lock = threading.Lock()
        self._ceiling = ceiling
        self._timeout = ceiling
        self._ema_rtt_ms = None

    def get(self):
        with self._lock:
            return self._timeout

    def update(self, rtt_ms):
        with self._lock:
            if self._ema_rtt_ms is None:
                self._ema_rtt_ms = rtt_ms
            else:
                self._ema_rtt_ms = (ADAPTIVE_TIMEOUT_ALPHA * rtt_ms
                                     + (1 - ADAPTIVE_TIMEOUT_ALPHA) * self._ema_rtt_ms)
            candidate = (self._ema_rtt_ms * ADAPTIVE_TIMEOUT_MARGIN) / 1000.0
            self._timeout = max(ADAPTIVE_TIMEOUT_FLOOR, min(candidate, self._ceiling))

    def summary(self):
        with self._lock:
            if self._ema_rtt_ms is None:
                return None
            return self._ema_rtt_ms, self._timeout


def get_service_name(port):
    """Returns the standard service name for a port (e.g., 80 -> HTTP)."""
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"


def clean_target(user_input):
    """Extract the hostname from a bare host, host:port or full URL.
    Does NOT handle CIDR notation -- see expand_target_entry for that."""
    target = user_input.strip()
    if "://" not in target:
        target = "//" + target
    try:
        return urlparse(target).hostname or ""
    except ValueError:
        return ""


def expand_target_entry(entry):
    """Expand ONE raw target string into a list of concrete targets:
    a CIDR block (e.g. 192.168.1.0/28) becomes every address in it; a
    bare host, host:port or full URL becomes a single cleaned hostname.
    Used for BOTH -t/--target and -i/--input-file, so a CIDR passed
    directly via -t is expanded exactly like one found in a file --
    previously, -t silently urlparse'd away the "/28" and scanned only
    the network address."""
    line = entry.split("#", 1)[0].strip()
    if not line:
        return []

    if "/" in line and "://" not in line:
        try:
            network = ipaddress.ip_network(line, strict=False)
        except ValueError:
            raise ValueError(f"invalid CIDR block: {line!r}")
        if network.num_addresses > MAX_HOSTS_PER_CIDR:
            raise ValueError(
                f"{line!r} expands to {network.num_addresses} hosts, "
                f"which is over the safety limit of {MAX_HOSTS_PER_CIDR}"
            )
        return [str(ip) for ip in network]

    cleaned = clean_target(line)
    return [cleaned] if cleaned else []


def read_targets_file(path):
    """Read targets from a file: one per line (see expand_target_entry
    for accepted formats). '#' starts a comment, blank lines are
    ignored. Duplicates are removed, order is preserved."""
    targets = []
    seen = set()
    with open(path, "r", encoding="utf-8") as f:
        for raw_line in f:
            for t in expand_target_entry(raw_line):
                if t not in seen:
                    seen.add(t)
                    targets.append(t)
    if not targets:
        raise ValueError(f"no valid targets found in {path}")
    return targets


def parse_ports(spec):
    """Turn '22,80,8000-8010' into a sorted list of ints.
    Trailing/empty commas (e.g. '22,80,') are ignored instead of raising."""
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if "-" in part:
            lo, hi = part.split("-", 1)
            ports.update(range(int(lo), int(hi) + 1))
        elif part:
            ports.add(int(part))
    if not ports or min(ports) < 1 or max(ports) > 65535:
        raise ValueError("ports must be between 1 and 65535")
    return sorted(ports)


def _sni_for(hostname):
    """Never send a literal IP address in the TLS SNI field (RFC 6066
    says SNI is for hostnames; some OpenSSL/Python combinations raise
    on an IP literal, others silently accept it -- either way, sending
    one serves no purpose). Returns None for an IP, else the hostname."""
    if not hostname:
        return None
    try:
        ipaddress.ip_address(hostname)
        return None
    except ValueError:
        return hostname


def _read_banner(sock):
    """Best-effort PASSIVE read of a service banner on an already-open
    (and, for TLS ports, already-handshaken) socket: never sends
    anything, just listens for BANNER_TIMEOUT. Returns None if nothing
    arrives -- many services never send anything unprompted."""
    try:
        sock.settimeout(BANNER_TIMEOUT)
        data = sock.recv(BANNER_MAX_BYTES)
    except socket.error:
        return None
    if not data:
        return None
    text = data.decode("utf-8", errors="replace").strip()
    if not text:
        return None
    return text.splitlines()[0][:BANNER_MAX_LEN]


def _active_probe(sock, port):
    """ACTIVE probing: send one small, protocol-appropriate payload to
    coax a quiet service into responding, then do one more short read.
    For TLS_PORTS, the caller has already wrapped `sock` in a completed
    TLS handshake, so this payload travels encrypted, exactly like a
    real client's would."""
    payload = ACTIVE_PROBE_PAYLOADS.get(port, ACTIVE_PROBE_FALLBACK)
    try:
        sock.sendall(payload)
        sock.settimeout(BANNER_TIMEOUT)
        data = sock.recv(BANNER_MAX_BYTES)
    except socket.error:
        return None
    if not data:
        return None
    text = data.decode("utf-8", errors="replace").strip()
    if not text:
        return None
    return text.splitlines()[0][:BANNER_MAX_LEN]


def _inspect_tls(raw_sock, hostname, port, active_probe):
    """Perform a real TLS handshake on an already-connected socket and
    report the negotiated protocol version and cipher. Certificate
    validation is deliberately disabled (CERT_NONE) -- this is a
    scanner, not a browser, and must be able to report on self-signed
    or expired certificates rather than refuse to connect to them.
    Returns (tls_info, banner); either may be None on failure."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with ctx.wrap_socket(raw_sock, server_hostname=_sni_for(hostname)) as tls_sock:
            tls_ver = tls_sock.version() or "TLS"
            cipher = tls_sock.cipher()
            cipher_name = cipher[0] if cipher else "unknown-cipher"
            tls_info = f"{tls_ver}/{cipher_name}"

            banner = _read_banner(tls_sock)
            if banner is None and active_probe:
                banner = _active_probe(tls_sock, port)
            return tls_info, banner
    except (ssl.SSLError, socket.error):
        return None, None


def scan_port(target_ip, port, timeout=TIMEOUT, grab_banner=False,
              active_probe=False, hostname=None):
    """Attempt to connect to one port. Always returns a ScanResult with
    the same honest 'open'/'closed'/'no_response' state as before, plus
    RTT, and (only for open ports, only when asked) a banner, TLS info,
    and a passive security advisory."""
    banner = None
    tls_info = None
    advisory = None
    start = time.perf_counter()
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
            client.settimeout(timeout)
            code = client.connect_ex((target_ip, port))
            rtt_ms = (time.perf_counter() - start) * 1000
            if code == 0:
                state = "open"
                advisory = PORT_SECURITY_NOTES.get(port)
                if grab_banner:
                    if port in TLS_PORTS:
                        tls_info, banner = _inspect_tls(
                            client, hostname or target_ip, port, active_probe
                        )
                    else:
                        banner = _read_banner(client)
                        if banner is None and active_probe:
                            banner = _active_probe(client, port)
            elif code == errno.ECONNREFUSED:
                state = "closed"
            else:
                state = "no_response"
    except socket.error:
        rtt_ms = (time.perf_counter() - start) * 1000
        state = "no_response"
    return ScanResult(state, round(rtt_ms, 2), banner, tls_info, advisory)


def parse_args():
    """Read the command-line arguments."""
    p = argparse.ArgumentParser(description="Simple TCP port scanner")

    target_source = p.add_mutually_exclusive_group()
    target_source.add_argument("-t", "--target", help="IP, domain, or CIDR to scan")
    target_source.add_argument("-i", "--input-file",
                                help="file with one target per line "
                                     "(IPs, domains, or simple CIDR blocks)")

    port_source = p.add_mutually_exclusive_group()
    port_source.add_argument("-p", "--ports", help="e.g. 22,80,443 or 1-1024")
    port_source.add_argument("--top-100", action="store_true",
                              help="scan the 100 most common ports")
    port_source.add_argument("--top-1000", action="store_true",
                              help="scan ports 1-1000")

    p.add_argument("--timeout", type=float, default=TIMEOUT,
                   help="socket timeout in seconds (ceiling, if --adaptive-timeout)")
    p.add_argument("-w", "--workers", type=int, default=20,
                   help="concurrent workers (1-100)")
    p.add_argument("--gentle", action="store_true",
                   help="fewer workers, longer timeout (less noisy on the network)")
    p.add_argument("--shuffle", action="store_true",
                   help="randomize port scan order instead of ascending")
    p.add_argument("--adaptive-timeout", action="store_true",
                   help="shrink the timeout towards the observed average RTT of "
                        "OPEN ports as the scan progresses (never exceeds --timeout)")
    p.add_argument("-y", "--yes", action="store_true",
                   help="skip the permission confirmation prompt")
    p.add_argument("--banners", action="store_true",
                   help="read a short service banner (and TLS info) on open ports")
    p.add_argument("--probe", "--active", action="store_true", dest="probe",
                   help="if a passive banner read gets nothing, send one small "
                        "protocol-appropriate payload to coax a reply (implies "
                        "--banners; sent over TLS for TLS ports)")
    p.add_argument("-o", "--output", help="save results to this path")
    p.add_argument("--csv", action="store_true",
                   help="save -o results as CSV instead of JSON")
    p.add_argument("--md", help="also save a human-readable Markdown report to this path")
    p.add_argument("--diff", help="compare against a previous JSON report "
                                   "(from -o) and flag new/closed ports")
    return p.parse_args()


def resolve_ports(args):
    """Decide which port list to scan, based on the mutually exclusive
    -p / --top-100 / --top-1000 flags (falls back to DEFAULT_PORTS)."""
    if args.top_1000:
        return list(TOP_1000_PORTS)
    if args.top_100:
        return list(TOP_100_PORTS)
    if args.ports:
        return parse_ports(args.ports)
    return list(DEFAULT_PORTS)


def resolve_targets(args):
    """Decide which raw target strings to scan: from -i/--input-file,
    from -t/--target (CIDR-aware, see expand_target_entry), or (if
    neither was given) the usual input() prompt."""
    if args.input_file:
        return read_targets_file(args.input_file)
    raw = args.target or input("[?] Enter the target IP, domain, or CIDR: ")
    targets = expand_target_entry(raw)
    if not targets:
        raise ValueError("no valid target provided")
    return targets


def build_records(run_id, scans):
    """Flatten `scans` into the per-port record list shared by the JSON
    and CSV writers, the Markdown report, and the --diff comparison."""
    records = []
    for scan in scans:
        for port, result in zip(scan["ports"], scan["results"]):
            records.append({
                "run_id": run_id,
                "target": scan["target"],
                "ip": scan["ip"],
                "port": port,
                "state": result.state,
                "service": get_service_name(port),
                "rtt_ms": result.rtt_ms,
                "tls_info": result.tls_info,
                "banner": result.banner,
                "advisory": result.advisory,
            })
    return records


def save_results(path, as_csv, run_id, scans):
    """Write the scan results to disk, in JSON (default) or CSV (--csv).
    Both are built from the SAME flat list of per-port records, so
    scanning several targets just appends more records -- nothing about
    an earlier target is ever overwritten."""
    records = build_records(run_id, scans)

    if as_csv:
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["run_id", "target", "ip", "port", "state", "service",
                              "rtt_ms", "tls_info", "banner", "advisory"])
            for r in records:
                writer.writerow([r["run_id"], r["target"], r["ip"], r["port"],
                                  r["state"], r["service"], f"{r['rtt_ms']:.2f}",
                                  r["tls_info"] or "", r["banner"] or "",
                                  r["advisory"] or ""])
    else:
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"run_id": run_id, "results": records}, f, indent=2)


def save_markdown_report(path, run_id, scans, duration, diff_result=None):
    """Write a human-readable Markdown summary: an open-ports table,
    any passive hardening advisories, and (if --diff was used) what
    changed since the previous report."""
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    lines = [
        f"# Port Scan Report (`{run_id}`)",
        f"- **Generated:** {now_str}",
        f"- **Duration:** {duration:.2f}s",
        "",
        "## Open Ports",
        "| Target | IP | Port | Service | RTT (ms) | TLS | Banner |",
        "| :--- | :--- | :--- | :--- | ---: | :--- | :--- |",
    ]

    advisories = []
    any_open = False
    for scan in scans:
        for port, result in zip(scan["ports"], scan["results"]):
            if result.state != "open":
                continue
            any_open = True
            banner_cell = (result.banner or "-").replace("|", "\\|")
            lines.append(
                f"| `{scan['target']}` | `{scan['ip']}` | **{port}** | "
                f"{get_service_name(port)} | {result.rtt_ms:.2f} | "
                f"{result.tls_info or '-'} | `{banner_cell}` |"
            )
            if result.advisory:
                advisories.append((scan["target"], port, result.advisory))

    if not any_open:
        lines.append("| *none* | - | - | - | - | - | - |")

    if advisories:
        lines += ["", "## Hardening Notes"]
        for target, port, note in advisories:
            lines.append(f"- **`{target}:{port}`** -- {note}")

    if diff_result is not None:
        new_open, newly_closed = diff_result
        lines += ["", "## Changes Since Previous Report"]
        if not new_open and not newly_closed:
            lines.append("- No port state changes detected.")
        for target, port in new_open:
            lines.append(f"- **[NEW OPEN]** `{target}:{port}`")
        for target, port in newly_closed:
            lines.append(f"- **[CLOSED]** `{target}:{port}`")

    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def load_previous_report(path):
    """Load a previous JSON report produced by this tool's -o option,
    for use with --diff. Raises ValueError with a clear message if the
    file can't be read or doesn't look like one of our reports."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        raise ValueError(f"could not read previous report {path!r}: {e}")
    if not isinstance(data, dict) or "results" not in data:
        raise ValueError(f"{path!r} doesn't look like a report produced by this tool")
    return {(r["target"], r["port"]): r["state"] for r in data["results"]}


def diff_against_previous(previous, scans):
    """Compare the just-completed scan against a previous report's
    states. Returns (new_open, newly_closed): lists of (target, port)
    tuples -- ports that just opened, and ports that used to be open
    but aren't anymore."""
    new_open = []
    newly_closed = []
    for scan in scans:
        for port, result in zip(scan["ports"], scan["results"]):
            key = (scan["target"], port)
            old_state = previous.get(key)
            if result.state == "open" and old_state != "open":
                new_open.append(key)
            elif result.state != "open" and old_state == "open":
                newly_closed.append(key)
    return new_open, newly_closed


def main():
    args = parse_args()

    if not (1 <= args.workers <= 100):
        print("\n[-] Error: workers must be between 1 and 100.")
        sys.exit(1)

    if args.probe and not args.banners:
        args.banners = True
        print("[*] --probe implies --banners -- turning banner/TLS reads on.")

    if args.gentle:
        args.workers = min(args.workers, 3)
        args.timeout = max(args.timeout, 2.0)

    previous_report = None
    if args.diff:
        try:
            previous_report = load_previous_report(args.diff)
        except ValueError as e:
            print(f"\n[-] Error: {e}")
            sys.exit(1)

    print("=" * 45)
    print("           NETWORK PORT SCANNER v1.7         ")
    print("=" * 45)

    try:
        targets = resolve_targets(args)
    except (ValueError, OSError) as e:
        print(f"\n[-] Error: {e}")
        sys.exit(1)

    try:
        ports = resolve_ports(args)
    except ValueError as e:
        print(f"\n[-] Error: {e}")
        sys.exit(1)

    resolved = []
    for t in targets:
        try:
            resolved.append((t, socket.gethostbyname(t)))
        except socket.gaierror:
            print(f"[-] Skipping {t}: invalid hostname or DNS resolution failure.")

    if not resolved:
        print("\n[-] Error: no target could be resolved.")
        sys.exit(1)

    run_id = uuid.uuid4().hex[:8]
    print(f"\n[*] Run {run_id} at {datetime.now(timezone.utc):%Y-%m-%d %H:%M:%S} UTC")
    if len(resolved) == 1:
        target, target_ip = resolved[0]
        print(f"[*] Target: {target} ({target_ip})")
    else:
        print(f"[*] Targets ({len(resolved)}):")
        for target, target_ip in resolved:
            print(f"    - {target} ({target_ip})")

    extras = []
    if args.adaptive_timeout:
        extras.append("adaptive-timeout=on")
    if args.banners:
        extras.append("banners=on" + ("+probe" if args.probe else ""))
    if args.shuffle:
        extras.append("shuffle=on")
    print(f"[*] {len(ports)} ports | workers={args.workers} | timeout={args.timeout}s"
          + (f" | {' | '.join(extras)}" if extras else ""))

    # Explicit authorization check before any packet is sent.
    if not args.yes:
        who = "this target" if len(resolved) == 1 else f"these {len(resolved)} targets"
        answer = input(f"[?] Do you have permission to scan {who}? [y/N] ")
        if answer.strip().lower() != "y":
            print("[-] Cancelled.")
            sys.exit(0)

    print("-" * 45)

    grand_counts = {"open": 0, "closed": 0, "no_response": 0}
    scans = []
    start_time = datetime.now()

    for target, target_ip in resolved:
        if len(resolved) > 1:
            print(f"\n[*] Scanning {target} ({target_ip})")

        scan_ports = list(ports)
        if args.shuffle:
            random.shuffle(scan_ports)

        adaptive = AdaptiveTimeout(args.timeout) if args.adaptive_timeout else None

        def _scan_one(p, _ip=target_ip, _host=target, _adaptive=adaptive):
            current_timeout = _adaptive.get() if _adaptive else args.timeout
            result = scan_port(_ip, p, current_timeout, args.banners, args.probe, _host)
            # Only open-port RTTs feed the average (see AdaptiveTimeout docstring).
            if _adaptive and result.state == "open":
                _adaptive.update(result.rtt_ms)
            return result

        with ThreadPoolExecutor(max_workers=args.workers) as pool:
            raw_results = list(pool.map(_scan_one, scan_ports))

        # Report in ascending port order regardless of scan order, so
        # --shuffle changes the wire pattern but not the readability
        # of the output or the saved report.
        ordered = sorted(zip(scan_ports, raw_results), key=lambda pair: pair[0])
        ordered_ports = [p for p, _ in ordered]
        ordered_results = [r for _, r in ordered]

        for port, result in ordered:
            grand_counts[result.state] += 1
            if result.state == "open":
                line = (f"[+] Port {port:<5}/TCP : OPEN ({get_service_name(port)}) "
                        f"- {result.rtt_ms:.2f}ms")
                if result.tls_info:
                    line += f" [{result.tls_info}]"
                if result.banner:
                    line += f" | {result.banner}"
                print(line)
                if result.advisory:
                    print(f"    [!] {result.advisory}")

        if adaptive:
            summary = adaptive.summary()
            if summary:
                avg_rtt, final_timeout = summary
                print(f"    [*] Adaptive timeout settled at {final_timeout:.2f}s "
                      f"(avg open-port RTT {avg_rtt:.1f}ms)")

        scans.append({"target": target, "ip": target_ip,
                       "ports": ordered_ports, "results": ordered_results})

    duration = (datetime.now() - start_time).total_seconds()
    print("-" * 45)
    print(f"[*] Scan completed in {duration:.2f}s! "
          f"{grand_counts['open']} open, {grand_counts['closed']} closed, "
          f"{grand_counts['no_response']} no response.")

    diff_result = None
    if previous_report is not None:
        diff_result = diff_against_previous(previous_report, scans)
        new_open, newly_closed = diff_result
        print("-" * 45)
        if new_open:
            print(f"[!] {len(new_open)} NEW open port(s) since {args.diff}:")
            for target, port in new_open:
                print(f"    + {target}:{port}")
        if newly_closed:
            print(f"[*] {len(newly_closed)} port(s) closed since {args.diff}:")
            for target, port in newly_closed:
                print(f"    - {target}:{port}")
        if not new_open and not newly_closed:
            print(f"[*] No changes since {args.diff}.")

    if args.output:
        save_results(args.output, args.csv, run_id, scans)
        fmt = "CSV" if args.csv else "JSON"
        print(f"[*] Results saved to {args.output} ({fmt})")

    if args.md:
        save_markdown_report(args.md, run_id, scans, duration, diff_result)
        print(f"[*] Markdown report saved to {args.md}")


if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        print("\n[-] Scan interrupted by user.")
        sys.exit(0)