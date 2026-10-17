#!/usr/bin/env python3
import argparse
import csv
import errno
import ipaddress
import json
import socket
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

# Safety cap for batch target files: a single CIDR block (e.g. a typo like
# "/8" instead of "/28") must never silently blow up into a scan of
# millions of hosts. Anything larger than this is rejected with a clear
# error instead of being expanded.
MAX_HOSTS_PER_CIDR = 1024

# Dedicated, short timeout for banner reads (passive or active). Kept
# independent of the connection --timeout (which --gentle extends): a
# banner, when a service sends one, arrives almost instantly, so waiting
# the full connection timeout for it would be wasteful.
BANNER_TIMEOUT = 0.75
BANNER_MAX_BYTES = 256
BANNER_MAX_LEN = 200

# Minimal, protocol-appropriate payloads used ONLY when --probe is passed
# and passive listening (the v1.5 default) got nothing back. Each one is
# just enough to make a normally-quiet service say something -- no
# exploitation, no third-party library, plain stdlib sockets.
ACTIVE_PROBE_PAYLOADS = {
    21: b"\r\n",                     # FTP: a nudge often re-sends the banner
    23: b"\r\n",                     # Telnet
    25: b"EHLO scanner\r\n",         # SMTP
    80: b"HEAD / HTTP/1.0\r\n\r\n",
    443: b"HEAD / HTTP/1.0\r\n\r\n",
    8000: b"HEAD / HTTP/1.0\r\n\r\n",
    8080: b"HEAD / HTTP/1.0\r\n\r\n",
    8443: b"HEAD / HTTP/1.0\r\n\r\n",
}
ACTIVE_PROBE_FALLBACK = b"\r\n"

# Adaptive timeout bounds: it can only ever shrink the operator's chosen
# --timeout down towards real observed latency, never exceed it, and
# never drop below this floor no matter how fast the network looks.
ADAPTIVE_TIMEOUT_FLOOR = 0.2
ADAPTIVE_TIMEOUT_MARGIN = 4.0   # new timeout = margin * observed avg RTT
ADAPTIVE_TIMEOUT_ALPHA = 0.3    # EMA smoothing factor

# state:   'open' / 'closed' (refused) / 'no_response' (timeout/error)
# rtt_ms:  round-trip time of the connection attempt itself, in ms
# banner:  short passive/active read of service data, or None
ScanResult = namedtuple("ScanResult", ["state", "rtt_ms", "banner"])


class AdaptiveTimeout:
    """Thread-safe exponential moving average of REAL observed RTTs
    (from ports that answered, open or closed -- never from timeouts,
    which carry no latency information). Used to shrink the per-port
    socket timeout mid-scan when --adaptive-timeout is enabled. The
    value only ever moves between ADAPTIVE_TIMEOUT_FLOOR and the
    operator's original --timeout -- it can make a scan faster, never
    slower than what was explicitly requested."""

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
    """Extract the hostname from a bare host, host:port or full URL."""
    target = user_input.strip()
    if "://" not in target:
        target = "//" + target
    try:
        return urlparse(target).hostname or ""
    except ValueError:
        return ""


def read_targets_file(path):
    """Read targets from a file: one per line. Supports bare hosts,
    host:port, full URLs (same as clean_target) and simple CIDR blocks
    (e.g. 192.168.1.0/30), which get expanded into individual IPs.
    '#' starts a comment (to end of line); blank lines are ignored.
    Duplicate targets are removed, order is preserved."""
    targets = []
    seen = set()

    with open(path, "r", encoding="utf-8") as f:
        lines = f.readlines()

    for raw_line in lines:
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue

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
            expanded = [str(ip) for ip in network]
        else:
            cleaned = clean_target(line)
            expanded = [cleaned] if cleaned else []

        for t in expanded:
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


def _read_banner(sock):
    """Best-effort PASSIVE read of a service banner on an already-open
    socket: never sends anything, just listens for BANNER_TIMEOUT.
    Returns None if nothing arrives -- many services (HTTP, databases,
    ...) never send anything unprompted, and that is a normal result."""
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
    Only ever called when passive listening got nothing AND the operator
    explicitly opted in with --probe (on top of --banners)."""
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


def scan_port(target_ip, port, timeout=TIMEOUT, grab_banner=False, active_probe=False):
    """Attempt to connect to one port. Always returns a ScanResult with
    the same honest 'open'/'closed'/'no_response' state as before, plus
    the connection's round-trip time in milliseconds. When grab_banner is
    True and the port is open, attempts one short PASSIVE read first;
    if that yields nothing and active_probe is also True, sends one
    small protocol-appropriate payload (ACTIVE_PROBE_PAYLOADS) and tries
    once more. Both are skipped entirely for closed/unresponsive ports."""
    banner = None
    start = time.perf_counter()
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
            client.settimeout(timeout)
            code = client.connect_ex((target_ip, port))
            rtt_ms = (time.perf_counter() - start) * 1000
            if code == 0:
                state = "open"
                if grab_banner:
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
    return ScanResult(state, round(rtt_ms, 2), banner)


def parse_args():
    """Read the command-line arguments."""
    p = argparse.ArgumentParser(description="Simple TCP port scanner")

    target_source = p.add_mutually_exclusive_group()
    target_source.add_argument("-t", "--target", help="IP or domain to scan")
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
    p.add_argument("--adaptive-timeout", action="store_true",
                   help="shrink the timeout towards the observed average RTT "
                        "as the scan progresses (never exceeds --timeout)")
    p.add_argument("-y", "--yes", action="store_true",
                   help="skip the permission confirmation prompt")
    p.add_argument("--banners", action="store_true",
                   help="passively read a short service banner on open ports")
    p.add_argument("--probe", "--active", action="store_true", dest="probe",
                   help="if a passive banner read gets nothing, send one small "
                        "protocol-appropriate payload to coax a reply (implies "
                        "--banners); more invasive than the default")
    p.add_argument("-o", "--output", help="save results to this path")
    p.add_argument("--csv", action="store_true",
                   help="save -o results as CSV instead of JSON")
    p.add_argument("--diff", help="compare against a previous JSON report "
                                   "(from -o) and flag new/closed ports")
    return p.parse_args()


def resolve_ports(args):
    """Decide which port list to scan, based on the mutually exclusive
    -p / --top-100 / --top-1000 flags (falls back to DEFAULT_PORTS)."""
    if args.top_1000:
        return TOP_1000_PORTS
    if args.top_100:
        return TOP_100_PORTS
    if args.ports:
        return parse_ports(args.ports)
    return DEFAULT_PORTS


def resolve_targets(args):
    """Decide which raw target strings to scan: from -i/--input-file,
    from -t/--target, or (if neither was given) the usual input() prompt."""
    if args.input_file:
        return read_targets_file(args.input_file)
    raw = args.target or input("[?] Enter the target IP or domain: ")
    return [raw]


def save_results(path, as_csv, run_id, scans):
    """Write the scan results to disk, in JSON (default) or CSV (--csv).
    `scans` is a list of {"target", "ip", "ports", "results"} dicts, one
    per target. Both formats are built from the SAME flat list of
    per-port records, so adding a target just appends more records --
    nothing about an earlier target is ever overwritten."""
    records = build_records(run_id, scans)

    if as_csv:
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["run_id", "target", "ip", "port", "state",
                              "service", "rtt_ms", "banner"])
            for r in records:
                writer.writerow([r["run_id"], r["target"], r["ip"], r["port"],
                                  r["state"], r["service"], f"{r['rtt_ms']:.2f}",
                                  r["banner"] or ""])
    else:
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"run_id": run_id, "results": records}, f, indent=2)


def build_records(run_id, scans):
    """Flatten `scans` into the per-port record list shared by both the
    JSON and CSV writers, and by the --diff comparison."""
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
                "banner": result.banner,
            })
    return records


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

    previous = {}
    for r in data["results"]:
        previous[(r["target"], r["port"])] = r["state"]
    return previous


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
                new_open.append((scan["target"], port))
            elif result.state != "open" and old_state == "open":
                newly_closed.append((scan["target"], port))
    return new_open, newly_closed


def main():
    args = parse_args()

    if not (1 <= args.workers <= 100):
        print("\n[-] Error: workers must be between 1 and 100.")
        sys.exit(1)

    if args.probe and not args.banners:
        args.banners = True
        print("[*] --probe implies --banners -- turning banner reads on.")

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
    print("           NETWORK PORT SCANNER v1.6         ")
    print("=" * 45)

    try:
        raw_targets = resolve_targets(args)
    except (ValueError, OSError) as e:
        print(f"\n[-] Error: {e}")
        sys.exit(1)

    targets = []
    for raw in raw_targets:
        cleaned = clean_target(raw)
        if cleaned:
            targets.append(cleaned)
    if not targets:
        print("\n[-] Error: No valid target provided.")
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

        adaptive = AdaptiveTimeout(args.timeout) if args.adaptive_timeout else None

        def _scan_one(p, _ip=target_ip, _adaptive=adaptive):
            current_timeout = _adaptive.get() if _adaptive else args.timeout
            result = scan_port(_ip, p, current_timeout, args.banners, args.probe)
            if _adaptive and result.state != "no_response":
                _adaptive.update(result.rtt_ms)
            return result

        with ThreadPoolExecutor(max_workers=args.workers) as pool:
            results = list(pool.map(_scan_one, ports))

        for port, result in zip(ports, results):
            grand_counts[result.state] += 1
            if result.state == "open":
                line = (f"[+] Port {port:<5}/TCP : OPEN ({get_service_name(port)}) "
                        f"- {result.rtt_ms:.2f}ms")
                if result.banner:
                    line += f" | {result.banner}"
                print(line)

        if adaptive:
            summary = adaptive.summary()
            if summary:
                avg_rtt, final_timeout = summary
                print(f"    [*] Adaptive timeout settled at {final_timeout:.2f}s "
                      f"(avg RTT {avg_rtt:.1f}ms)")

        scans.append({"target": target, "ip": target_ip, "ports": ports, "results": results})

    duration = (datetime.now() - start_time).total_seconds()
    print("-" * 45)
    print(f"[*] Scan completed in {duration:.2f}s! "
          f"{grand_counts['open']} open, {grand_counts['closed']} closed, "
          f"{grand_counts['no_response']} no response.")

    if previous_report is not None:
        new_open, newly_closed = diff_against_previous(previous_report, scans)
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


if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        print("\n[-] Scan interrupted by user.")
        sys.exit(0)