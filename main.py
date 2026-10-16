#!/usr/bin/env python3
import argparse
import csv
import errno
import json
import socket
import sys
import uuid
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


def scan_port(target_ip, port, timeout=TIMEOUT):
    """Return 'open', 'closed' (refused) or 'no_response' (timeout/error)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
            client.settimeout(timeout)
            code = client.connect_ex((target_ip, port))
    except socket.error:
        return "no_response"
    if code == 0:
        return "open"
    if code == errno.ECONNREFUSED:
        return "closed"
    return "no_response"


def parse_args():
    """Read the command-line arguments."""
    p = argparse.ArgumentParser(description="Simple TCP port scanner")
    p.add_argument("-t", "--target", help="IP or domain to scan")

    # Only one port source may be chosen at a time -- argparse enforces
    # this and prints a friendly error if two are combined by mistake.
    port_source = p.add_mutually_exclusive_group()
    port_source.add_argument("-p", "--ports", help="e.g. 22,80,443 or 1-1024")
    port_source.add_argument("--top-100", action="store_true",
                              help="scan the 100 most common ports")
    port_source.add_argument("--top-1000", action="store_true",
                              help="scan ports 1-1000")

    p.add_argument("--timeout", type=float, default=TIMEOUT,
                   help="socket timeout in seconds")
    p.add_argument("-w", "--workers", type=int, default=20,
                   help="concurrent workers (1-100)")
    p.add_argument("--gentle", action="store_true",
                   help="fewer workers, longer timeout (less noisy on the network)")
    p.add_argument("-y", "--yes", action="store_true",
                   help="skip the permission confirmation prompt")
    p.add_argument("-o", "--output", help="save results to this path")
    p.add_argument("--csv", action="store_true",
                   help="save -o results as CSV instead of JSON")
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


def save_results(path, as_csv, run_id, target, target_ip, ports, states):
    """Write the scan results to disk, in JSON (default) or CSV (--csv)."""
    if as_csv:
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["run_id", "target", "ip", "port", "state", "service"])
            for port, state in zip(ports, states):
                writer.writerow([run_id, target, target_ip, port, state,
                                  get_service_name(port)])
    else:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(
                {
                    "run_id": run_id,
                    "target": target,
                    "ip": target_ip,
                    "results": dict(zip(ports, states)),
                },
                f,
                indent=2,
            )


def main():
    args = parse_args()

    if not (1 <= args.workers <= 100):
        print("\n[-] Error: workers must be between 1 and 100.")
        sys.exit(1)

    if args.gentle:
        args.workers = min(args.workers, 3)
        args.timeout = max(args.timeout, 2.0)

    print("=" * 45)
    print("           NETWORK PORT SCANNER v1.3         ")
    print("=" * 45)

    raw_target = args.target or input("[?] Enter the target IP or domain: ")
    target = clean_target(raw_target)

    if not target:
        print("\n[-] Error: No target provided.")
        sys.exit(1)

    try:
        ports = resolve_ports(args)
    except ValueError as e:
        print(f"\n[-] Error: {e}")
        sys.exit(1)

    try:
        target_ip = socket.gethostbyname(target)
    except socket.gaierror:
        print("\n[-] Error: Invalid hostname or DNS resolution failure.")
        sys.exit(1)

    run_id = uuid.uuid4().hex[:8]
    print(f"\n[*] Run {run_id} at {datetime.now(timezone.utc):%Y-%m-%d %H:%M:%S} UTC")
    print(f"[*] Target: {target} ({target_ip})")
    print(f"[*] {len(ports)} ports | workers={args.workers} | timeout={args.timeout}s")

    # Explicit authorization check before any packet is sent.
    if not args.yes:
        answer = input("[?] Do you have permission to scan this target? [y/N] ")
        if answer.strip().lower() != "y":
            print("[-] Cancelled.")
            sys.exit(0)

    print("-" * 45)

    counts = {"open": 0, "closed": 0, "no_response": 0}
    start_time = datetime.now()

    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        states = list(pool.map(lambda p: scan_port(target_ip, p, args.timeout), ports))

    for port, state in zip(ports, states):
        counts[state] += 1
        if state == "open":
            print(f"[+] Port {port:<5}/TCP : OPEN ({get_service_name(port)})")

    duration = (datetime.now() - start_time).total_seconds()
    print("-" * 45)
    print(f"[*] Scan completed in {duration:.2f}s! "
          f"{counts['open']} open, {counts['closed']} closed, "
          f"{counts['no_response']} no response.")

    if args.output:
        save_results(args.output, args.csv, run_id, target, target_ip, ports, states)
        fmt = "CSV" if args.csv else "JSON"
        print(f"[*] Results saved to {args.output} ({fmt})")


if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        print("\n[-] Scan interrupted by user.")
        sys.exit(0)