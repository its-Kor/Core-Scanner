#!/usr/bin/env python3
import argparse
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
    p.add_argument("-p", "--ports", help="e.g. 22,80,443 or 1-1024")
    p.add_argument("--timeout", type=float, default=TIMEOUT,
                   help="socket timeout in seconds")
    p.add_argument("-w", "--workers", type=int, default=20,
                   help="concurrent workers (1-100)")
    p.add_argument("--gentle", action="store_true",
                   help="fewer workers, longer timeout (less noisy on the network)")
    p.add_argument("-y", "--yes", action="store_true",
                   help="skip the permission confirmation prompt")
    p.add_argument("-o", "--output", help="save results as JSON to this path")
    return p.parse_args()


def main():
    args = parse_args()

    if not (1 <= args.workers <= 100):
        print("\n[-] Error: workers must be between 1 and 100.")
        sys.exit(1)

    if args.gentle:
        args.workers = min(args.workers, 3)
        args.timeout = max(args.timeout, 2.0)

    print("=" * 45)
    print("           NETWORK PORT SCANNER v1.2         ")
    print("=" * 45)

    raw_target = args.target or input("[?] Enter the target IP or domain: ")
    target = clean_target(raw_target)

    if not target:
        print("\n[-] Error: No target provided.")
        sys.exit(1)

    try:
        ports = parse_ports(args.ports) if args.ports else DEFAULT_PORTS
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
        with open(args.output, "w", encoding="utf-8") as f:
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
        print(f"[*] Results saved to {args.output}")


if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        print("\n[-] Scan interrupted by user.")
        sys.exit(0)