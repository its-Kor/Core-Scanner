"""CLI argument definitions and target/port source selection only.

Orchestration deliberately remains in main.py to preserve legacy monkeypatch
points on main.main() without circular imports or module-global forwarding.
"""
import argparse
from .config import DEFAULT_PORTS, TOP_100_PORTS, TOP_1000_PORTS, TIMEOUT
from .targets import parse_ports, read_targets_file, expand_target_entry

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
