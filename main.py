#!/usr/bin/env python3
"""Compatibility façade and CLI orchestration for Core-Scanner v1.7.

Legacy functions are re-exported here. main() resolves these names at call
 time so mock.patch.object(main, ...) retains its Phase-3 semantics. In the
 two exceptional cases requiring a façade-local override (TLS_PORTS and JSON
 limits), forwarding wrappers explicitly pass those values to their modules.
"""
import json
import os
import random
import socket
import ssl
import sys
import threading
import time
import uuid
from datetime import datetime, timezone

from core_scanner.config import *  # compatibility: existing CLI constants
from core_scanner.models import (ScanResult, DiffResult, ScanCancelled,
                                 ScanExecutionError, _check_cancelled)
from core_scanner.network import (AdaptiveTimeout, _connection_state,
                                  _socket_error_code, _sni_for, _read_banner,
                                  _active_probe, _inspect_tls)
from core_scanner import network as _network
from core_scanner.targets import (_normalize_host, _parse_single_target,
                                  clean_target, expand_target_entry,
                                  read_targets_file, parse_ports,
                                  validate_timeout, validate_scan_scope,
                                  resolve_address)
from core_scanner.scheduler import scan_ports_bounded
from core_scanner.cli import parse_args, resolve_ports, resolve_targets
from core_scanner.baseline import (_checked_text, _validate_report_record,
                                   _json_nesting_is_valid, _unique_keys,
                                   _invalid_json_constant, diff_against_previous)
from core_scanner import baseline as _baseline
from core_scanner.reports import (get_service_name, _iter_scan_records,
                                  build_records, _safe_display_text, _csv_text,
                                  _markdown_text, _normalized_path,
                                  validate_report_paths, _write_report_exclusive,
                                  save_results, _diff_fields, save_markdown_report)


def scan_port(target_ip, port, timeout=TIMEOUT, grab_banner=False,
              active_probe=False, hostname=None, *, cancel_event=None):
    """Legacy API; forward the façade's TLS_PORTS override when mocked."""
    return _network.scan_port(
        target_ip, port, timeout, grab_banner, active_probe, hostname,
        cancel_event=cancel_event, tls_ports=TLS_PORTS
    )


def load_previous_report(path):
    """Legacy API; honor patched size/record limits on the public façade."""
    return _baseline.load_previous_report(
        path, max_file_bytes=MAX_REPORT_FILE_BYTES,
        max_records=MAX_SCAN_COMBINATIONS
    )

def main():
    args = parse_args()

    if not (1 <= args.workers <= 100):
        print("\n[-] Error: workers must be between 1 and 100.")
        sys.exit(1)

    try:
        args.timeout = validate_timeout(args.timeout)
    except ValueError as exc:
        print(f"\n[-] Error: {exc}")
        sys.exit(1)

    if args.probe and not args.banners:
        args.banners = True
        print("[*] --probe implies --banners -- turning banner/TLS reads on.")

    if args.gentle:
        args.workers = min(args.workers, 3)
        args.timeout = max(args.timeout, 2.0)

    # Output preflight must finish before DNS or TCP traffic begins.
    try:
        validate_report_paths(args.output, args.md, args.diff, args.input_file)
    except ValueError as exc:
        print(f"\n[-] Error: {exc}")
        sys.exit(1)

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

    # Phase 1: cap the complete scope and confirm authorization BEFORE DNS.
    try:
        combinations = validate_scan_scope(targets, ports)
    except ValueError as exc:
        print(f"\n[-] Error: {exc}")
        sys.exit(1)

    print(f"[*] Requested scope: {len(targets)} target(s), {len(ports)} port(s), "
          f"{combinations} connection attempt(s).")
    for target in targets[:10]:
        print(f"    - {target}")
    if len(targets) > 10:
        print(f"    ... and {len(targets) - 10} more targets")
    if not args.yes:
        answer = input(
            "[?] Do you have explicit permission to resolve and scan ALL "
            "listed targets? [y/N] "
        )
        if answer.strip().lower() != "y":
            print("[-] Cancelled before DNS resolution.")
            sys.exit(0)

    resolved = []
    for t in targets:
        try:
            resolved.append((t, resolve_address(t)))
        except socket.gaierror:
            print(f"[-] Skipping {t}: DNS resolution failure.")

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

    print("-" * 45)

    grand_counts = {"open": 0, "closed": 0, "no_response": 0, "error": 0}
    scans = []
    start_time = time.perf_counter()
    cancel_event = threading.Event()

    for target, target_ip in resolved:
        if len(resolved) > 1:
            print(f"\n[*] Scanning {target} ({target_ip})")

        scan_ports = list(ports)
        if args.shuffle:
            random.shuffle(scan_ports)
        adaptive = AdaptiveTimeout(args.timeout) if args.adaptive_timeout else None

        def _scan_one(p, _ip=target_ip, _host=target, _adaptive=adaptive):
            _check_cancelled(cancel_event)
            current_timeout = _adaptive.get() if _adaptive else args.timeout
            result = scan_port(_ip, p, current_timeout, args.banners, args.probe,
                               _host, cancel_event=cancel_event)
            if _adaptive and result.state == "open":
                _adaptive.update(result.rtt_ms)
            return result

        try:
            results_by_port = scan_ports_bounded(
                scan_ports, _scan_one, args.workers, cancel_event
            )
        except ScanCancelled:
            print("[-] Scan interrupted; partial results were not published.")
            sys.exit(130)
        except ScanExecutionError:
            print("[-] Error: a worker failed; incomplete scan results were discarded.")
            sys.exit(1)

        # --shuffle changes request order, not the ordering of saved results.
        ordered_ports = sorted(scan_ports)
        ordered_results = [results_by_port[port] for port in ordered_ports]
        for port, result in zip(ordered_ports, ordered_results):
            grand_counts[result.state] += 1
            if result.state == "open":
                line = (f"[+] Port {port:<5}/TCP : OPEN ({get_service_name(port)}) "
                        f"- {result.rtt_ms:.2f}ms")
                if result.tls_info:
                    line += f" [{result.tls_info}]"
                if result.banner:
                    line += f" | {_safe_display_text(result.banner)}"
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

    duration = time.perf_counter() - start_time
    print("-" * 45)
    print(f"[*] Scan completed in {duration:.2f}s! "
          f"{grand_counts['open']} open, {grand_counts['closed']} closed, "
          f"{grand_counts['no_response']} no response, "
          f"{grand_counts['error']} error.")

    diff_result = None
    if previous_report is not None:
        diff_result = diff_against_previous(previous_report, scans)
        print("-" * 45)
        for target, port in diff_result.new_open:
            print(f"[!] CONFIRMED OPEN: {target}:{port} (closed -> open)")
        for target, port in diff_result.newly_closed:
            print(f"[*] CONFIRMED CLOSED: {target}:{port} (open -> closed)")
        for target, port, old, current in diff_result.inconclusive:
            print(f"[?] INCONCLUSIVE: {target}:{port} ({old} -> {current})")
        for target, port in diff_result.newly_observed:
            print(f"[*] FIRST OBSERVED OPEN: {target}:{port} (absent from baseline)")
        if not any((diff_result.new_open, diff_result.newly_closed,
                    diff_result.inconclusive, diff_result.newly_observed)):
            print(f"[*] No differences in comparable observations since {args.diff}.")

    try:
        if args.output is not None:
            save_results(args.output, args.csv, run_id, scans)
            fmt = "CSV" if args.csv else "JSON"
            print(f"[*] Results saved to {_safe_display_text(args.output)} ({fmt})")
        if args.md is not None:
            save_markdown_report(args.md, run_id, scans, duration, diff_result)
            print(f"[*] Markdown report saved to {_safe_display_text(args.md)}")
    except FileExistsError:
        print("[-] Error saving report: output already exists (refusing overwrite).")
        sys.exit(1)
    except OSError:
        print("[-] Error saving report: filesystem operation failed; check permissions and filesystem support.")
        sys.exit(1)
    except ValueError as exc:
        print(f"[-] Error saving report: {exc}")
        sys.exit(1)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[-] Scan interrupted by user; incomplete results were not published.")
        sys.exit(130)
    except EOFError:
        print("\n[-] Input closed; scan cancelled.")
        sys.exit(0)