"""Lossless JSON output, escaped CSV/Markdown and exclusive file publication."""
import csv
import html
import json
import math
import os
import re
import socket
import tempfile
import unicodedata
from datetime import datetime, timezone

from .config import (MAX_REPORT_RUN_ID_LEN, MAX_SCAN_COMBINATIONS)
from .baseline import _checked_text, _validate_report_record

def get_service_name(port):
    """Returns the standard service name for a port (e.g., 80 -> HTTP)."""
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"

def _iter_scan_records(run_id, scans):
    _checked_text(run_id, "run_id", MAX_REPORT_RUN_ID_LEN)
    count = 0
    for scan in scans:
        if len(scan["ports"]) != len(scan["results"]):
            raise ValueError("scan ports/results length mismatch")
        for port, result in zip(scan["ports"], scan["results"]):
            count += 1
            if count > MAX_SCAN_COMBINATIONS:
                raise ValueError("scan result count exceeds safety limit")
            record = {
                "run_id": run_id, "target": scan["target"], "ip": scan["ip"],
                "port": port, "state": result.state,
                "service": get_service_name(port), "rtt_ms": result.rtt_ms,
                "tls_info": result.tls_info, "banner": result.banner,
                "advisory": result.advisory,
            }
            _validate_report_record(record, count)
            yield record

def build_records(run_id, scans):
    """Preserve the legacy flat JSON/CSV contract, with field validation."""
    return list(_iter_scan_records(run_id, scans))

def _safe_display_text(value):
    """Render unsafe Unicode controls literally; never execute ANSI escapes."""
    chars = []
    named_controls = {"\t": r"\t", "\r": r"\r", "\n": r"\n"}
    for char in value:
        if char in named_controls:
            chars.append(named_controls[char])
            continue
        number = ord(char)
        category = unicodedata.category(char)
        if category.startswith("C") or category in {"Zl", "Zp"}:
            chars.append(f"\\x{number:02x}" if number <= 255 else f"\\u{number:04x}")
        else:
            chars.append(char)
    return "".join(chars)

def _csv_text(value):
    """Neutralize spreadsheet formulas after control-character encoding."""
    text = _safe_display_text(value)
    if text.lstrip().startswith(("=", "+", "-", "@")):
        return "'" + text
    return text

def _markdown_text(value):
    """Escape HTML and Markdown syntax; caller must not wrap in code spans."""
    safe = html.escape(_safe_display_text(value), quote=True)
    return re.sub(r"([\\`*_{}\[\]()#+.!|>~-])", r"\\\1", safe)

def _normalized_path(path):
    return os.path.normcase(os.path.realpath(os.path.abspath(os.fspath(path))))

def validate_report_paths(output=None, markdown=None, baseline=None, targets_file=None):
    """Fail before DNS if a destination collides or already exists."""
    protected = {_normalized_path(p) for p in (baseline, targets_file) if p is not None}
    destinations = set()
    for label, path in (("--output", output), ("--md", markdown)):
        if path is None:
            continue
        if not isinstance(path, (str, os.PathLike)) or not os.fspath(path):
            raise ValueError(f"{label}: output path is empty or invalid")
        normalized = _normalized_path(path)
        parent = os.path.dirname(normalized)
        if not os.path.isdir(parent):
            raise ValueError(f"{label}: output directory does not exist")
        if normalized in protected or normalized in destinations:
            raise ValueError(f"{label}: output path collides with an input or another output")
        if os.path.lexists(path):
            raise ValueError(f"{label}: output path already exists (refusing overwrite)")
        destinations.add(normalized)

def _write_report_exclusive(path, write_contents):
    """Write to a same-directory temp file, then atomically hardlink in place.

    A hardlink fails when the destination already exists (unlike os.replace).
    This deliberately fails closed on filesystems without hardlink support.
    """
    path = os.fspath(path)
    directory = os.path.dirname(os.path.abspath(path))
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", newline="",
                                         prefix=".core-scanner-", suffix=".tmp",
                                         dir=directory, delete=False) as output:
            temporary = output.name
            write_contents(output)
            output.flush()
            os.fsync(output.fileno())
        os.link(temporary, path)
    finally:
        if temporary is not None:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass

def save_results(path, as_csv, run_id, scans):
    """Write validated JSON (lossless) or safe-for-display CSV, without overwrite."""
    records = build_records(run_id, scans)

    def write_contents(stream):
        if as_csv:
            writer = csv.writer(stream)
            keys = ("run_id", "target", "ip", "port", "state", "service",
                    "rtt_ms", "tls_info", "banner", "advisory")
            writer.writerow(keys)
            for record in records:
                row = []
                for key in keys:
                    value = record[key]
                    if key == "rtt_ms":
                        row.append(f"{value:.2f}")
                    elif isinstance(value, str):
                        row.append(_csv_text(value))
                    else:
                        row.append(value if value is not None else "")
                writer.writerow(row)
        else:
            # JSON escapes controls per RFC 8259 and retains the original
            # field data for forensic use. Display layers must still escape it.
            json.dump({"run_id": run_id, "results": records}, stream,
                      ensure_ascii=True, allow_nan=False, indent=2)

    _write_report_exclusive(path, write_contents)

def _diff_fields(diff_result):
    new_open, newly_closed = diff_result  # legacy two-list compatibility
    return (new_open, newly_closed,
            getattr(diff_result, "inconclusive", []),
            getattr(diff_result, "newly_observed", []))

def save_markdown_report(path, run_id, scans, duration, diff_result=None):
    """Generate a safe presentation of validated scan observations."""
    records = build_records(run_id, scans)
    if not isinstance(duration, (int, float)) or not math.isfinite(duration) or duration < 0:
        raise ValueError("invalid scan duration")
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    lines = [
        f"# Port Scan Report ({_markdown_text(run_id)})",
        f"- **Generated:** {now_str}",
        f"- **Duration:** {duration:.2f}s",
        "", "## Open Ports",
        "| Target | IP | Port | Service | RTT (ms) | TLS | Banner |",
        "| :--- | :--- | :--- | :--- | ---: | :--- | :--- |",
    ]
    advisories = []
    any_open = False
    for record in records:
        if record["state"] != "open":
            continue
        any_open = True
        cell = lambda field: _markdown_text(record[field]) if record[field] is not None else "-"
        lines.append(
            f"| {cell('target')} | {cell('ip')} | **{record['port']}** | "
            f"{cell('service')} | {record['rtt_ms']:.2f} | "
            f"{cell('tls_info')} | {cell('banner')} |"
        )
        if record["advisory"]:
            advisories.append((record["target"], record["port"], record["advisory"]))
    if not any_open:
        lines.append("| *none* | - | - | - | - | - | - |")
    if advisories:
        lines += ["", "## Hardening Notes"]
        for target, port, note in advisories:
            lines.append(f"- **{_markdown_text(target)}:{port}** — {_markdown_text(note)}")
    if diff_result is not None:
        new_open, newly_closed, inconclusive, newly_observed = _diff_fields(diff_result)
        lines += ["", "## Changes Since Previous Report"]
        if not any((new_open, newly_closed, inconclusive, newly_observed)):
            lines.append("- No differences in comparable port observations.")
        for target, port in new_open:
            lines.append(f"- **[CONFIRMED OPEN]** {_markdown_text(target)}:{port} (closed → open)")
        for target, port in newly_closed:
            lines.append(f"- **[CONFIRMED CLOSED]** {_markdown_text(target)}:{port} (open → closed)")
        for target, port, old, current in inconclusive:
            lines.append(f"- **[INCONCLUSIVE]** {_markdown_text(target)}:{port} "
                         f"({_markdown_text(str(old))} → {_markdown_text(str(current))})")
        for target, port in newly_observed:
            lines.append(f"- **[FIRST OBSERVED OPEN]** {_markdown_text(target)}:{port} "
                         "(not in baseline; not necessarily newly opened)")

    def write_contents(stream):
        stream.write("\n".join(lines) + "\n")

    _write_report_exclusive(path, write_contents)
