"""Strict reading of prior JSON baselines and conservative state comparisons."""
import ipaddress
import json
import math

from .config import (MAX_TARGET_ENTRY_LENGTH, MAX_REPORT_RUN_ID_LEN,
                     MAX_REPORT_FILE_BYTES, MAX_REPORT_JSON_DEPTH,
                     MAX_SCAN_COMBINATIONS, BANNER_MAX_LEN, REPORT_STATES)
from .models import DiffResult

def _checked_text(value, name, maximum, nullable=False):
    """Validate report fields without normalizing away evidence."""
    if nullable and value is None:
        return value
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise ValueError(f"invalid report field {name}: expected text up to {maximum} characters")
    return value

def _validate_report_record(record, index):
    """Validate old and current JSON records. Additional fields are rejected."""
    allowed = {"run_id", "target", "ip", "port", "state", "service",
               "rtt_ms", "tls_info", "banner", "advisory"}
    if not isinstance(record, dict):
        raise ValueError(f"report record {index}: expected an object")
    if set(record) - allowed:
        raise ValueError(f"report record {index}: unexpected field(s)")
    for field in ("target", "port", "state"):
        if field not in record:
            raise ValueError(f"report record {index}: missing field {field}")
    _checked_text(record["target"], "target", MAX_TARGET_ENTRY_LENGTH)
    port = record["port"]
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError(f"report record {index}: invalid port")
    if not isinstance(record["state"], str) or record["state"] not in REPORT_STATES:
        raise ValueError(f"report record {index}: invalid state")
    optional_text_limits = {
        "run_id": MAX_REPORT_RUN_ID_LEN, "ip": 128, "service": 128,
        "tls_info": 256, "banner": BANNER_MAX_LEN, "advisory": 1024,
    }
    for field, limit in optional_text_limits.items():
        if field in record:
            _checked_text(record[field], field, limit,
                          nullable=field in {"tls_info", "banner", "advisory"})
    if "ip" in record:
        try:
            ipaddress.ip_address(record["ip"])
        except ValueError as exc:
            raise ValueError(f"report record {index}: invalid IP address") from exc
    if "rtt_ms" in record:
        rtt = record["rtt_ms"]
        if (type(rtt) not in (int, float) or not math.isfinite(rtt)
                or rtt < 0):
            raise ValueError(f"report record {index}: invalid RTT")

def _json_nesting_is_valid(payload):
    """Check JSON nesting without recursively walking attacker-owned objects."""
    depth = 0
    inside_string = False
    escaped = False
    for byte in payload:
        if inside_string:
            if escaped:
                escaped = False
            elif byte == 92:  # backslash
                escaped = True
            elif byte == 34:  # double quote
                inside_string = False
        elif byte == 34:
            inside_string = True
        elif byte in (91, 123):  # [ {
            depth += 1
            if depth > MAX_REPORT_JSON_DEPTH:
                return False
        elif byte in (93, 125):
            depth -= 1
            if depth < 0:
                return False
    return depth == 0 and not inside_string

def _unique_keys(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError("JSON contains duplicate object keys")
        obj[key] = value
    return obj

def _invalid_json_constant(_value):
    raise ValueError("JSON contains a non-finite numeric value")

def load_previous_report(path, *, max_file_bytes=None, max_records=None):
    """Read and validate a bounded JSON baseline before scanning.

    Old reports need only target, port and state for each record. Other
    fields, when present, must match the original v1.7 field types.
    """
    if max_file_bytes is None:
        max_file_bytes = MAX_REPORT_FILE_BYTES
    if max_records is None:
        max_records = MAX_SCAN_COMBINATIONS
    try:
        with open(path, "rb") as stream:
            payload = stream.read(max_file_bytes + 1)
    except OSError as exc:
        raise ValueError("could not read previous report") from exc
    if len(payload) > max_file_bytes:
        raise ValueError("previous report exceeds the allowed file size")
    if not _json_nesting_is_valid(payload):
        raise ValueError("previous report has invalid or excessive JSON nesting")
    try:
        data = json.loads(payload, object_pairs_hook=_unique_keys,
                          parse_constant=_invalid_json_constant)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise ValueError("previous report contains invalid JSON") from exc
    if not isinstance(data, dict) or "results" not in data:
        raise ValueError("previous report must contain a results array")
    if set(data) - {"run_id", "results"}:
        raise ValueError("previous report contains unexpected top-level fields")
    if "run_id" in data:
        _checked_text(data["run_id"], "run_id", MAX_REPORT_RUN_ID_LEN)
    entries = data["results"]
    if not isinstance(entries, list):
        raise ValueError("previous report results must be an array")
    if len(entries) > max_records:
        raise ValueError("previous report exceeds the allowed record count")
    previous = {}
    for index, entry in enumerate(entries, 1):
        _validate_report_record(entry, index)
        key = (entry["target"], entry["port"])
        if key in previous:
            raise ValueError(f"previous report has a duplicate target-port at record {index}")
        previous[key] = entry["state"]
    return previous

def diff_against_previous(previous, scans):
    """Report only confirmed transitions; retain two-list unpack compatibility.

    closed -> open and open -> closed are confirmed. Non-responses,
    errors and unknown observations are inconclusive. Baseline-absent
    open ports are first observations, not proof that the port just opened.
    """
    new_open = []
    newly_closed = []
    inconclusive = []
    newly_observed = []
    for scan in scans:
        for port, result in zip(scan["ports"], scan["results"]):
            key = (scan["target"], port)
            current = result.state
            if key not in previous:
                if current == "open":
                    newly_observed.append(key)
                continue
            old = previous[key]
            if old == current:
                continue
            if old == "closed" and current == "open":
                new_open.append(key)
            elif old == "open" and current == "closed":
                newly_closed.append(key)
            else:
                inconclusive.append((scan["target"], port, str(old), str(current)))
    return DiffResult(new_open, newly_closed, inconclusive, newly_observed)
