"""Public data contracts and cooperative cancellation exceptions."""
from collections import namedtuple
from dataclasses import dataclass

ScanResult = namedtuple("ScanResult", ["state", "rtt_ms", "banner", "tls_info", "advisory"])

@dataclass
class DiffResult:
    """Changes with certainty levels. Iteration preserves the old two-list API."""

    new_open: list
    newly_closed: list
    inconclusive: list
    newly_observed: list

    def __iter__(self):
        # Historical callers unpacked (new_open, newly_closed).
        yield self.new_open
        yield self.newly_closed

class ScanCancelled(Exception):
    """Scan interrupted; never publish partial scan data as a full report."""

class ScanExecutionError(Exception):
    """Unexpected worker failure; abort instead of publishing incomplete results."""

def _check_cancelled(cancel_event):
    if cancel_event is not None and cancel_event.is_set():
        raise ScanCancelled("scan cancelled")
