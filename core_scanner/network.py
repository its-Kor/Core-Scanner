"""TCP attempts, bounded TLS/banner inspection and adaptive latency estimates."""
import errno
import ipaddress
import socket
import ssl
import threading
import time

from .config import (TIMEOUT, BANNER_TIMEOUT, TLS_HANDSHAKE_TIMEOUT,
                     BANNER_MAX_BYTES, BANNER_MAX_LEN, TLS_PORTS,
                     ACTIVE_PROBE_PAYLOADS, ACTIVE_PROBE_FALLBACK,
                     PORT_SECURITY_NOTES, ADAPTIVE_TIMEOUT_FLOOR,
                     ADAPTIVE_TIMEOUT_MARGIN, ADAPTIVE_TIMEOUT_ALPHA)
from .models import ScanResult, ScanCancelled, _check_cancelled

# Both POSIX errno and explicit Windows WSA* codes are handled: errno values
# are not guaranteed to be mapped identically by Python on every platform.
_REFUSED_CODES = {errno.ECONNREFUSED, 10061}
_NO_RESPONSE_CODES = {
    errno.ETIMEDOUT, errno.ENETUNREACH, errno.EHOSTUNREACH,
    10060, 10051, 10065, 10050,
}
for _symbol in ("EHOSTDOWN", "ENETDOWN"):
    _code = getattr(errno, _symbol, None)
    if _code is not None:
        _NO_RESPONSE_CODES.add(_code)


def _connection_state(error_code):
    """Classify known connection outcomes, never infer closure from a timeout."""
    if error_code == 0:
        return "open"
    if error_code in _REFUSED_CODES:
        return "closed"
    if error_code in _NO_RESPONSE_CODES:
        return "no_response"
    return "error"

def _socket_error_code(exc):
    return getattr(exc, "winerror", None) or getattr(exc, "errno", None)

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
            self._timeout = min(self._ceiling, max(ADAPTIVE_TIMEOUT_FLOOR, candidate))

    def summary(self):
        with self._lock:
            if self._ema_rtt_ms is None:
                return None
            return self._ema_rtt_ms, self._timeout

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

def _read_banner(sock, cancel_event=None):
    """Read one bounded passive banner from a connected plaintext/TLS socket."""
    _check_cancelled(cancel_event)
    try:
        sock.settimeout(BANNER_TIMEOUT)
        data = sock.recv(BANNER_MAX_BYTES)
    except (OSError, TimeoutError):
        return None
    if not data:
        return None
    text = data.decode("utf-8", errors="replace").strip()
    return text.splitlines()[0][:BANNER_MAX_LEN] if text else None

def _active_probe(sock, port, cancel_event=None):
    """Perform at most one bounded protocol probe and one bounded read.

    The total I/O deadline is BANNER_TIMEOUT, shared between send and recv.
    The Python socket timeout applies to each operation; this deadline also
    prevents the send and recv timeouts from stacking.
    """
    _check_cancelled(cancel_event)
    deadline = time.monotonic() + BANNER_TIMEOUT
    payload = ACTIVE_PROBE_PAYLOADS.get(port, ACTIVE_PROBE_FALLBACK)
    try:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return None
        sock.settimeout(remaining)
        sock.sendall(payload)
        _check_cancelled(cancel_event)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return None
        sock.settimeout(remaining)
        data = sock.recv(BANNER_MAX_BYTES)
    except (OSError, TimeoutError):
        return None
    if not data:
        return None
    text = data.decode("utf-8", errors="replace").strip()
    return text.splitlines()[0][:BANNER_MAX_LEN] if text else None

def _inspect_tls(raw_sock, hostname, port, active_probe, cancel_event=None):
    """Inspect TLS on a TCP-open socket without changing the TCP state.

    TLS_HANDSHAKE_TIMEOUT caps the handshake independently of --timeout.
    Failure yields no TLS details, never a false TCP closed observation.
    """
    _check_cancelled(cancel_event)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with ctx.wrap_socket(raw_sock, server_hostname=_sni_for(hostname),
                             do_handshake_on_connect=False) as tls_sock:
            tls_sock.settimeout(TLS_HANDSHAKE_TIMEOUT)
            tls_sock.do_handshake()
            _check_cancelled(cancel_event)
            tls_ver = tls_sock.version() or "TLS"
            cipher = tls_sock.cipher()
            cipher_name = cipher[0] if cipher else "unknown-cipher"
            tls_info = f"{tls_ver}/{cipher_name}"
            banner = _read_banner(tls_sock, cancel_event)
            if banner is None and active_probe:
                banner = _active_probe(tls_sock, port, cancel_event)
            return tls_info, banner
    except (OSError, ssl.SSLError, TimeoutError):
        return None, None

def scan_port(target_ip, port, timeout=TIMEOUT, grab_banner=False,
              active_probe=False, hostname=None, *, cancel_event=None,
              tls_ports=None):
    """One bounded TCP attempt, plus optional bounded service inspection.

    RTT is the TCP connect duration only, and not TLS/banner time. Callers
    still receive the Phase 1/2 five-field ScanResult tuple.
    """
    _check_cancelled(cancel_event)
    if tls_ports is None:
        tls_ports = TLS_PORTS
    banner = tls_info = advisory = None
    start = time.perf_counter()
    try:
        try:
            family = (socket.AF_INET6 if ipaddress.ip_address(target_ip).version == 6
                      else socket.AF_INET)
        except ValueError:
            family = socket.AF_INET  # legacy direct scan_port(hostname)
        with socket.socket(family, socket.SOCK_STREAM) as client:
            client.settimeout(timeout)
            code = client.connect_ex((target_ip, port))
            rtt_ms = (time.perf_counter() - start) * 1000
            _check_cancelled(cancel_event)
            state = _connection_state(code)
            if state == "open":
                advisory = PORT_SECURITY_NOTES.get(port)
                if grab_banner:
                    if port in tls_ports:
                        tls_info, banner = _inspect_tls(
                            client, hostname or target_ip, port, active_probe, cancel_event
                        )
                    else:
                        banner = _read_banner(client, cancel_event)
                        if banner is None and active_probe:
                            banner = _active_probe(client, port, cancel_event)
                _check_cancelled(cancel_event)
    except (OSError, TimeoutError) as exc:
        rtt_ms = (time.perf_counter() - start) * 1000
        if isinstance(exc, (socket.timeout, TimeoutError)):
            state = "no_response"
        else:
            state = _connection_state(_socket_error_code(exc))
    return ScanResult(state, round(rtt_ms, 2), banner, tls_info, advisory)
