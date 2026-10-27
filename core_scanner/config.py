"""Immutable-by-convention scanner limits and network protocol constants."""

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
# Phase 1: caps apply to the entire request, not to individual input lines.
MAX_TARGETS = 1024
MAX_PORTS = 4096
MAX_SCAN_COMBINATIONS = 262144
MAX_TARGET_ENTRY_LENGTH = 2048
MAX_TARGET_FILE_BYTES = 1048576
MAX_TARGET_FILE_LINES = 8192
MIN_TIMEOUT = 0.2
MAX_TIMEOUT = 30.0

# Phase 2: cap imported reports and field sizes before parsing or writing.
MAX_REPORT_FILE_BYTES = 256 * 1024 * 1024
MAX_REPORT_JSON_DEPTH = 16
MAX_REPORT_RUN_ID_LEN = 128
REPORT_STATES = frozenset({"open", "closed", "no_response", "error", "unknown"})

# Dedicated, short timeout for banner reads (passive or active). Kept
# independent of the connection --timeout (which --gentle extends): a
# banner, when a service sends one, arrives almost instantly.
BANNER_TIMEOUT = 0.75
TLS_HANDSHAKE_TIMEOUT = 1.0
MAX_IN_FLIGHT_FACTOR = 2  # includes running and queued futures per target
COMPLETION_POLL_INTERVAL = 0.1  # allows prompt cooperative cancellation
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
