"""Strict, bounded target/port parsing and authorized-after-consent DNS lookup."""
import ipaddress
import math
import os
import re
import socket
import warnings
from urllib.parse import urlsplit

from .config import (MAX_TARGET_ENTRY_LENGTH, MAX_HOSTS_PER_CIDR, MAX_TARGETS,
                     MAX_TARGET_FILE_BYTES, MAX_TARGET_FILE_LINES, MAX_PORTS,
                     MAX_SCAN_COMBINATIONS, MIN_TIMEOUT, MAX_TIMEOUT)

_HOST_LABEL_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
_PORT_PART_RE = re.compile(r"([0-9]+)(?:\s*-\s*([0-9]+))?\Z")



def _normalize_host(host):
    """Return a canonical IP/IDNA hostname; never reinterpret malformed IPs."""
    if not host or "%" in host:
        raise ValueError("missing host or unsupported IPv6 zone identifier")
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        pass
    if ":" in host:
        raise ValueError("invalid IPv6 address")
    if re.fullmatch(r"[0-9.]+", host):
        raise ValueError("invalid or abbreviated IPv4 address")
    try:
        ascii_host = host.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValueError("invalid hostname (IDNA encoding failed)") from exc
    if ascii_host.endswith("."):
        ascii_host = ascii_host[:-1]
    if len(ascii_host) > 253 or not ascii_host or any(
        not _HOST_LABEL_RE.fullmatch(label) for label in ascii_host.split(".")
    ):
        raise ValueError("invalid hostname (expected valid DNS labels)")
    return ascii_host

def _parse_single_target(raw):
    """Return (host, embedded_port); any port is advisory, never a scan override."""
    if any(ord(char) < 32 or ord(char) == 127 for char in raw):
        raise ValueError("target contains control characters")
    if any(char.isspace() for char in raw):
        raise ValueError("target contains whitespace")
    if len(raw) > MAX_TARGET_ENTRY_LENGTH:
        raise ValueError(f"target exceeds {MAX_TARGET_ENTRY_LENGTH} characters")

    if "%" in raw:
        raise ValueError("IPv6 zone identifiers are not supported")
    try:
        return str(ipaddress.ip_address(raw)), None
    except ValueError:
        pass

    if "://" in raw:
        # Explicit network URLs have a required authority and scheme.
        parsed = urlsplit(raw)
        if not re.fullmatch(r"[a-zA-Z][a-zA-Z0-9+.-]*", parsed.scheme):
            raise ValueError("invalid URL scheme")
    else:
        if "/" in raw or "?" in raw or "#" in raw:
            raise ValueError("a host with a path/query needs an explicit URL scheme")
        if raw.count(":") >= 2 and not raw.startswith("["):
            raise ValueError("invalid IPv6 address")
        parsed = urlsplit("//" + raw)
        if parsed.path or parsed.query or parsed.fragment:
            raise ValueError("invalid host or host:port target")

    if not parsed.netloc or parsed.username is not None or parsed.password is not None:
        raise ValueError("URL requires a host and must not contain credentials")
    try:
        host = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise ValueError(f"invalid target host or port: {exc}") from exc
    if host is None:
        raise ValueError("target is missing a hostname")
    if port is not None and not 1 <= port <= 65535:
        raise ValueError("embedded port must be between 1 and 65535")
    # urlsplit accepts a trailing colon without a numeric port; reject it.
    authority = parsed.netloc.rsplit("@", 1)[-1]
    if authority.endswith(":"):
        raise ValueError("empty embedded port")
    return _normalize_host(host), port

def clean_target(user_input):
    """Validate and extract the host from a host, host:port, IP or URL.

    An explicit URL may contain a path; a bare host may not. Returns an
    empty string for invalid input to preserve the original helper API.
    """
    try:
        host, _ = _parse_single_target(user_input.strip())
        return host
    except ValueError:
        return ""

def expand_target_entry(entry):
    """Expand one validated IP/CIDR/hostname/URL; preserve IPv6 literally."""
    if not isinstance(entry, str):
        raise ValueError("target entry must be text")
    line = entry.strip()
    if not line or line.startswith("#"):
        return []
    # Inline comments require whitespace. URL fragments aren't comments.
    line = re.split(r"\s+#", line, maxsplit=1)[0].strip()
    if not line:
        return []
    if len(line) > MAX_TARGET_ENTRY_LENGTH:
        raise ValueError(f"target exceeds {MAX_TARGET_ENTRY_LENGTH} characters")

    if "/" in line and "://" not in line:
        try:
            network = ipaddress.ip_network(line, strict=False)
        except ValueError as exc:
            raise ValueError(f"invalid CIDR or missing URL scheme: {line!r}") from exc
        if network.num_addresses > MAX_HOSTS_PER_CIDR:
            raise ValueError(
                f"{line!r} expands to {network.num_addresses} addresses; "
                f"limit is {MAX_HOSTS_PER_CIDR}"
            )
        return [str(ip) for ip in network]

    host, explicit_port = _parse_single_target(line)
    if explicit_port is not None:
        warnings.warn(
            f"target port {explicit_port} is not a scan selection; "
            "use --ports to select scanned ports",
            UserWarning,
            stacklevel=2,
        )
    return [host]

def read_targets_file(path):
    """Read a bounded UTF-8 target list; de-duplicate without changing order."""
    targets = []
    seen = set()
    with open(path, "r", encoding="utf-8") as f:
        if os.fstat(f.fileno()).st_size > MAX_TARGET_FILE_BYTES:
            raise ValueError(f"target file exceeds {MAX_TARGET_FILE_BYTES} bytes")
        for line_number in range(1, MAX_TARGET_FILE_LINES + 2):
            raw_line = f.readline(MAX_TARGET_ENTRY_LENGTH + 3)
            if not raw_line:
                break
            if line_number > MAX_TARGET_FILE_LINES:
                raise ValueError(f"target file exceeds {MAX_TARGET_FILE_LINES} lines")
            if len(raw_line.rstrip("\r\n")) > MAX_TARGET_ENTRY_LENGTH:
                raise ValueError(f"target file line {line_number} is too long")
            try:
                expanded = expand_target_entry(raw_line)
            except ValueError as exc:
                raise ValueError(f"target file line {line_number}: {exc}") from exc
            for host in expanded:
                if host not in seen:
                    if len(targets) >= MAX_TARGETS:
                        raise ValueError(f"too many unique targets (limit {MAX_TARGETS})")
                    seen.add(host)
                    targets.append(host)
    if not targets:
        raise ValueError(f"no valid targets found in {path}")
    return targets

def parse_ports(spec):
    """Parse validated, bounded TCP port ranges into sorted unique ports."""
    if not isinstance(spec, str) or len(spec) > 16384:
        raise ValueError("invalid or excessively long port specification")
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue  # preserves historical trailing/empty comma behavior
        match = _PORT_PART_RE.fullmatch(part)
        if not match or len(match.group(1)) > 5 or (
            match.group(2) and len(match.group(2)) > 5
        ):
            raise ValueError(f"invalid port or range: {part!r}")
        lo = int(match.group(1))
        hi = int(match.group(2)) if match.group(2) is not None else lo
        if not (1 <= lo <= hi <= 65535):
            raise ValueError(f"invalid port range {part!r}: expected 1 <= start <= end <= 65535")
        if hi - lo + 1 > MAX_PORTS:
            raise ValueError(f"port range exceeds the limit of {MAX_PORTS} ports")
        ports.update(range(lo, hi + 1))
        if len(ports) > MAX_PORTS:
            raise ValueError(f"too many distinct ports (limit {MAX_PORTS})")
    if not ports:
        raise ValueError("no valid ports provided")
    return sorted(ports)

def validate_timeout(timeout):
    """Reject nonfinite and out-of-range timeouts before any network activity."""
    if not isinstance(timeout, (int, float)) or not math.isfinite(timeout):
        raise ValueError("timeout must be a finite number")
    if not MIN_TIMEOUT <= timeout <= MAX_TIMEOUT:
        raise ValueError(f"timeout must be between {MIN_TIMEOUT} and {MAX_TIMEOUT} seconds")
    return float(timeout)

def validate_scan_scope(targets, ports):
    """Enforce per-run caps; call before DNS lookup or TCP connections."""
    if not targets or len(targets) > MAX_TARGETS:
        raise ValueError(f"target count must be between 1 and {MAX_TARGETS}")
    if not ports or len(ports) > MAX_PORTS:
        raise ValueError(f"port count must be between 1 and {MAX_PORTS}")
    total = len(targets) * len(ports)
    if total > MAX_SCAN_COMBINATIONS:
        raise ValueError(
            f"scan requires {total} target-port combinations; "
            f"limit is {MAX_SCAN_COMBINATIONS}"
        )
    return total

def resolve_address(target):
    """Resolve after authorization. Prefer IPv4 for existing hostname behavior."""
    try:
        return str(ipaddress.ip_address(target))
    except ValueError:
        pass
    infos = socket.getaddrinfo(target, None, type=socket.SOCK_STREAM)
    for family in (socket.AF_INET, socket.AF_INET6):
        for addr_family, _, _, _, sockaddr in infos:
            if addr_family == family:
                return sockaddr[0]
    raise socket.gaierror(f"no TCP IPv4/IPv6 address for {target}")
