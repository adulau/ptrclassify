from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import re


_DNS_LINE = re.compile(
    r"^\s*(?P<owner>\S+)\s+(?:(?P<ttl>\d+)\s+)?(?:(?P<class>IN)\s+)?(?P<rtype>PTR|CNAME)\s+(?P<target>\S+)\s*$",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class PTRRecord:
    raw: str
    hostname: str | None
    address: str | None = None
    owner: str | None = None
    record_type: str = "PTR"


def _ipv4_from_inaddr(owner: str) -> str | None:
    suffix = ".in-addr.arpa."
    lower = owner.lower()
    if not lower.endswith(suffix):
        return None
    body = owner[: -len(suffix)]
    parts = body.split(".")
    if len(parts) != 4 or not all(p.isdigit() for p in parts):
        return None
    candidate = ".".join(reversed(parts))
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        return None


def parse_ptr_record(value: str) -> PTRRecord:
    """Parse either a full DNS PTR/CNAME line or a bare PTR hostname."""
    raw = value.strip()
    match = _DNS_LINE.match(raw)
    if match:
        target = match.group("target").rstrip(".").lower()
        owner = match.group("owner")
        return PTRRecord(
            raw=raw,
            hostname=target,
            address=_ipv4_from_inaddr(owner),
            owner=owner,
            record_type=match.group("rtype").upper(),
        )

    # Bare FQDN / hostname input.
    hostname = raw.rstrip(".").lower() if raw else None
    return PTRRecord(raw=raw, hostname=hostname, record_type="PTR")
