import ipaddress
import re
import socket

# Matches an IPv4-like address where each octet is either a number or one or more x's
# e.g. 192.168.1.x  192.168.x.x  10.xxx.x.x
_IP_WILD_RE = re.compile(
    r"^(\d{1,3}|x+)\.(\d{1,3}|x+)\.(\d{1,3}|x+)\.(\d{1,3}|x+)$",
    re.IGNORECASE,
)


def expand_targets(destination: str) -> list[str]:
    """
    Expand a destination string into a deduplicated list of IP address strings.

    Accepts comma-separated destinations. Each piece may be:
      - Single IP:     192.168.1.5  or  ::1
      - CIDR range:    192.168.1.0/24  or  fe80::/10
      - Wildcard:      192.168.1.x  (x octets must be trailing, IPv4 only)
      - Hostname:      localhost, google.com
    """
    seen: dict[str, None] = {}  # ordered-set pattern
    for part in destination.split(","):
        part = part.strip()
        if not part:
            continue
        for ip in _expand_one(part):
            seen.setdefault(ip, None)
    return list(seen)


def _expand_one(destination: str) -> list[str]:
    # IPv4 wildcard detection (only for dotted-quad style addresses)
    m = _IP_WILD_RE.match(destination)
    if m:
        octets = list(m.groups())
        if any(_is_wild(o) for o in octets):
            cidr = _wildcard_to_cidr(octets)
            network = ipaddress.ip_network(cidr, strict=False)
            return [str(ip) for ip in network]
        # All numeric — fall through

    # Single IP address (IPv4 or IPv6)
    try:
        return [str(ipaddress.ip_address(destination))]
    except ValueError:
        pass

    # Network / CIDR (IPv4 or IPv6)
    try:
        network = ipaddress.ip_network(destination, strict=False)
        return [str(ip) for ip in network]
    except ValueError:
        pass

    # Hostname or domain — resolve via DNS (both IPv4 and IPv6)
    try:
        infos = socket.getaddrinfo(destination, None)
        ips = list(dict.fromkeys(info[4][0] for info in infos))
        if not ips:
            raise ValueError(f"Cannot resolve destination: '{destination}'")
        return ips
    except socket.gaierror:
        raise ValueError(f"Cannot resolve destination: '{destination}'")


def _is_wild(octet: str) -> bool:
    return bool(re.fullmatch(r"x+", octet, re.IGNORECASE))


def _wildcard_to_cidr(octets: list[str]) -> str:
    first_x = next(i for i, o in enumerate(octets) if _is_wild(o))
    if any(not _is_wild(o) for o in octets[first_x:]):
        raise ValueError(
            "Wildcard 'x' octets must be trailing (e.g. 192.168.1.x, not 192.x.1.x)"
        )
    prefix_bits = first_x * 8
    cidr_octets = octets[:first_x] + ["0"] * (4 - first_x)
    return ".".join(cidr_octets) + f"/{prefix_bits}"
