import ipaddress
import re
import socket

# Matches an IPv4-like address where each octet is either a number or 'x'
# e.g. 192.168.1.x  192.168.x.x  10.x.x.x
_IP_WILD_RE = re.compile(
    r"^(\d{1,3}|x)\.(\d{1,3}|x)\.(\d{1,3}|x)\.(\d{1,3}|x)$",
    re.IGNORECASE,
)


def expand_targets(destination: str) -> list[str]:
    """
    Expand a destination string into a list of IP address strings.

    Accepts:
      - Single IP:     192.168.1.5
      - CIDR range:    192.168.1.0/24
      - Wildcard:      192.168.1.x  (x octets must be trailing)
      - Hostname:      localhost, google.com
    """
    m = _IP_WILD_RE.match(destination)
    if m:
        octets = list(m.groups())
        if any(o.lower() == "x" for o in octets):
            cidr = _wildcard_to_cidr(octets)
            network = ipaddress.ip_network(cidr, strict=False)
            return [str(ip) for ip in network]
        # All numeric octets — fall through to single IP / CIDR handling

    try:
        return [str(ipaddress.ip_address(destination))]
    except ValueError:
        pass

    try:
        network = ipaddress.ip_network(destination, strict=False)
        return [str(ip) for ip in network]
    except ValueError:
        pass

    # Hostname or domain — resolve to IPv4
    try:
        infos = socket.getaddrinfo(destination, None, socket.AF_INET)
        return list(dict.fromkeys(info[4][0] for info in infos))
    except socket.gaierror:
        raise ValueError(f"Cannot resolve destination: '{destination}'")


def _wildcard_to_cidr(octets: list[str]) -> str:
    first_x = next(i for i, o in enumerate(octets) if o.lower() == "x")
    if any(o.lower() != "x" for o in octets[first_x:]):
        raise ValueError(
            "Wildcard 'x' octets must be trailing (e.g. 192.168.1.x, not 192.x.1.x)"
        )
    prefix_bits = first_x * 8
    cidr_octets = octets[:first_x] + ["0"] * (4 - first_x)
    return ".".join(cidr_octets) + f"/{prefix_bits}"
