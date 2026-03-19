import ipaddress


def expand_targets(destination: str) -> list[str]:
    """
    Expand a destination string into a list of IP address strings.

    Accepts:
      - Single IP:     192.168.1.5
      - CIDR range:    192.168.1.0/24
      - Wildcard:      192.168.1.*  (equivalent to 192.168.1.0/24)
    """
    if "x" in destination.split("."):
        destination = _wildcard_to_cidr(destination)

    try:
        return [str(ipaddress.ip_address(destination))]
    except ValueError:
        pass

    try:
        network = ipaddress.ip_network(destination, strict=False)
        return [str(ip) for ip in network]
    except ValueError:
        raise ValueError(f"Invalid destination: '{destination}'")


def _wildcard_to_cidr(destination: str) -> str:
    parts = destination.split(".")
    if "x" not in parts:
        raise ValueError(f"Unexpected wildcard position in '{destination}'")
    wildcard_idx = parts.index("x")
    prefix_bits = wildcard_idx * 8
    cidr_parts = parts[:wildcard_idx] + ["0"] * (4 - wildcard_idx)
    return ".".join(cidr_parts) + f"/{prefix_bits}"
