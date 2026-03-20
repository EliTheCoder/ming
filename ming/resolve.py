import asyncio
import socket


async def resolve_one(ip: str) -> str | None:
    """Reverse-DNS resolve a single IP. Returns hostname or None."""
    loop = asyncio.get_running_loop()
    try:
        result = await loop.run_in_executor(None, socket.gethostbyaddr, ip)
        return result[0]  # (hostname, aliaslist, ipaddrlist)
    except (socket.herror, socket.gaierror, OSError):
        return None


async def resolve_all(ips: list[str]) -> dict[str, str | None]:
    """Reverse-DNS resolve a list of IPs concurrently. Returns {ip: hostname_or_None}."""
    hostnames = await asyncio.gather(*[resolve_one(ip) for ip in ips])
    return dict(zip(ips, hostnames, strict=True))
