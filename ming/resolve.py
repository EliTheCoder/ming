import asyncio
import socket


async def resolve_all(ips: list[str]) -> dict[str, str | None]:
    """
    Reverse-DNS resolve a list of IPs concurrently.
    Returns {ip: hostname_or_None}.
    """
    loop = asyncio.get_running_loop()

    async def _resolve_one(ip: str) -> tuple[str, str | None]:
        try:
            result = await loop.run_in_executor(None, socket.gethostbyaddr, ip)
            return ip, result[0]  # (hostname, aliaslist, ipaddrlist)
        except socket.herror, socket.gaierror, OSError:
            return ip, None

    pairs = await asyncio.gather(*[_resolve_one(ip) for ip in ips])
    return dict(pairs)
