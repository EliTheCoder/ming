import asyncio
import ipaddress
import socket
from collections.abc import Callable

from icmplib import async_ping

ICMP_CONCURRENCY = 150
TCP_CONCURRENCY = 500
UDP_CONCURRENCY = 200

ICMP_TIMEOUT = 1.0
TCP_TIMEOUT = 1.0
UDP_TIMEOUT = 2.0


async def _icmp_probe(ip: str, timeout: float) -> tuple[bool, float]:
    try:
        host = await async_ping(ip, count=1, timeout=timeout, privileged=False)
        return host.is_alive, host.avg_rtt if host.is_alive else 0.0
    except Exception:
        return False, 0.0


async def _tcp_probe(ip: str, port: int, timeout: float) -> bool:
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=timeout,
        )
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return True
    except Exception:
        return False


async def _udp_probe(ip: str, port: int, timeout: float) -> str:
    """Returns 'responded', 'reachable', or 'closed'."""
    loop = asyncio.get_running_loop()
    try:
        addr = ipaddress.ip_address(ip)
        family = socket.AF_INET6 if addr.version == 6 else socket.AF_INET
    except ValueError:
        family = socket.AF_INET

    sock = socket.socket(family, socket.SOCK_DGRAM)
    sock.setblocking(False)
    try:
        # Use getaddrinfo to get the correct connect address for both IPv4 and IPv6
        addrinfos = socket.getaddrinfo(ip, port, family, socket.SOCK_DGRAM)
        connect_addr = addrinfos[0][4]
        sock.connect(connect_addr)

        try:
            await loop.sock_sendall(sock, b"\x00\x00")
        except (ConnectionRefusedError, ConnectionResetError):
            return "reachable"
        except OSError:
            return "closed"

        try:
            await asyncio.wait_for(loop.sock_recv(sock, 1024), timeout=timeout)
            return "responded"
        except asyncio.TimeoutError:
            return "closed"
        except (ConnectionRefusedError, ConnectionResetError):
            return "reachable"
        except OSError:
            return "closed"
    except Exception:
        return "closed"
    finally:
        sock.close()


async def run_icmp_scan(
    ips: list[str],
    on_result: Callable[[str, dict], None],
    on_progress: Callable[[], None],
    timeout: float = ICMP_TIMEOUT,
    concurrency: int = ICMP_CONCURRENCY,
) -> None:
    sem = asyncio.Semaphore(concurrency)

    async def scan_one(ip: str) -> None:
        async with sem:
            alive, rtt = await _icmp_probe(ip, timeout)
        on_progress()
        if alive:
            on_result(ip, {"rtt": rtt})

    await asyncio.gather(
        *[asyncio.create_task(scan_one(ip)) for ip in ips],
        return_exceptions=True,
    )


async def run_tcp_scan(
    ips: list[str],
    ports: list[int],
    on_result: Callable[[str, dict], None],
    on_progress: Callable[[], None],
    timeout: float = TCP_TIMEOUT,
    concurrency: int = TCP_CONCURRENCY,
) -> None:
    sem = asyncio.Semaphore(concurrency)
    ip_ports: dict[str, list[int]] = {}

    async def scan_one(ip: str, port: int) -> None:
        async with sem:
            is_open = await _tcp_probe(ip, port, timeout)
        on_progress()
        if is_open:
            if ip not in ip_ports:
                ip_ports[ip] = []
            ip_ports[ip].append(port)
            on_result(ip, {"open_ports": sorted(ip_ports[ip])})

    await asyncio.gather(
        *[asyncio.create_task(scan_one(ip, port)) for ip in ips for port in ports],
        return_exceptions=True,
    )


async def run_udp_scan(
    ips: list[str],
    ports: list[int],
    on_result: Callable[[str, dict], None],
    on_progress: Callable[[], None],
    timeout: float = UDP_TIMEOUT,
    concurrency: int = UDP_CONCURRENCY,
) -> None:
    sem = asyncio.Semaphore(concurrency)
    ip_data: dict[str, dict] = {}

    async def scan_one(ip: str, port: int) -> None:
        async with sem:
            result = await _udp_probe(ip, port, timeout)
        on_progress()
        if result in ("reachable", "responded"):
            if ip not in ip_data:
                ip_data[ip] = {"reachable": False, "responded_ports": []}
            if result == "reachable":
                ip_data[ip]["reachable"] = True
            else:
                ip_data[ip]["responded_ports"].append(port)
                ip_data[ip]["responded_ports"].sort()
            on_result(ip, dict(ip_data[ip]))

    await asyncio.gather(
        *[asyncio.create_task(scan_one(ip, port)) for ip in ips for port in ports],
        return_exceptions=True,
    )
