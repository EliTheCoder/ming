import asyncio
import collections
import contextlib
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


async def _tcp_probe(ip: str, port: int, timeout: float) -> str:
    """Returns 'open', 'closed' (RST/refused), or 'timeout' (packet dropped)."""
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=timeout,
        )
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()
        return "open"
    except TimeoutError:
        return "timeout"
    except Exception:
        return "closed"


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
        except TimeoutError:
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
    queue: asyncio.Queue = asyncio.Queue()
    for ip in ips:
        queue.put_nowait(ip)

    async def worker() -> None:
        while True:
            try:
                ip = queue.get_nowait()
            except asyncio.QueueEmpty:
                return
            try:
                alive, rtt = await _icmp_probe(ip, timeout)
            except asyncio.CancelledError:
                return
            on_progress()
            if alive:
                on_result(ip, {"rtt": rtt})

    n_workers = min(concurrency, len(ips)) if ips else 0
    await asyncio.gather(
        *[asyncio.create_task(worker()) for _ in range(n_workers)],
        return_exceptions=True,
    )


async def run_tcp_scan(
    ips: list[str],
    ports: list[int],
    on_result: Callable[[str, dict], None],
    on_progress: Callable[[], None],
    timeout: float = TCP_TIMEOUT,
    concurrency: int = TCP_CONCURRENCY,
    max_concurrency: int | None = None,
) -> None:
    queue: asyncio.Queue = asyncio.Queue()
    # Port-major ordering: interleave hosts so workers spread load evenly
    # rather than hammering one host with all workers at once.
    for port in ports:
        for ip in ips:
            queue.put_nowait((ip, port))

    ip_ports: dict[str, list[int]] = {}

    # ------------------------------------------------------------------
    # Adaptive concurrency: track timeout ratio in a sliding window.
    # Timeouts mean packets are being dropped (throttled/filtered).
    # RST/refused connections are fast and expected — not a signal.
    #
    # `concurrency`     — starting (conservative) limit
    # `max_concurrency` — ceiling for adaptive growth (defaults to concurrency)
    #
    # To reduce: consume semaphore slots (acquire without releasing).
    # To recover: release those consumed slots back, up to max_concurrency.
    # Workers are always spawned at max_concurrency so they're ready when
    # extra slots open up — the semaphore controls actual parallelism.
    # ------------------------------------------------------------------
    _max_conc = max_concurrency if max_concurrency is not None else concurrency
    sem = asyncio.Semaphore(concurrency)
    current_conc = concurrency
    min_conc = max(5, concurrency // 10)
    window: collections.deque[bool] = collections.deque(maxlen=30)
    adjusting = False

    async def _adjust() -> None:
        nonlocal current_conc, adjusting
        if adjusting or len(window) < 10:
            return
        rate = sum(window) / len(window)
        if rate > 0.25 and current_conc > min_conc:
            # Too many timeouts — reduce by 25% (consume slots).
            adjusting = True
            new = max(min_conc, current_conc * 3 // 4)
            delta = current_conc - new
            current_conc = new
            for _ in range(delta):
                await sem.acquire()
            adjusting = False
        elif rate < 0.05 and current_conc < _max_conc:
            # Mostly RSTs, network is healthy — grow by 25% (release slots).
            new = min(_max_conc, current_conc + max(1, current_conc // 4))
            delta = new - current_conc
            current_conc = new
            for _ in range(delta):
                sem.release()

    async def worker() -> None:
        while True:
            try:
                ip, port = queue.get_nowait()
            except asyncio.QueueEmpty:
                return
            try:
                async with sem:
                    result = await _tcp_probe(ip, port, timeout)
            except asyncio.CancelledError:
                return
            on_progress()
            window.append(result == "timeout")
            await _adjust()
            if result == "open":
                if ip not in ip_ports:
                    ip_ports[ip] = []
                ip_ports[ip].append(port)
                on_result(ip, {"open_ports": sorted(ip_ports[ip])})

    total = len(ips) * len(ports)
    # Spawn workers up to _max_conc so they're ready as adaptive recovery
    # releases more slots — semaphore caps actual in-flight probes.
    n_workers = min(_max_conc, total) if total else 0
    await asyncio.gather(
        *[asyncio.create_task(worker()) for _ in range(n_workers)],
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
    queue: asyncio.Queue = asyncio.Queue()
    for ip in ips:
        for port in ports:
            queue.put_nowait((ip, port))

    ip_data: dict[str, dict] = {}

    async def worker() -> None:
        while True:
            try:
                ip, port = queue.get_nowait()
            except asyncio.QueueEmpty:
                return
            try:
                result = await _udp_probe(ip, port, timeout)
            except asyncio.CancelledError:
                return
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

    total = len(ips) * len(ports)
    n_workers = min(concurrency, total) if total else 0
    await asyncio.gather(
        *[asyncio.create_task(worker()) for _ in range(n_workers)],
        return_exceptions=True,
    )
