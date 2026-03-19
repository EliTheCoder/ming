import asyncio
import csv
import io
import ipaddress

def _ip_sort_key(ip: str) -> tuple:
    addr = ipaddress.ip_address(ip)
    return (addr.version, int(addr))
import json
import time

import click

from ming.display import ScanDisplay, _fmt_ports, console
from ming.ports import parse_port_spec
from ming.resolve import resolve_all
from ming.scanner import (
    ICMP_CONCURRENCY,
    ICMP_TIMEOUT,
    TCP_CONCURRENCY,
    TCP_TIMEOUT,
    UDP_CONCURRENCY,
    UDP_TIMEOUT,
    run_icmp_scan,
    run_tcp_scan,
    run_udp_scan,
)
from ming.targets import expand_targets

VALID_METHODS = {"icmp", "ping", "syn", "tcp", "udp"}
ICMP_METHODS = {"icmp", "ping"}
TCP_METHODS = {"syn", "tcp"}
UDP_METHODS = {"udp"}


@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.argument("destination")
@click.argument("method", default="icmp", required=False)
@click.argument("port_spec", default=None, required=False)
@click.option("--output", "-o", "output_format",
              type=click.Choice(["json", "csv"]), default=None,
              help="Output format — prints to stdout, disables live display.")
@click.option("--quiet", "-q", is_flag=True, default=False,
              help="No live display; print one line per responding host.")
@click.option("--timeout", "-t", type=float, default=None,
              help="Probe timeout in seconds (overrides per-protocol default).")
@click.option("--concurrency", "-c", type=int, default=None,
              help="Max concurrent probes (overrides per-protocol default).")
@click.option("--resolve/--no-resolve", "-r/-R", default=True,
              help="Reverse DNS lookup on responding IPs (default: on).")
@click.option("--watch", "-w", is_flag=True, default=False,
              help="Re-scan repeatedly on --interval.")
@click.option("--interval", "-i", type=int, default=30,
              help="Seconds between re-scans in watch mode (default: 30).")
def main(
    destination: str,
    method: str,
    port_spec: str | None,
    output_format: str | None,
    quiet: bool,
    timeout: float | None,
    concurrency: int | None,
    resolve: bool,
    watch: bool,
    interval: int,
) -> None:
    """
    Multi-ping network scanner.

    \b
    DESTINATION  IP, CIDR, wildcard, or hostname  (e.g. 192.168.1.1, 192.168.1.0/24,
                 192.168.1.x, localhost, google.com, 10.0.0.1,10.0.1.1)
    METHOD       icmp|ping|syn|tcp|udp             (default: icmp)
    PORT_SPEC    ports for tcp/udp mode            (e.g. 80, 80,443, 8000-8080,
                 top100, web, db, ssh, http, postgres)
    """
    method = method.lower()
    if method not in VALID_METHODS:
        raise click.BadParameter(
            f"must be one of: {', '.join(sorted(VALID_METHODS))}",
            param_hint="METHOD",
        )

    if port_spec is not None and method in ICMP_METHODS:
        raise click.UsageError("Port specification is only supported for tcp/udp modes.")

    if output_format and watch:
        raise click.UsageError("--output and --watch are mutually exclusive.")

    if quiet and output_format:
        raise click.UsageError("--quiet and --output are mutually exclusive.")

    try:
        ips = expand_targets(destination)
    except ValueError as e:
        raise click.BadParameter(str(e), param_hint="DESTINATION") from e

    if not ips:
        console.print("[yellow]No targets to scan.[/yellow]")
        return

    ports: list[int] = []
    if method in TCP_METHODS | UDP_METHODS:
        try:
            ports = parse_port_spec(port_spec)
        except ValueError as e:
            raise click.BadParameter(str(e), param_hint="PORT_SPEC") from e

    mode_label = (
        "icmp" if method in ICMP_METHODS
        else "tcp" if method in TCP_METHODS
        else "udp"
    )
    n_ips = len(ips)
    n_ports = len(ports)
    total = n_ips if mode_label == "icmp" else n_ips * n_ports

    # Effective timeout and concurrency
    if timeout is None:
        eff_timeout = {"icmp": ICMP_TIMEOUT, "tcp": TCP_TIMEOUT, "udp": UDP_TIMEOUT}[mode_label]
    else:
        eff_timeout = timeout

    if concurrency is None:
        eff_concurrency = {"icmp": ICMP_CONCURRENCY, "tcp": TCP_CONCURRENCY, "udp": UDP_CONCURRENCY}[mode_label]
    else:
        eff_concurrency = concurrency

    suppress_display = quiet or bool(output_format)
    use_silent = bool(output_format)  # buffer only, no per-line output

    # ------------------------------------------------------------------
    # Scan loop (runs once normally, loops in watch mode)
    # ------------------------------------------------------------------
    previous_ips: set[str] = set()
    new_ips: set[str] = set()
    hostname_cache: dict[str, str | None] = {}
    scan_num = 0

    while True:
        scan_num += 1
        current_ips: set[str] = set()
        interrupted = False

        if not suppress_display:
            if mode_label == "icmp":
                console.print(f"[bold]Scanning {n_ips} host(s) via ICMP[/bold]")
            else:
                console.print(
                    f"[bold]Scanning {n_ips} host(s) × {n_ports} port(s)"
                    f" via {method.upper()}[/bold]"
                )

        start_time = time.monotonic()

        watch_scan_num = scan_num if watch else 0
        with ScanDisplay(
            mode_label,
            total,
            quiet=quiet and not use_silent,
            silent=use_silent,
            resolve=resolve,
            watch_scan=watch_scan_num,
            show_progress=n_ips > 1,
        ) as display:

            def on_result(ip: str, data: dict) -> None:
                current_ips.add(ip)
                display.update_host(ip, data)

            def on_progress() -> None:
                display.advance()

            try:
                if mode_label == "icmp":
                    asyncio.run(run_icmp_scan(
                        ips, on_result, on_progress,
                        timeout=eff_timeout, concurrency=eff_concurrency,
                    ))
                elif mode_label == "tcp":
                    asyncio.run(run_tcp_scan(
                        ips, ports, on_result, on_progress,
                        timeout=eff_timeout, concurrency=eff_concurrency,
                    ))
                else:
                    asyncio.run(run_udp_scan(
                        ips, ports, on_result, on_progress,
                        timeout=eff_timeout, concurrency=eff_concurrency,
                    ))
            except KeyboardInterrupt:
                interrupted = True

            # Highlight new hosts in watch mode (after scan, before display closes)
            if watch and previous_ips:
                display.set_new_ips(current_ips - previous_ips)

            # Reverse DNS resolution — skip if interrupted
            hostnames: dict[str, str | None] | None = None
            if resolve and display.results and not interrupted:
                try:
                    new_to_resolve = set(display.results) - set(hostname_cache)
                    if new_to_resolve:
                        new_h = asyncio.run(resolve_all(list(new_to_resolve)))
                        hostname_cache.update(new_h)
                    hostnames = {ip: hostname_cache.get(ip) for ip in display.results}
                    display.set_hostnames(hostnames)
                except KeyboardInterrupt:
                    interrupted = True

        # ----------------------------------------------------------
        # Post-scan: output, stats
        # ----------------------------------------------------------
        elapsed = time.monotonic() - start_time

        if interrupted and not suppress_display:
            console.print("[yellow]Interrupted.[/yellow]")

        if output_format:
            print(_format_json(display.results, mode_label, hostnames) if output_format == "json"
                  else _format_csv(display.results, mode_label, hostnames))

        if not output_format:
            _print_summary(display.results, mode_label, n_ips, n_ports, elapsed)

        if interrupted or not watch:
            break

        previous_ips = set(display.results.keys())
        try:
            console.print(f"[dim]Waiting {interval}s... (Ctrl+C to stop)[/dim]")
            time.sleep(interval)
        except KeyboardInterrupt:
            break


# ------------------------------------------------------------------
# Output formatters
# ------------------------------------------------------------------


def _format_json(
    results: dict[str, dict],
    mode: str,
    hostnames: dict[str, str | None] | None,
) -> str:
    rows = []
    for ip in sorted(results, key=_ip_sort_key):
        row: dict = {"ip": ip}
        if hostnames is not None:
            row["hostname"] = hostnames.get(ip)
        data = dict(results[ip])
        # Convert port lists to plain lists (already are, just being explicit)
        row.update(data)
        rows.append(row)
    return json.dumps(rows, indent=2)


def _format_csv(
    results: dict[str, dict],
    mode: str,
    hostnames: dict[str, str | None] | None,
) -> str:
    if not results:
        return ""
    sample = next(iter(results.values()))
    fieldnames = ["ip"]
    if hostnames is not None:
        fieldnames.append("hostname")
    fieldnames.extend(sample.keys())

    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=fieldnames, extrasaction="ignore")
    writer.writeheader()
    for ip in sorted(results, key=_ip_sort_key):
        row: dict = {"ip": ip}
        if hostnames is not None:
            row["hostname"] = hostnames.get(ip)
        data = dict(results[ip])
        for k, v in data.items():
            if isinstance(v, list):
                data[k] = ";".join(str(p) for p in v)
        row.update(data)
        writer.writerow(row)
    return buf.getvalue().rstrip("\r\n")


# ------------------------------------------------------------------
# Summary stats
# ------------------------------------------------------------------


def _print_summary(
    results: dict[str, dict],
    mode: str,
    n_ips: int,
    n_ports: int,
    elapsed: float,
) -> None:
    n = len(results)
    if n == 0:
        console.print("[yellow]No hosts responded.[/yellow]")
        return

    if mode == "icmp":
        rtts = [d["rtt"] for d in results.values() if d.get("rtt")]
        avg_rtt = sum(rtts) / len(rtts) if rtts else 0.0
        rate = 100 * n / n_ips if n_ips else 0
        console.print(
            f"[green]{n}/{n_ips} hosts responded ({rate:.0f}%)[/green]  "
            f"[dim]avg RTT {avg_rtt:.1f}ms — {elapsed:.1f}s[/dim]"
        )
    elif mode in ("tcp", "syn"):
        total_ports = sum(len(d.get("open_ports", [])) for d in results.values())
        console.print(
            f"[green]{n} host(s) with open ports, {total_ports} open port(s) total[/green]  "
            f"[dim]{n_ips} hosts × {n_ports} ports — {elapsed:.1f}s[/dim]"
        )
    else:  # udp
        reachable = sum(1 for d in results.values() if d.get("reachable"))
        responded = sum(len(d.get("responded_ports", [])) for d in results.values())
        console.print(
            f"[green]{reachable} reachable host(s), {responded} port(s) responded[/green]  "
            f"[dim]{n_ips} hosts × {n_ports} ports — {elapsed:.1f}s[/dim]"
        )
