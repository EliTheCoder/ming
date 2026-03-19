import asyncio

import click

from ming.display import ScanDisplay, console
from ming.ports import parse_port_spec
from ming.scanner import run_icmp_scan, run_tcp_scan, run_udp_scan
from ming.targets import expand_targets

VALID_METHODS = {"icmp", "ping", "syn", "tcp", "udp"}
ICMP_METHODS = {"icmp", "ping"}
TCP_METHODS = {"syn", "tcp"}
UDP_METHODS = {"udp"}


@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.argument("destination")
@click.argument("method", default="icmp", required=False)
@click.argument("port_spec", default=None, required=False)
def main(destination: str, method: str, port_spec: str | None) -> None:
    """
    Multi-ping network scanner.

    \b
    DESTINATION  IP, CIDR range, or wildcard  (e.g. 192.168.1.1, 192.168.1.0/24, 192.168.1.*)
    METHOD       icmp|ping|syn|tcp|udp         (default: icmp)
    PORT_SPEC    ports for tcp/udp mode        (e.g. 80, 80,443, 8000-8080, top100)
    """
    method = method.lower()
    if method not in VALID_METHODS:
        raise click.BadParameter(
            f"must be one of: {', '.join(sorted(VALID_METHODS))}",
            param_hint="METHOD",
        )

    if port_spec is not None and method in ICMP_METHODS:
        raise click.UsageError("Port specification is only supported for tcp/udp modes.")

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

    n_ips = len(ips)
    n_ports = len(ports)
    total = n_ips if method in ICMP_METHODS else n_ips * n_ports

    mode_label = "icmp" if method in ICMP_METHODS else ("tcp" if method in TCP_METHODS else "udp")

    if method in ICMP_METHODS:
        console.print(f"[bold]Scanning {n_ips} host(s) via ICMP[/bold]")
    else:
        console.print(
            f"[bold]Scanning {n_ips} host(s) × {n_ports} port(s) via {method.upper()}[/bold]"
        )

    with ScanDisplay(mode_label, total) as display:

        def on_result(ip: str, data: dict) -> None:
            display.update_host(ip, data)

        def on_progress() -> None:
            display.advance()

        if method in ICMP_METHODS:
            asyncio.run(run_icmp_scan(ips, on_result, on_progress))
        elif method in TCP_METHODS:
            asyncio.run(run_tcp_scan(ips, ports, on_result, on_progress))
        else:
            asyncio.run(run_udp_scan(ips, ports, on_result, on_progress))

    count = len(display.results)
    if count == 0:
        console.print("[yellow]No hosts responded.[/yellow]")
    else:
        console.print(f"[green]Done. {count} host(s) responded.[/green]")
