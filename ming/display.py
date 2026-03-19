import ipaddress

from rich.console import Console, Group
from rich.live import Live
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeRemainingColumn,
)
from rich.table import Table

console = Console()


class ScanDisplay:
    def __init__(self, mode: str, total: int) -> None:
        self.mode = mode
        self.results: dict[str, dict] = {}

        self.progress = Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
            TimeRemainingColumn(),
            console=console,
        )
        self._task_id = self.progress.add_task("Scanning", total=total)
        self._live = Live(
            self._render(),
            console=console,
            refresh_per_second=10,
            transient=False,
        )

    def __enter__(self) -> "ScanDisplay":
        self._live.__enter__()
        return self

    def __exit__(self, *args: object) -> None:
        self._live.__exit__(*args)

    def _build_table(self) -> Table:
        table = Table(show_header=True, header_style="bold cyan", box=None, padding=(0, 1))

        if self.mode == "icmp":
            table.add_column("IP Address", style="bold white", min_width=16)
            table.add_column("RTT (ms)", justify="right", style="green")
        elif self.mode in ("tcp", "syn"):
            table.add_column("IP Address", style="bold white", min_width=16)
            table.add_column("Open Ports", style="green")
        else:  # udp
            table.add_column("IP Address", style="bold white", min_width=16)
            table.add_column("Reachable", justify="center")
            table.add_column("Responded Ports", style="green")

        for ip in sorted(self.results, key=ipaddress.ip_address):
            data = self.results[ip]
            if self.mode == "icmp":
                table.add_row(ip, f"{data['rtt']:.1f}")
            elif self.mode in ("tcp", "syn"):
                ports_str = _fmt_ports(data.get("open_ports", []))
                table.add_row(ip, ports_str)
            else:  # udp
                reachable = "[green]✓[/green]" if data.get("reachable") else "[red]✗[/red]"
                ports_str = _fmt_ports(data.get("responded_ports", []))
                table.add_row(ip, reachable, ports_str)

        return table

    def _render(self) -> Group:
        return Group(self._build_table(), self.progress)

    def update_host(self, ip: str, data: dict) -> None:
        self.results[ip] = data
        self._live.update(self._render())

    def advance(self) -> None:
        self.progress.advance(self._task_id)
        self._live.update(self._render())


def _fmt_ports(ports: list[int]) -> str:
    if not ports:
        return ""
    return ", ".join(str(p) for p in sorted(ports))
