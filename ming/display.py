import ipaddress
from datetime import datetime

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
from rich.text import Text

from ming.ports import port_color

console = Console()


def _ip_sort_key(ip: str) -> tuple:
    """Sort key that handles mixed IPv4/IPv6 (IPv4 first, then IPv6 by value)."""
    addr = ipaddress.ip_address(ip)
    return (addr.version, int(addr))


class ScanDisplay:
    def __init__(
        self,
        mode: str,
        total: int,
        *,
        quiet: bool = False,
        silent: bool = False,
        resolve: bool = False,
        watch_scan: int = 0,
        show_progress: bool = True,
    ) -> None:
        self.mode = mode
        self.quiet = quiet
        self.silent = silent  # buffer only, no output at all (used with --output)
        self.resolve = resolve
        self.results: dict[str, dict] = {}
        self.hostnames: dict[str, str | None] = {}
        self.new_ips: set[str] = set()
        self._watch_scan = watch_scan

        self._show_progress = show_progress and not quiet and not silent

        if not quiet and not silent:
            if self._show_progress:
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
        if not self.quiet and not self.silent:
            self._live.__enter__()
        return self

    def __exit__(self, *args: object) -> None:
        if not self.quiet and not self.silent:
            self._live.__exit__(*args)

    # ------------------------------------------------------------------
    # Public update methods
    # ------------------------------------------------------------------

    def update_host(self, ip: str, data: dict) -> None:
        self.results[ip] = data
        if self.silent:
            pass  # buffer only
        elif self.quiet:
            if not self.resolve:
                _print_quiet_line(ip, data, self.mode)
            # if quiet+resolve: buffer only; printed in print_quiet_results()
        else:
            self._live.update(self._render())

    def advance(self) -> None:
        if self.quiet or self.silent:
            return
        if self._show_progress:
            self.progress.advance(self._task_id)
        self._live.update(self._render())

    def set_hostnames(self, hostnames: dict[str, str | None]) -> None:
        self.hostnames = hostnames
        if self.silent:
            pass  # caller handles output
        elif self.quiet:
            self.print_quiet_results()
        else:
            self._live.update(self._render())

    def set_new_ips(self, new_ips: set[str]) -> None:
        self.new_ips = new_ips
        if not self.quiet and not self.silent:
            self._live.update(self._render())

    def print_quiet_results(self) -> None:
        """Print all results with hostnames. Used when --quiet --resolve."""
        for ip in sorted(self.results, key=_ip_sort_key):
            data = self.results[ip]
            hostname = self.hostnames.get(ip) or ""
            suffix = f" ({hostname})" if hostname else ""
            _print_quiet_line(ip + suffix, data, self.mode)

    # ------------------------------------------------------------------
    # Rendering
    # ------------------------------------------------------------------

    def _build_table(self) -> Table:
        table = Table(show_header=True, header_style="bold cyan", box=None, padding=(0, 1))

        # IP column
        table.add_column("IP Address", min_width=16)

        # Optional hostname column
        if self.resolve:
            table.add_column("Hostname", style="dim", min_width=20)

        if self.mode == "icmp":
            table.add_column("RTT (ms)", justify="right")
        elif self.mode in ("tcp", "syn"):
            table.add_column("Open Ports")
        else:  # udp
            table.add_column("Reachable", justify="center")
            table.add_column("Responded Ports")

        for ip in sorted(self.results, key=_ip_sort_key):
            data = self.results[ip]
            is_new = ip in self.new_ips
            ip_text = Text(ip, style="bold green" if is_new else "bold white")

            cells: list = [ip_text]

            if self.resolve:
                cells.append(self.hostnames.get(ip) or "")

            if self.mode == "icmp":
                cells.append(f"{data['rtt']:.1f}")
            elif self.mode in ("tcp", "syn"):
                cells.append(_fmt_ports_colored(data.get("open_ports", [])))
            else:  # udp
                reachable = (
                    Text("✓", style="green") if data.get("reachable")
                    else Text("✗", style="red")
                )
                cells.append(reachable)
                cells.append(_fmt_ports_colored(data.get("responded_ports", [])))

            table.add_row(*cells)

        return table

    def _render(self) -> Group:
        items: list = []
        if self._watch_scan > 0:
            now = datetime.now().strftime("%H:%M:%S")
            items.append(Text(f"  Scan #{self._watch_scan} — {now}", style="bold cyan"))
        items.append(self._build_table())
        if self._show_progress:
            items.append(self.progress)
        return Group(*items)


# ------------------------------------------------------------------
# Module-level helpers
# ------------------------------------------------------------------


def _fmt_ports(ports: list[int]) -> str:
    return ", ".join(str(p) for p in sorted(ports))


def _fmt_ports_colored(ports: list[int]) -> Text:
    if not ports:
        return Text("")
    text = Text()
    for i, p in enumerate(sorted(ports)):
        if i > 0:
            text.append(", ", style="white")
        text.append(str(p), style=port_color(p))
    return text


def _print_quiet_line(ip: str, data: dict, mode: str) -> None:
    if mode == "icmp":
        console.print(f"{ip}  rtt={data['rtt']:.1f}ms")
    elif mode in ("tcp", "syn"):
        console.print(f"{ip}  open={_fmt_ports(data.get('open_ports', []))}")
    else:
        reachable = "yes" if data.get("reachable") else "no"
        responded = _fmt_ports(data.get("responded_ports", []))
        console.print(f"{ip}  reachable={reachable}  responded={responded}")
