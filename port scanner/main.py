"""CLI entry point for the asynchronous port scanner."""

from __future__ import annotations

import argparse
import asyncio
import sys
from collections.abc import Sequence

from rich.console import Console
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table
from rich.text import Text

from scanner import COMMON_PORTS, AsyncPortScanner, PortState, ScanResult

console = Console()

STATE_STYLES: dict[PortState, str] = {
    PortState.OPEN: "bold green",
    PortState.CLOSED: "dim",
    PortState.FILTERED: "yellow",
    PortState.ERROR: "red",
}


def parse_ports(raw: str) -> list[int]:
    ports: set[int] = set()
    for chunk in raw.split(","):
        piece = chunk.strip()
        if not piece:
            continue
        if "-" in piece:
            start_s, end_s = piece.split("-", 1)
            try:
                start, end = int(start_s), int(end_s)
            except ValueError as exc:
                raise argparse.ArgumentTypeError(f"Invalid port range: {piece}") from exc
            if start > end:
                start, end = end, start
            if start < 1 or end > 65535:
                raise argparse.ArgumentTypeError(f"Port range out of bounds: {piece}")
            ports.update(range(start, end + 1))
        else:
            try:
                port = int(piece)
            except ValueError as exc:
                raise argparse.ArgumentTypeError(f"Invalid port: {piece}") from exc
            if port < 1 or port > 65535:
                raise argparse.ArgumentTypeError(f"Port out of bounds: {piece}")
            ports.add(port)
    if not ports:
        raise argparse.ArgumentTypeError("No valid ports were provided")
    return sorted(ports)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="port-scanner",
        description="Asynchronous TCP port scanner with banner grabbing.",
    )
    parser.add_argument("host", help="Target hostname or IPv4 address")
    parser.add_argument(
        "-p",
        "--ports",
        default="1-1024",
        help="Ports to scan, e.g. 22,80,443 or 1-1024 (default: 1-1024)",
    )
    parser.add_argument(
        "--common",
        action="store_true",
        help="Scan a built-in list of common service ports instead of --ports",
    )
    parser.add_argument(
        "-t",
        "--timeout",
        type=float,
        default=2.0,
        help="Connection timeout in seconds (default: 2.0)",
    )
    parser.add_argument(
        "-c",
        "--concurrency",
        type=int,
        default=200,
        help="Maximum concurrent connections (default: 200)",
    )
    parser.add_argument(
        "--no-banner",
        action="store_true",
        help="Skip banner grabbing on open ports",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Show closed/filtered ports as well as open ones",
    )
    return parser


def render_results(host: str, ip: str, results: Sequence[ScanResult], show_all: bool) -> None:
    visible = [item for item in results if show_all or item.state == PortState.OPEN]
    open_count = sum(1 for item in results if item.state == PortState.OPEN)

    summary = Table.grid(padding=(0, 2))
    summary.add_row("[bold]Target[/]", f"{host} ({ip})")
    summary.add_row("[bold]Scanned[/]", str(len(results)))
    summary.add_row("[bold]Open[/]", f"[green]{open_count}[/]")
    console.print(summary)
    console.print()

    if not visible:
        console.print("[yellow]No open ports found.[/]")
        return

    table = Table(title="Scan Results", show_lines=False, expand=True)
    table.add_column("Port", style="cyan", no_wrap=True)
    table.add_column("State")
    table.add_column("Service", style="magenta")
    table.add_column("Latency", justify="right")
    table.add_column("Banner", overflow="fold")

    for item in visible:
        latency = f"{item.latency_ms:.1f} ms" if item.latency_ms is not None else "-"
        state = Text(item.state.value, style=STATE_STYLES[item.state])
        banner = item.banner or item.error or ""
        table.add_row(str(item.port), state, item.service or "-", latency, banner)

    console.print(table)


async def run(args: argparse.Namespace) -> int:
    ports = list(COMMON_PORTS.keys()) if args.common else parse_ports(args.ports)
    scanner = AsyncPortScanner(
        timeout=args.timeout,
        concurrency=args.concurrency,
        grab_banner=not args.no_banner,
    )

    console.print(
        f"[bold blue]Scanning[/] [white]{args.host}[/] "
        f"[dim]({len(ports)} ports, concurrency={args.concurrency})[/]"
    )

    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("{task.completed}/{task.total}"),
            TimeElapsedColumn(),
            console=console,
            transient=True,
        ) as progress:
            task_id = progress.add_task("Probing ports", total=len(ports))

            def on_progress(done: int, total: int) -> None:
                progress.update(task_id, completed=done, total=total)

            results = await scanner.scan(args.host, ports, on_progress=on_progress)
    except ValueError as exc:
        console.print(f"[red]Error:[/] {exc}")
        return 1
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan cancelled.[/]")
        return 130

    ip = results[0].ip if results else args.host
    render_results(args.host, ip, results, show_all=args.all)
    return 0


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    try:
        raise SystemExit(asyncio.run(run(args)))
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan cancelled.[/]")
        raise SystemExit(130) from None


if __name__ == "__main__":
    if sys.platform.startswith("win"):
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    main()
