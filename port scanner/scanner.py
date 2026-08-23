"""Asynchronous TCP port scanner with optional banner grabbing."""

from __future__ import annotations

import asyncio
import socket
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from enum import Enum

ProgressCallback = Callable[[int, int], None]


class PortState(str, Enum):
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"
    ERROR = "error"


@dataclass(frozen=True, slots=True)
class ScanResult:
    host: str
    ip: str
    port: int
    state: PortState
    service: str
    banner: str
    latency_ms: float | None = None
    error: str | None = None


COMMON_PORTS: dict[int, str] = {
    20: "ftp-data",
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    111: "rpcbind",
    135: "msrpc",
    139: "netbios-ssn",
    143: "imap",
    443: "https",
    445: "microsoft-ds",
    465: "smtps",
    587: "submission",
    993: "imaps",
    995: "pop3s",
    1433: "mssql",
    1521: "oracle",
    3306: "mysql",
    3389: "rdp",
    5432: "postgresql",
    5900: "vnc",
    6379: "redis",
    8080: "http-alt",
    8443: "https-alt",
    27017: "mongodb",
}


class AsyncPortScanner:
    """Concurrent TCP connect scanner with banner grabbing."""

    def __init__(
        self,
        timeout: float = 2.0,
        concurrency: int = 200,
        grab_banner: bool = True,
        banner_bytes: int = 256,
    ) -> None:
        if timeout <= 0:
            raise ValueError("timeout must be greater than 0")
        if concurrency < 1:
            raise ValueError("concurrency must be at least 1")
        if banner_bytes < 1:
            raise ValueError("banner_bytes must be at least 1")

        self.timeout = timeout
        self.concurrency = concurrency
        self.grab_banner = grab_banner
        self.banner_bytes = banner_bytes

    async def resolve_host(self, host: str) -> str:
        loop = asyncio.get_running_loop()
        try:
            info = await loop.getaddrinfo(
                host,
                None,
                family=socket.AF_INET,
                type=socket.SOCK_STREAM,
            )
        except socket.gaierror as exc:
            raise ValueError(f"Could not resolve host: {host}") from exc

        if not info:
            raise ValueError(f"Could not resolve host: {host}")
        return info[0][4][0]

    async def scan(
        self,
        host: str,
        ports: Sequence[int],
        on_progress: ProgressCallback | None = None,
    ) -> list[ScanResult]:
        unique_ports = self._normalize_ports(ports)
        ip = await self.resolve_host(host)
        semaphore = asyncio.Semaphore(self.concurrency)
        completed = 0
        total = len(unique_ports)
        results: list[ScanResult] = []
        lock = asyncio.Lock()

        async def _run(port: int) -> None:
            nonlocal completed
            async with semaphore:
                result = await self._probe(host, ip, port)
            async with lock:
                results.append(result)
                completed += 1
                if on_progress is not None:
                    on_progress(completed, total)

        await asyncio.gather(*(_run(port) for port in unique_ports))
        results.sort(key=lambda item: item.port)
        return results

    async def _probe(self, host: str, ip: str, port: int) -> ScanResult:
        service = COMMON_PORTS.get(port, "")
        started = asyncio.get_running_loop().time()
        reader: asyncio.StreamReader | None = None
        writer: asyncio.StreamWriter | None = None

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=self.timeout,
            )
            latency_ms = (asyncio.get_running_loop().time() - started) * 1000
            banner = ""
            if self.grab_banner:
                banner = await self._read_banner(reader, writer, port)
            return ScanResult(
                host=host,
                ip=ip,
                port=port,
                state=PortState.OPEN,
                service=service,
                banner=banner,
                latency_ms=latency_ms,
            )
        except TimeoutError:
            return ScanResult(
                host=host,
                ip=ip,
                port=port,
                state=PortState.FILTERED,
                service=service,
                banner="",
            )
        except ConnectionRefusedError:
            return ScanResult(
                host=host,
                ip=ip,
                port=port,
                state=PortState.CLOSED,
                service=service,
                banner="",
            )
        except OSError as exc:
            return ScanResult(
                host=host,
                ip=ip,
                port=port,
                state=PortState.ERROR,
                service=service,
                banner="",
                error=str(exc),
            )
        finally:
            if writer is not None:
                writer.close()
                try:
                    await writer.wait_closed()
                except OSError:
                    pass

    async def _read_banner(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        port: int,
    ) -> str:
        try:
            data = await asyncio.wait_for(reader.read(self.banner_bytes), timeout=1.0)
            if not data:
                probe = self._probe_payload(port)
                if probe:
                    writer.write(probe)
                    await writer.drain()
                    data = await asyncio.wait_for(
                        reader.read(self.banner_bytes),
                        timeout=1.0,
                    )
            return self._sanitize_banner(data)
        except (TimeoutError, OSError):
            return ""

    @staticmethod
    def _probe_payload(port: int) -> bytes:
        if port in {80, 8080, 8000, 8888}:
            return b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n"
        if port in {443, 8443}:
            return b""
        return b"\r\n"

    @staticmethod
    def _sanitize_banner(raw: bytes) -> str:
        text = raw.decode("utf-8", errors="replace")
        cleaned = "".join(ch if 32 <= ord(ch) < 127 else " " for ch in text)
        return " ".join(cleaned.split())[:200]

    @staticmethod
    def _normalize_ports(ports: Sequence[int]) -> list[int]:
        unique: set[int] = set()
        for port in ports:
            if not isinstance(port, int) or isinstance(port, bool):
                raise ValueError(f"Invalid port: {port}")
            if port < 1 or port > 65535:
                raise ValueError(f"Port out of range: {port}")
            unique.add(port)
        if not unique:
            raise ValueError("At least one port is required")
        return sorted(unique)
