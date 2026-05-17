import socket
from dataclasses import dataclass


@dataclass(frozen=True)
class PortScanResult:
    target: str
    port: int
    is_open: bool
    error: str | None = None


def scan_tcp_port(target: str, port: int, timeout: float = 1.0) -> PortScanResult:
    try:
        with socket.create_connection((target, port), timeout=timeout):
            return PortScanResult(
                target=target,
                port=port,
                is_open=True,
            )

    except (socket.timeout, ConnectionRefusedError, OSError) as error:
        return PortScanResult(
            target=target,
            port=port,
            is_open=False,
            error=str(error),
        )


def scan_tcp_ports(target: str, ports: list[int], timeout: float = 1.0) -> list[PortScanResult]:
    results: list[PortScanResult] = []

    for port in ports:
        results.append(
            scan_tcp_port(
                target=target,
                port=port,
                timeout=timeout,
            )
        )

    return results