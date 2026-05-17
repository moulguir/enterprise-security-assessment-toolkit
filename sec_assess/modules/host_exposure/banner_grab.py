import socket


HTTP_PROBE = b"HEAD / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"


def grab_banner(target: str, port: int, timeout: float = 2.0) -> str:
    """
    Attempts to collect a lightweight service banner.

    This is intentionally conservative:
    - no exploitation
    - no authentication attempts
    - no intrusive payloads
    """
    try:
        with socket.create_connection((target, port), timeout=timeout) as sock:
            sock.settimeout(timeout)

            if port in [80, 8080, 8000, 8008]:
                sock.sendall(HTTP_PROBE)

            try:
                data = sock.recv(1024)
            except socket.timeout:
                return ""

            return data.decode(errors="replace").strip()

    except OSError:
        return ""