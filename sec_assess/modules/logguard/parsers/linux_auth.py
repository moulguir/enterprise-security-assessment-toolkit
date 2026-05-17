import re
from dataclasses import dataclass
from pathlib import Path


FAILED_PASSWORD_PATTERN = re.compile(
    r"Failed password for (?:(invalid user) )?(?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+) port (?P<port>\d+)"
)

ACCEPTED_PASSWORD_PATTERN = re.compile(
    r"Accepted password for (?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+) port (?P<port>\d+)"
)


@dataclass(frozen=True)
class AuthEvent:
    raw_line: str
    event_type: str
    source_ip: str
    username: str
    source_port: int | None = None
    is_invalid_user: bool = False
    is_root_attempt: bool = False


def parse_linux_auth_log(file_path: str) -> list[AuthEvent]:
    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(f"Log file not found: {file_path}")

    events: list[AuthEvent] = []

    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        failed_match = FAILED_PASSWORD_PATTERN.search(line)

        if failed_match:
            username = failed_match.group("user")
            source_ip = failed_match.group("ip")
            source_port = int(failed_match.group("port"))
            invalid_user_marker = failed_match.group(1)

            events.append(
                AuthEvent(
                    raw_line=line,
                    event_type="failed_password",
                    source_ip=source_ip,
                    username=username,
                    source_port=source_port,
                    is_invalid_user=invalid_user_marker is not None,
                    is_root_attempt=username == "root",
                )
            )
            continue

        accepted_match = ACCEPTED_PASSWORD_PATTERN.search(line)

        if accepted_match:
            username = accepted_match.group("user")
            source_ip = accepted_match.group("ip")
            source_port = int(accepted_match.group("port"))

            events.append(
                AuthEvent(
                    raw_line=line,
                    event_type="accepted_password",
                    source_ip=source_ip,
                    username=username,
                    source_port=source_port,
                    is_invalid_user=False,
                    is_root_attempt=username == "root",
                )
            )

    return events