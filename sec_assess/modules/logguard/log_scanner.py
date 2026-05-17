from pathlib import Path

from sec_assess.core.finding import Finding
from sec_assess.modules.logguard.detectors.ssh_bruteforce import (
    detect_invalid_user_activity,
    detect_root_login_attempts,
    detect_ssh_bruteforce,
)
from sec_assess.modules.logguard.parsers.linux_auth import parse_linux_auth_log


class LogGuardScanner:
    def scan_auth_log(
        self,
        file_path: str,
        threshold: int = 5,
    ) -> list[Finding]:
        path = Path(file_path)
        target = str(path)

        events = parse_linux_auth_log(file_path)

        findings: list[Finding] = []

        findings.extend(
            detect_ssh_bruteforce(
                events=events,
                target=target,
                threshold=threshold,
            )
        )

        findings.extend(
            detect_invalid_user_activity(
                events=events,
                target=target,
            )
        )

        findings.extend(
            detect_root_login_attempts(
                events=events,
                target=target,
            )
        )

        return findings