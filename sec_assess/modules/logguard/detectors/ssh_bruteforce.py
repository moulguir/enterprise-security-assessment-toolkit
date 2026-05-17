from collections import Counter, defaultdict

from sec_assess.core.finding import Finding
from sec_assess.core.severity import Severity
from sec_assess.modules.logguard.parsers.linux_auth import AuthEvent


def _severity_from_attempts(attempts: int) -> Severity:
    if attempts >= 20:
        return Severity.CRITICAL
    if attempts >= 10:
        return Severity.HIGH
    if attempts >= 5:
        return Severity.MEDIUM
    return Severity.LOW


def detect_ssh_bruteforce(
    events: list[AuthEvent],
    target: str,
    threshold: int = 5,
) -> list[Finding]:
    failed_events = [
        event for event in events if event.event_type == "failed_password"
    ]

    attempts_by_ip = Counter(event.source_ip for event in failed_events)
    users_by_ip: dict[str, set[str]] = defaultdict(set)
    invalid_users_by_ip: Counter[str] = Counter()
    root_attempts_by_ip: Counter[str] = Counter()

    for event in failed_events:
        users_by_ip[event.source_ip].add(event.username)

        if event.is_invalid_user:
            invalid_users_by_ip[event.source_ip] += 1

        if event.is_root_attempt:
            root_attempts_by_ip[event.source_ip] += 1

    findings: list[Finding] = []

    for source_ip, attempts in attempts_by_ip.items():
        if attempts < threshold:
            continue

        severity = _severity_from_attempts(attempts)
        usernames = sorted(users_by_ip[source_ip])
        invalid_user_attempts = invalid_users_by_ip[source_ip]
        root_attempts = root_attempts_by_ip[source_ip]

        findings.append(
            Finding(
                id="LOG-SSH-001",
                title="Multiple failed SSH login attempts detected",
                severity=severity,
                category="LogGuard SSH",
                description=(
                    "Multiple failed SSH authentication attempts were observed "
                    "from the same source IP address."
                ),
                evidence=(
                    f"Source IP: {source_ip}\n"
                    f"Failed attempts: {attempts}\n"
                    f"Targeted users: {', '.join(usernames)}\n"
                    f"Invalid user attempts: {invalid_user_attempts}\n"
                    f"Root login attempts: {root_attempts}"
                ),
                recommendation=(
                    "Review the source IP, enforce SSH key authentication, disable password login, "
                    "restrict SSH access by IP, enable MFA where possible and consider fail2ban/rate limiting."
                ),
                target=target,
                framework="MITRE ATT&CK",
                mitre_tactic="Credential Access",
                mitre_technique="T1110 - Brute Force",
                metadata={
                    "source_ip": source_ip,
                    "failed_attempts": attempts,
                    "targeted_users": usernames,
                    "invalid_user_attempts": invalid_user_attempts,
                    "root_attempts": root_attempts,
                },
            )
        )

    return findings


def detect_invalid_user_activity(
    events: list[AuthEvent],
    target: str,
    threshold: int = 3,
) -> list[Finding]:
    invalid_events = [
        event
        for event in events
        if event.event_type == "failed_password" and event.is_invalid_user
    ]

    invalid_by_ip = Counter(event.source_ip for event in invalid_events)

    findings: list[Finding] = []

    for source_ip, attempts in invalid_by_ip.items():
        if attempts < threshold:
            continue

        findings.append(
            Finding(
                id="LOG-SSH-002",
                title="Multiple SSH attempts against invalid users",
                severity=Severity.MEDIUM,
                category="LogGuard SSH",
                description=(
                    "Several SSH authentication attempts targeted users that do not appear to exist."
                ),
                evidence=(
                    f"Source IP: {source_ip}\n"
                    f"Invalid user attempts: {attempts}"
                ),
                recommendation=(
                    "Investigate the source IP and verify whether user enumeration or automated scanning is occurring."
                ),
                target=target,
                framework="MITRE ATT&CK",
                mitre_tactic="Credential Access",
                mitre_technique="T1110 - Brute Force",
                metadata={
                    "source_ip": source_ip,
                    "invalid_user_attempts": attempts,
                },
            )
        )

    return findings


def detect_root_login_attempts(
    events: list[AuthEvent],
    target: str,
) -> list[Finding]:
    root_events = [
        event
        for event in events
        if event.event_type == "failed_password" and event.is_root_attempt
    ]

    root_by_ip = Counter(event.source_ip for event in root_events)

    findings: list[Finding] = []

    for source_ip, attempts in root_by_ip.items():
        findings.append(
            Finding(
                id="LOG-SSH-003",
                title="SSH root login attempts detected",
                severity=Severity.HIGH,
                category="LogGuard SSH",
                description="Failed SSH login attempts against the root account were detected.",
                evidence=(
                    f"Source IP: {source_ip}\n"
                    f"Root login attempts: {attempts}"
                ),
                recommendation=(
                    "Disable direct root SSH login and require named user accounts with privilege escalation."
                ),
                target=target,
                framework="MITRE ATT&CK",
                mitre_tactic="Credential Access",
                mitre_technique="T1110 - Brute Force",
                metadata={
                    "source_ip": source_ip,
                    "root_attempts": attempts,
                },
            )
        )

    return findings