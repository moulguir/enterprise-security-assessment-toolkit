from pathlib import Path

from sec_assess.modules.logguard.detectors.ssh_bruteforce import (
    detect_invalid_user_activity,
    detect_root_login_attempts,
    detect_ssh_bruteforce,
)
from sec_assess.modules.logguard.log_scanner import LogGuardScanner
from sec_assess.modules.logguard.parsers.linux_auth import parse_linux_auth_log


SAMPLE_LOG = """
May 17 10:01:01 server sshd[1001]: Failed password for invalid user admin from 185.23.44.10 port 51234 ssh2
May 17 10:01:05 server sshd[1002]: Failed password for invalid user test from 185.23.44.10 port 51235 ssh2
May 17 10:01:09 server sshd[1003]: Failed password for root from 185.23.44.10 port 51236 ssh2
May 17 10:01:14 server sshd[1004]: Failed password for invalid user oracle from 185.23.44.10 port 51237 ssh2
May 17 10:01:18 server sshd[1005]: Failed password for invalid user postgres from 185.23.44.10 port 51238 ssh2
May 17 10:01:22 server sshd[1006]: Failed password for invalid user deploy from 185.23.44.10 port 51239 ssh2
May 17 10:05:10 server sshd[1020]: Accepted password for mohamed from 192.168.1.25 port 50000 ssh2
"""


def test_parse_linux_auth_log_extracts_failed_and_accepted_events(tmp_path: Path):
    log_file = tmp_path / "auth.log"
    log_file.write_text(SAMPLE_LOG, encoding="utf-8")

    events = parse_linux_auth_log(str(log_file))

    assert len(events) == 7
    assert events[0].event_type == "failed_password"
    assert events[0].source_ip == "185.23.44.10"
    assert events[0].username == "admin"
    assert events[0].is_invalid_user is True
    assert events[2].is_root_attempt is True
    assert events[-1].event_type == "accepted_password"


def test_detect_ssh_bruteforce_generates_finding(tmp_path: Path):
    log_file = tmp_path / "auth.log"
    log_file.write_text(SAMPLE_LOG, encoding="utf-8")

    events = parse_linux_auth_log(str(log_file))
    findings = detect_ssh_bruteforce(
        events=events,
        target=str(log_file),
        threshold=5,
    )

    assert len(findings) == 1
    assert findings[0].id == "LOG-SSH-001"
    assert findings[0].metadata["source_ip"] == "185.23.44.10"
    assert findings[0].metadata["failed_attempts"] == 6


def test_detect_invalid_user_activity_generates_finding(tmp_path: Path):
    log_file = tmp_path / "auth.log"
    log_file.write_text(SAMPLE_LOG, encoding="utf-8")

    events = parse_linux_auth_log(str(log_file))
    findings = detect_invalid_user_activity(
        events=events,
        target=str(log_file),
        threshold=3,
    )

    assert len(findings) == 1
    assert findings[0].id == "LOG-SSH-002"


def test_detect_root_login_attempts_generates_finding(tmp_path: Path):
    log_file = tmp_path / "auth.log"
    log_file.write_text(SAMPLE_LOG, encoding="utf-8")

    events = parse_linux_auth_log(str(log_file))
    findings = detect_root_login_attempts(
        events=events,
        target=str(log_file),
    )

    assert len(findings) == 1
    assert findings[0].id == "LOG-SSH-003"


def test_logguard_scanner_returns_combined_findings(tmp_path: Path):
    log_file = tmp_path / "auth.log"
    log_file.write_text(SAMPLE_LOG, encoding="utf-8")

    scanner = LogGuardScanner()
    findings = scanner.scan_auth_log(
        file_path=str(log_file),
        threshold=5,
    )

    finding_ids = [finding.id for finding in findings]

    assert "LOG-SSH-001" in finding_ids
    assert "LOG-SSH-002" in finding_ids
    assert "LOG-SSH-003" in finding_ids