import json
from pathlib import Path

from sec_assess.core.finding import Finding
from sec_assess.core.severity import Severity
from sec_assess.reporting.csv_report import generate_csv_rows, save_csv_report
from sec_assess.reporting.json_report import generate_json_report, save_json_report
from sec_assess.reporting.markdown_report import (
    generate_markdown_report,
    get_priority_findings,
    save_markdown_report,
    sort_findings_by_severity,
)


def make_finding(
    finding_id: str = "TEST-001",
    severity: Severity = Severity.MEDIUM,
) -> Finding:
    return Finding(
        id=finding_id,
        title="Test finding",
        severity=severity,
        category="Test Category",
        description="Test description",
        evidence="Test evidence",
        recommendation="Test recommendation",
        target="https://example.com",
        framework="OWASP ASVS",
    )


def test_generate_markdown_report_contains_enterprise_sections():
    findings = [make_finding()]

    report = generate_markdown_report("https://example.com", findings)

    assert "# Security Assessment Report" in report
    assert "## Executive Summary" in report
    assert "## Priority Findings" in report
    assert "## Technical Findings" in report
    assert "TEST-001 - Test finding" in report


def test_sort_findings_by_severity_orders_critical_first():
    findings = [
        make_finding("LOW-001", Severity.LOW),
        make_finding("CRIT-001", Severity.CRITICAL),
        make_finding("HIGH-001", Severity.HIGH),
    ]

    sorted_findings = sort_findings_by_severity(findings)

    assert sorted_findings[0].severity == Severity.CRITICAL
    assert sorted_findings[1].severity == Severity.HIGH
    assert sorted_findings[2].severity == Severity.LOW


def test_get_priority_findings_excludes_low_and_info():
    findings = [
        make_finding("INFO-001", Severity.INFO),
        make_finding("LOW-001", Severity.LOW),
        make_finding("MED-001", Severity.MEDIUM),
        make_finding("HIGH-001", Severity.HIGH),
    ]

    priority_findings = get_priority_findings(findings)
    priority_ids = [finding.id for finding in priority_findings]

    assert "MED-001" in priority_ids
    assert "HIGH-001" in priority_ids
    assert "LOW-001" not in priority_ids
    assert "INFO-001" not in priority_ids


def test_generate_json_report_has_expected_fields():
    findings = [make_finding()]

    report = generate_json_report("https://example.com", findings)

    assert report["target"] == "https://example.com"
    assert report["risk_score"] == 92
    assert report["overall_risk"] == "MEDIUM"
    assert report["summary_by_severity"]["MEDIUM"] == 1
    assert report["findings"][0]["id"] == "TEST-001"


def test_generate_csv_rows_has_expected_fields():
    findings = [make_finding()]

    rows = generate_csv_rows("https://example.com", findings)

    assert len(rows) == 1
    assert rows[0]["target"] == "https://example.com"
    assert rows[0]["finding_id"] == "TEST-001"
    assert rows[0]["severity"] == "MEDIUM"
    assert rows[0]["risk_score"] == 92


def test_save_markdown_report_creates_file(tmp_path: Path):
    findings = [make_finding()]

    output_path = save_markdown_report(
        target="https://example.com",
        findings=findings,
        output_dir=str(tmp_path),
    )

    assert output_path.exists()
    assert output_path.suffix == ".md"
    assert "Security Assessment Report" in output_path.read_text(encoding="utf-8")


def test_save_json_report_creates_valid_json_file(tmp_path: Path):
    findings = [make_finding()]

    output_path = save_json_report(
        target="https://example.com",
        findings=findings,
        output_dir=str(tmp_path),
    )

    assert output_path.exists()
    assert output_path.suffix == ".json"

    data = json.loads(output_path.read_text(encoding="utf-8"))
    assert data["target"] == "https://example.com"


def test_save_csv_report_creates_file(tmp_path: Path):
    findings = [make_finding()]

    output_path = save_csv_report(
        target="https://example.com",
        findings=findings,
        output_dir=str(tmp_path),
    )

    assert output_path.exists()
    assert output_path.suffix == ".csv"
    assert "finding_id" in output_path.read_text(encoding="utf-8")