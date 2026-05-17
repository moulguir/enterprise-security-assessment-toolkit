from datetime import datetime
from pathlib import Path

from sec_assess.core.finding import Finding
from sec_assess.core.risk_engine import RiskEngine
from sec_assess.utils.url_utils import safe_filename_from_url


SEVERITY_ORDER = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
    "INFO": 4,
}


def sort_findings_by_severity(findings: list[Finding]) -> list[Finding]:
    return sorted(
        findings,
        key=lambda finding: SEVERITY_ORDER.get(finding.severity.value, 99),
    )

def _format_compliance_metadata(finding: Finding) -> list[str]:
    compliance = finding.metadata.get("compliance", {})

    if not compliance:
        return ["  - N/A"]

    lines = []

    mitre = compliance.get("mitre_attack")
    if mitre:
        lines.append(
            f"  - MITRE ATT&CK: {mitre.get('tactic')} / {mitre.get('technique')}"
        )

    owasp = compliance.get("owasp_asvs")
    if owasp:
        lines.append(
            f"  - OWASP ASVS {owasp.get('version')}: {owasp.get('control_area')}"
        )

    nist = compliance.get("nist_csf")
    if nist:
        lines.append(
            f"  - NIST CSF: {nist.get('function')} / {nist.get('category')}"
        )

    return lines
def get_priority_findings(findings: list[Finding]) -> list[Finding]:
    return [
        finding
        for finding in sort_findings_by_severity(findings)
        if finding.severity.value in ["CRITICAL", "HIGH", "MEDIUM"]
    ]


def generate_markdown_report(target: str, findings: list[Finding]) -> str:
    risk_engine = RiskEngine()
    score = risk_engine.calculate_score(findings)
    risk_level = risk_engine.classify_risk(score, findings)
    counts = risk_engine.count_by_severity(findings)

    sorted_findings = sort_findings_by_severity(findings)
    priority_findings = get_priority_findings(findings)

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    lines = [
        "# Security Assessment Report",
        "",
        "## Executive Summary",
        "",
        f"- **Target:** `{target}`",
        f"- **Scan date:** {now}",
        f"- **Risk score:** {score}/100",
        f"- **Overall risk:** {risk_level}",
        f"- **Total findings:** {len(findings)}",
        "",
        "## Findings by Severity",
        "",
        "| Severity | Count |",
        "|---|---:|",
    ]

    for severity, count in counts.items():
        lines.append(f"| {severity} | {count} |")

    lines.extend(
        [
            "",
            "## Priority Findings",
            "",
        ]
    )

    if not priority_findings:
        lines.append("No priority findings were detected.")
        lines.append("")
    else:
        lines.extend(
            [
                "| Severity | ID | Title | Recommendation |",
                "|---|---|---|---|",
            ]
        )

        for finding in priority_findings:
            recommendation = finding.recommendation.replace("\n", " ")
            lines.append(
                f"| {finding.severity.value} | {finding.id} | {finding.title} | {recommendation} |"
            )

        lines.append("")

    lines.extend(
        [
            "## Technical Findings",
            "",
        ]
    )

    if not sorted_findings:
        lines.append("No findings were detected.")
    else:
        for finding in sorted_findings:
            lines.extend(
    [
        f"### {finding.id} - {finding.title}",
        "",
        f"- **Severity:** {finding.severity.value}",
        f"- **Category:** {finding.category}",
        f"- **Target:** `{finding.target}`",
        f"- **Framework:** {finding.framework or 'N/A'}",
        f"- **MITRE tactic:** {finding.mitre_tactic or 'N/A'}",
        f"- **MITRE technique:** {finding.mitre_technique or 'N/A'}",
        f"- **Compliance mappings:**",
        *_format_compliance_metadata(finding),
        "",
        "**Description**",
        "",
        finding.description,
        "",
        "**Evidence**",
        "",
        f"```text\n{finding.evidence}\n```",
        "",
        "**Recommendation**",
        "",
        finding.recommendation,
        "",
        "---",
        "",
    ]
)

    lines.extend(
        [
            "## Security Notice",
            "",
            "This report was generated for defensive security and authorized assessment purposes only.",
            "",
        ]
    )

    return "\n".join(lines)


def save_markdown_report(target: str, findings: list[Finding], output_dir: str = "reports") -> Path:
    Path(output_dir).mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{safe_filename_from_url(target)}_{timestamp}.md"
    output_path = Path(output_dir) / filename

    report_content = generate_markdown_report(target, findings)
    output_path.write_text(report_content, encoding="utf-8")

    return output_path