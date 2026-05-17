from datetime import datetime
from pathlib import Path

from sec_assess.core.finding import Finding
from sec_assess.core.risk_engine import RiskEngine
from sec_assess.utils.url_utils import safe_filename_from_url


def generate_markdown_report(target: str, findings: list[Finding]) -> str:
    risk_engine = RiskEngine()
    score = risk_engine.calculate_score(findings)
    risk_level = risk_engine.classify_risk(score)
    counts = risk_engine.count_by_severity(findings)

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
            "## Technical Findings",
            "",
        ]
    )

    if not findings:
        lines.append("No findings were detected.")
    else:
        for finding in findings:
            lines.extend(
                [
                    f"### {finding.id} - {finding.title}",
                    "",
                    f"- **Severity:** {finding.severity.value}",
                    f"- **Category:** {finding.category}",
                    f"- **Target:** `{finding.target}`",
                    f"- **Framework:** {finding.framework or 'N/A'}",
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