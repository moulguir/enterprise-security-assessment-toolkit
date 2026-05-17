import csv
from datetime import datetime
from pathlib import Path

from sec_assess.core.finding import Finding
from sec_assess.core.risk_engine import RiskEngine
from sec_assess.utils.url_utils import safe_filename_from_url


def generate_csv_rows(target: str, findings: list[Finding]) -> list[dict]:
    risk_engine = RiskEngine()
    score = risk_engine.calculate_score(findings)
    risk_level = risk_engine.classify_risk(score, findings)
    scan_date = datetime.now().isoformat(timespec="seconds")

    rows = []

    for finding in findings:
        rows.append(
            {
                "target": target,
                "scan_date": scan_date,
                "risk_score": score,
                "overall_risk": risk_level,
                "finding_id": finding.id,
                "title": finding.title,
                "severity": finding.severity.value,
                "category": finding.category,
                "framework": finding.framework or "",
                "mitre_tactic": finding.mitre_tactic or "",
                "mitre_technique": finding.mitre_technique or "",
                "evidence": finding.evidence,
                "recommendation": finding.recommendation,
            }
        )

    return rows


def save_csv_report(target: str, findings: list[Finding], output_dir: str = "reports") -> Path:
    Path(output_dir).mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{safe_filename_from_url(target)}_{timestamp}.csv"
    output_path = Path(output_dir) / filename

    fieldnames = [
        "target",
        "scan_date",
        "risk_score",
        "overall_risk",
        "finding_id",
        "title",
        "severity",
        "category",
        "framework",
        "mitre_tactic",
        "mitre_technique",
        "evidence",
        "recommendation",
    ]

    rows = generate_csv_rows(target, findings)

    with output_path.open("w", encoding="utf-8", newline="") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    return output_path