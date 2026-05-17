import json
from datetime import datetime
from pathlib import Path

from sec_assess.core.finding import Finding
from sec_assess.core.risk_engine import RiskEngine
from sec_assess.utils.url_utils import safe_filename_from_url


def generate_json_report(target: str, findings: list[Finding]) -> dict:
    risk_engine = RiskEngine()
    score = risk_engine.calculate_score(findings)
    risk_level = risk_engine.classify_risk(score, findings)
    counts = risk_engine.count_by_severity(findings)

    return {
        "target": target,
        "scan_date": datetime.now().isoformat(timespec="seconds"),
        "risk_score": score,
        "overall_risk": risk_level,
        "summary_by_severity": counts,
        "findings": [finding.to_dict() for finding in findings],
    }


def save_json_report(target: str, findings: list[Finding], output_dir: str = "reports") -> Path:
    Path(output_dir).mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{safe_filename_from_url(target)}_{timestamp}.json"
    output_path = Path(output_dir) / filename

    report_data = generate_json_report(target, findings)

    output_path.write_text(
        json.dumps(report_data, indent=4, ensure_ascii=False),
        encoding="utf-8",
    )

    return output_path