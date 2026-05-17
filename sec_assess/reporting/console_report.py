from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from sec_assess.core.finding import Finding
from sec_assess.core.risk_engine import RiskEngine


console = Console()


def print_scan_report(target: str, findings: list[Finding]) -> None:
    risk_engine = RiskEngine()
    score = risk_engine.calculate_score(findings)
    risk_level = risk_engine.classify_risk(score, findings)
    counts = risk_engine.count_by_severity(findings)

    console.print(
        Panel.fit(
            "[bold]Enterprise Security Assessment Toolkit[/bold]\n"
            f"Target: {target}\n"
            f"Risk Score: {score}/100\n"
            f"Overall Risk: {risk_level}",
            title="Security Assessment",
        )
    )

    summary_table = Table(title="Summary by Severity")
    summary_table.add_column("Severity", style="bold")
    summary_table.add_column("Count")

    for severity, count in counts.items():
        summary_table.add_row(severity, str(count))

    console.print(summary_table)

    findings_table = Table(title="Findings")
    findings_table.add_column("Severity")
    findings_table.add_column("ID")
    findings_table.add_column("Title")
    findings_table.add_column("Recommendation")

    for finding in findings:
        findings_table.add_row(
            finding.severity.value,
            finding.id,
            finding.title,
            finding.recommendation,
        )

    console.print(findings_table)