from enum import Enum

import typer
from rich.console import Console

from sec_assess.config import ReportFormat, load_config
from sec_assess.core.risk_engine import RiskEngine
from sec_assess.modules.web_security.web_scanner import WebSecurityScanner
from sec_assess.reporting.console_report import print_scan_report
from sec_assess.reporting.json_report import save_json_report
from sec_assess.reporting.markdown_report import save_markdown_report
from sec_assess.utils.url_utils import normalize_url
from sec_assess.reporting.csv_report import save_csv_report
from sec_assess.modules.host_exposure.host_scanner import HostExposureScanner
from sec_assess.modules.logguard.log_scanner import LogGuardScanner


console = Console()


class OutputFormat(str, Enum):
    console = "console"
    markdown = "markdown"
    json = "json"
    csv = "csv"


app = typer.Typer(
    help="Enterprise Security Assessment Toolkit - Defensive security assessment CLI."
)

scan_app = typer.Typer(help="Run security scans.")
app.add_typer(scan_app, name="scan")
analyze_app = typer.Typer(help="Analyze security data sources.")
app.add_typer(analyze_app, name="analyze")

def handle_report_output(
    target: str,
    findings: list,
    output_format: str,
    output_dir: str = "reports",
) -> None:
    if output_format == "console":
        print_scan_report(target=target, findings=findings)
        return

    if output_format == "markdown":
        output_path = save_markdown_report(
            target=target,
            findings=findings,
            output_dir=output_dir,
        )
        console.print(f"[green]Markdown report generated:[/green] {output_path}")
        return

    if output_format == "json":
        output_path = save_json_report(
            target=target,
            findings=findings,
            output_dir=output_dir,
        )
        console.print(f"[green]JSON report generated:[/green] {output_path}")
        return

    if output_format == "csv":
        output_path = save_csv_report(
            target=target,
            findings=findings,
            output_dir=output_dir,
        )
        console.print(f"[green]CSV report generated:[/green] {output_path}")
        return

    raise typer.BadParameter(f"Unsupported output format: {output_format}")

@scan_app.command("web")
def scan_web(
    url: str = typer.Option(..., "--url", "-u", help="Target URL to scan."),
    timeout: int = typer.Option(10, "--timeout", help="HTTP request timeout in seconds."),
    output_format: OutputFormat = typer.Option(
        OutputFormat.console,
        "--format",
        "-f",
        help="Output format: console, markdown, json or csv.",
    ),
    output_dir: str = typer.Option(
        "reports",
        "--output-dir",
        help="Directory where reports are saved.",
    ),
):
    """
    Run a web security baseline scan.
    """
    target = normalize_url(url)
    scanner = WebSecurityScanner(timeout=timeout)
    findings = scanner.scan(target)

    handle_report_output(
        target=target,
        findings=findings,
        output_format=output_format.value,
        output_dir=output_dir,
    )

@scan_app.command("host")
def scan_host(
    target: str = typer.Option(..., "--target", "-t", help="Target host or IP to scan."),
    ports: str = typer.Option(
        "common",
        "--ports",
        "-p",
        help="Ports to scan. Use 'common', a comma list like 22,80,443, or a range like 1-1024.",
    ),
    timeout: float = typer.Option(
        1.0,
        "--timeout",
        help="TCP connection timeout in seconds.",
    ),
    output_format: OutputFormat = typer.Option(
        OutputFormat.console,
        "--format",
        "-f",
        help="Output format: console, markdown, json or csv.",
    ),
    output_dir: str = typer.Option(
        "reports",
        "--output-dir",
        help="Directory where reports are saved.",
    ),
    no_banner: bool = typer.Option(
        False,
        "--no-banner",
        help="Disable banner grabbing.",
    ),
):
    """
    Run a safe host exposure scan against authorized targets.
    """
    try:
        scanner = HostExposureScanner(
            timeout=timeout,
            enable_banner_grab=not no_banner,
        )
        findings = scanner.scan(
            target=target,
            ports=ports,
        )

    except ValueError as error:
        console.print(f"[red]Invalid port configuration:[/red] {error}")
        raise typer.Exit(code=1)

    handle_report_output(
        target=target,
        findings=findings,
        output_format=output_format.value,
        output_dir=output_dir,
    )
    
@app.command("run")
def run_from_config(
    config: str = typer.Option(
        ...,
        "--config",
        "-c",
        help="Path to YAML configuration file.",
    )
):
    """
    Run an assessment from a YAML configuration file.
    """
    try:
        app_config = load_config(config)
    except Exception as error:
        console.print(f"[red]Configuration error:[/red] {error}")
        raise typer.Exit(code=1)

    target = normalize_url(str(app_config.target.url))

    if app_config.scan.type == "web":
        scanner = WebSecurityScanner(timeout=app_config.scan.timeout)
        findings = scanner.scan(target)

        handle_report_output(
            target=target,
            findings=findings,
            output_format=app_config.report.format.value,
            output_dir=app_config.report.output_dir,
        )

        risk_engine = RiskEngine()
        score = risk_engine.calculate_score(findings)
        risk_level = risk_engine.classify_risk(score)

        if app_config.risk.fail_on_high and risk_level in ["HIGH", "CRITICAL"]:
            console.print(
                f"[red]Failing because risk level is {risk_level} and fail_on_high is enabled.[/red]"
            )
            raise typer.Exit(code=2)

        return

    console.print(f"[red]Unsupported scan type:[/red] {app_config.scan.type}")
    raise typer.Exit(code=1)

@analyze_app.command("logs")
def analyze_logs(
    file: str = typer.Option(..., "--file", "-f", help="Path to log file."),
    log_type: str = typer.Option(
        "linux-auth",
        "--type",
        help="Log type to analyze. Currently supported: linux-auth.",
    ),
    threshold: int = typer.Option(
        5,
        "--threshold",
        help="Minimum failed attempts from one IP to generate brute-force finding.",
    ),
    output_format: OutputFormat = typer.Option(
        OutputFormat.console,
        "--format",
        help="Output format: console, markdown, json or csv.",
    ),
    output_dir: str = typer.Option(
        "reports",
        "--output-dir",
        help="Directory where reports are saved.",
    ),
):
    """
    Analyze security logs and generate defensive findings.
    """
    if log_type != "linux-auth":
        console.print(f"[red]Unsupported log type:[/red] {log_type}")
        raise typer.Exit(code=1)

    try:
        scanner = LogGuardScanner()
        findings = scanner.scan_auth_log(
            file_path=file,
            threshold=threshold,
        )

    except FileNotFoundError as error:
        console.print(f"[red]Log file error:[/red] {error}")
        raise typer.Exit(code=1)

    handle_report_output(
        target=file,
        findings=findings,
        output_format=output_format.value,
        output_dir=output_dir,
    )
    
if __name__ == "__main__":
    app()