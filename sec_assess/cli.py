from enum import Enum

import typer
from rich.console import Console

from sec_assess.modules.web_security.web_scanner import WebSecurityScanner
from sec_assess.reporting.console_report import print_scan_report
from sec_assess.reporting.json_report import save_json_report
from sec_assess.reporting.markdown_report import save_markdown_report
from sec_assess.utils.url_utils import normalize_url


console = Console()


class OutputFormat(str, Enum):
    console = "console"
    markdown = "markdown"
    json = "json"


app = typer.Typer(
    help="Enterprise Security Assessment Toolkit - Defensive security assessment CLI."
)

scan_app = typer.Typer(help="Run security scans.")
app.add_typer(scan_app, name="scan")


@scan_app.command("web")
def scan_web(
    url: str = typer.Option(..., "--url", "-u", help="Target URL to scan."),
    timeout: int = typer.Option(10, "--timeout", help="HTTP request timeout in seconds."),
    output_format: OutputFormat = typer.Option(
        OutputFormat.console,
        "--format",
        "-f",
        help="Output format: console, markdown or json.",
    ),
):
    """
    Run a web security baseline scan.
    """
    target = normalize_url(url)
    scanner = WebSecurityScanner(timeout=timeout)
    findings = scanner.scan(target)

    if output_format == OutputFormat.console:
        print_scan_report(target=target, findings=findings)
        return

    if output_format == OutputFormat.markdown:
        output_path = save_markdown_report(target=target, findings=findings)
        console.print(f"[green]Markdown report generated:[/green] {output_path}")
        return

    if output_format == OutputFormat.json:
        output_path = save_json_report(target=target, findings=findings)
        console.print(f"[green]JSON report generated:[/green] {output_path}")
        return


if __name__ == "__main__":
    app()