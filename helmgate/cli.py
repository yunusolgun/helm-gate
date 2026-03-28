import sys
from pathlib import Path

import typer
from rich.console import Console

from .scanner import scan
from .report import print_report
from .license import is_pro, activate as activate_license
from . import __version__

app = typer.Typer(
    name="helmgate",
    help="Helm chart linter and policy enforcement tool.",
    add_completion=False,
)
console = Console()


@app.command(name="scan")
def scan_cmd(
    chart: Path = typer.Argument(..., help="Path to the Helm chart directory."),
    fail_on: str = typer.Option(
        "CRITICAL",
        "--fail-on",
        help="Exit with code 1 if findings at or above this severity exist. "
             "Choices: CRITICAL, HIGH, MEDIUM, LOW, INFO, NONE",
    ),
    output: str = typer.Option("table", "--output", "-o", help="Output format: table, json"),
):
    """Scan a Helm chart for security and best-practice issues."""
    if not chart.is_dir():
        console.print(f"[red]Error:[/red] '{chart}' is not a directory.")
        raise typer.Exit(1)

    pro = is_pro()

    if output == "json" and not pro:
        console.print(
            "[yellow]JSON output requires a Pro license.[/yellow]\n"
            "Activate with: [bold]helmgate activate <key>[/bold]\n"
            "Get a license key: [bold]yunus.olgun@outlook.com[/bold]"
        )
        raise typer.Exit(1)

    from .rules import ALL_RULES, FREE_RULES
    rules = ALL_RULES if pro else FREE_RULES

    if not pro:
        hidden = len(ALL_RULES) - len(FREE_RULES)
        console.print(
            f"[dim]Free tier: scanning with CRITICAL and HIGH rules only "
            f"({hidden} MEDIUM/LOW rules hidden). "
            f"Upgrade at helmgate.io/pricing[/dim]\n"
        )

    findings = scan(chart, rules=rules)

    if output == "json":
        import json
        data = [
            {
                "rule_id": f.rule_id,
                "severity": f.severity.value,
                "path": f.path,
                "message": f.message,
                "hint": f.line_hint,
            }
            for f in findings
        ]
        print(json.dumps(data, indent=2))
    else:
        print_report(findings, str(chart))

    if not pro and findings:
        console.print(
            "\n[dim]Upgrade to Pro to scan with all rules and export JSON reports.[/dim]"
        )

    if fail_on != "NONE":
        from .rules import Severity
        try:
            threshold = Severity(fail_on)
        except ValueError:
            console.print(f"[red]Unknown severity:[/red] {fail_on}")
            raise typer.Exit(1)

        severity_order = list(Severity)
        threshold_idx = severity_order.index(threshold)
        should_fail = any(
            severity_order.index(f.severity) <= threshold_idx for f in findings
        )
        if should_fail:
            raise typer.Exit(1)


@app.command()
def activate(
    key: str = typer.Argument(..., help="Your Pro license key (format: HGATE-XXXX-XXXX-XXXX-XXXX)"),
):
    """Activate a Pro license key."""
    if activate_license(key):
        console.print(f"[green]License activated![/green] helmgate Pro is now enabled.")
    else:
        console.print(
            "[red]Invalid license key.[/red] "
            "Check the key and try again, or visit helmgate.io/pricing"
        )
        raise typer.Exit(1)


@app.command()
def version():
    """Show helmgate version."""
    tier = "Pro" if is_pro() else "Free"
    console.print(f"helmgate v{__version__} [{tier}]")


if __name__ == "__main__":
    app()
