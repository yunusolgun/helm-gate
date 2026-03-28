from rich.console import Console
from rich.table import Table
from rich import box
from .rules import Finding, Severity

console = Console()

_SEVERITY_COLOR = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}


def print_report(findings: list[Finding], chart_path: str) -> None:
    if not findings:
        console.print(f"\n[bold green]✓ No issues found in {chart_path}[/bold green]\n")
        return

    table = Table(box=box.ROUNDED, show_lines=True)
    table.add_column("ID", style="bold", no_wrap=True)
    table.add_column("Severity", no_wrap=True)
    table.add_column("File", style="dim")
    table.add_column("Message")
    table.add_column("Hint", style="dim")

    for f in sorted(findings, key=lambda x: list(Severity).index(x.severity)):
        color = _SEVERITY_COLOR[f.severity]
        table.add_row(
            f.rule_id,
            f"[{color}]{f.severity.value}[/{color}]",
            f.path,
            f.message,
            f.line_hint,
        )

    console.print()
    console.print(table)
    _print_summary(findings)


def _print_summary(findings: list[Finding]) -> None:
    counts: dict[Severity, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    parts = []
    for sev in Severity:
        if sev in counts:
            color = _SEVERITY_COLOR[sev]
            parts.append(f"[{color}]{counts[sev]} {sev.value}[/{color}]")

    console.print(f"  Found {len(findings)} issue(s): " + "  ".join(parts) + "\n")
