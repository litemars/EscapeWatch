from __future__ import annotations

from io import StringIO
from typing import TextIO

from escapewatch.models import AssessmentResult, Category, Finding, Severity

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text

    HAS_RICH = True
except ImportError:
    HAS_RICH = False

SEVERITY_COLORS = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}

SEVERITY_ICONS = {
    Severity.CRITICAL: "[!!]",
    Severity.HIGH: "[!] ",
    Severity.MEDIUM: "[~] ",
    Severity.LOW: "[.] ",
    Severity.INFO: "[i] ",
}

GRADE_COLORS = {
    "A": "bold green",
    "B": "green",
    "C": "yellow",
    "D": "red",
    "F": "bold red",
}


class TerminalFormatter:
    """Format assessment results for terminal display."""

    def __init__(self, compact: bool = False, no_color: bool = False) -> None:
        self.compact = compact
        self.no_color = no_color

    def format(self, result: AssessmentResult) -> str:
        if HAS_RICH and not self.no_color:
            return self._format_rich(result)
        return self._format_plain(result)

    def write(self, result: AssessmentResult, output: TextIO) -> None:
        output.write(self.format(result))

    def _format_rich(self, result: AssessmentResult) -> str:
        # Write to a throwaway StringIO so nothing leaks to stdout while
        # recording.  The old code used `force_terminal=True` with no
        # explicit `file`, which made Rich write to sys.stdout *and*
        # record — then cli.py called `print(output_text)`, duplicating
        # the entire report.
        console = Console(record=True, width=100, force_terminal=True, file=StringIO())

        # Banner
        console.print()
        console.print(
            Panel(
                "[bold blue]EscapeWatch[/bold blue] — Container Escape Risk Assessment",
                border_style="blue",
            )
        )

        # Environment
        env = result.environment
        env_table = Table(title="Environment", show_header=False, border_style="dim")
        env_table.add_column("Key", style="bold")
        env_table.add_column("Value")
        env_table.add_row("Context", env.summary)
        env_table.add_row("Kernel", env.kernel_version)
        env_table.add_row("Hostname", env.hostname)
        env_table.add_row("cgroup", env.cgroup_version or "unknown")
        env_table.add_row("Init", env.init_process or "unknown")
        if env.container_id:
            env_table.add_row("Container ID", env.container_id[:16] + "...")
        console.print(env_table)
        console.print()

        # Summary
        grade_color = GRADE_COLORS.get(result.grade, "white")
        console.print(
            f"  Risk Score: [bold]{result.total_score:.0f}[/bold]  "
            f"Grade: [{grade_color}]{result.grade}[/{grade_color}]  "
            f"Findings: [bold]{len(result.findings)}[/bold]"
        )
        console.print()

        if not result.findings:
            console.print("  [bold green]No escape-risk findings detected.[/bold green]")
            console.print()
            return console.export_text()

        # Category breakdown
        cat_scores = result.category_scores()
        if cat_scores:
            cat_table = Table(title="Category Breakdown", border_style="dim")
            cat_table.add_column("Category", style="bold")
            cat_table.add_column("Findings", justify="right")
            cat_table.add_column("Score", justify="right")
            for cat, cs in sorted(cat_scores.items(), key=lambda x: -x[1].total_score):
                cat_table.add_row(cat.value, str(cs.finding_count), f"{cs.total_score:.0f}")
            console.print(cat_table)
            console.print()

        # Findings
        sorted_findings = sorted(result.findings, key=lambda f: -f.weighted_score)

        for f in sorted_findings:
            sev_color = SEVERITY_COLORS[f.severity]
            icon = SEVERITY_ICONS[f.severity]
            console.print(
                f"  [{sev_color}]{icon} {f.id} — {f.title}[/{sev_color}]"
            )
            console.print(
                f"     Severity: [{sev_color}]{f.severity.value}[/{sev_color}]  "
                f"Confidence: {f.confidence.value}  "
                f"Score: {f.weighted_score:.0f}"
            )
            console.print(f"     Evidence: {f.evidence}")
            if not self.compact:
                console.print(f"     Impact: {f.why_it_matters}")
                console.print(f"     Fix: {f.remediation}")
                if f.references:
                    console.print(f"     Ref: {f.references[0]}")
            console.print()

        return console.export_text()

    def _format_plain(self, result: AssessmentResult) -> str:
        lines: list[str] = []

        lines.append("")
        lines.append("=" * 70)
        lines.append("  EscapeWatch — Container Escape Risk Assessment")
        lines.append("=" * 70)
        lines.append("")

        # Environment
        env = result.environment
        lines.append(f"  Context:      {env.summary}")
        lines.append(f"  Kernel:       {env.kernel_version}")
        lines.append(f"  Hostname:     {env.hostname}")
        lines.append(f"  cgroup:       {env.cgroup_version or 'unknown'}")
        lines.append(f"  Init:         {env.init_process or 'unknown'}")
        lines.append("")

        # Summary
        lines.append(
            f"  Risk Score: {result.total_score:.0f}  "
            f"Grade: {result.grade}  "
            f"Findings: {len(result.findings)}"
        )
        lines.append("")

        if not result.findings:
            lines.append("  No escape-risk findings detected.")
            lines.append("")
            return "\n".join(lines)

        lines.append("-" * 70)

        sorted_findings = sorted(result.findings, key=lambda f: -f.weighted_score)
        for f in sorted_findings:
            icon = SEVERITY_ICONS[f.severity]
            lines.append(f"  {icon} {f.id} — {f.title}")
            lines.append(
                f"     Severity: {f.severity.value}  "
                f"Confidence: {f.confidence.value}  "
                f"Score: {f.weighted_score:.0f}"
            )
            lines.append(f"     Evidence: {f.evidence}")
            if not self.compact:
                lines.append(f"     Impact: {f.why_it_matters}")
                lines.append(f"     Fix: {f.remediation}")
            lines.append("")

        return "\n".join(lines)
