from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import TextIO

from rich import box
from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table

from cipguard.models import Finding, Severity, SEVERITY_WEIGHTS


_SEVERITY_STYLE: dict[Severity, str] = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "yellow",
    Severity.MEDIUM: "cyan",
}

_SEVERITY_ORDER = list(Severity)


def _calculate_score(findings: list[Finding]) -> int:
    penalty = sum(SEVERITY_WEIGHTS[f.severity] for f in findings)
    return max(0, 100 - penalty)


def _score_style(score: int) -> str:
    if score >= 80:
        return "bold green"
    if score >= 50:
        return "bold yellow"
    return "bold red"


def _severity_counts(findings: list[Finding]) -> dict[Severity, int]:
    return {s: sum(1 for f in findings if f.severity == s) for s in Severity}


def _open_console(output_file: str | None) -> tuple[Console, TextIO | None]:
    if output_file:
        fh: TextIO = open(output_file, "w", encoding="utf-8")
        try:
            return Console(file=fh, highlight=False), fh
        except Exception:
            fh.close()
            raise
    encoding = getattr(sys.stdout, "encoding", "utf-8") or "utf-8"
    try:
        "─".encode(encoding)
        safe_box = False
    except (UnicodeEncodeError, LookupError):
        safe_box = True
    return Console(highlight=False, safe_box=safe_box), None


def render_table(
    findings_by_file: dict[str, list[Finding]],
    output_file: str | None = None,
) -> None:
    console, fh = _open_console(output_file)
    all_findings: list[Finding] = []

    try:
        for file_path, findings in findings_by_file.items():
            all_findings.extend(findings)
            counts = _severity_counts(findings)

            # escape filename in case it contains Rich markup characters
            safe_name = escape(Path(file_path).name)
            summary = (
                f"[bold]{safe_name}[/bold]   "
                f"findings: [bold]{len(findings)}[/bold]   "
                f"[bold red]CRITICAL {counts[Severity.CRITICAL]}[/bold red]   "
                f"[yellow]HIGH {counts[Severity.HIGH]}[/yellow]   "
                f"[cyan]MEDIUM {counts[Severity.MEDIUM]}[/cyan]"
            )
            console.print(Panel(summary, expand=False, border_style="dim"))

            if not findings:
                console.print("[green]  No findings.[/green]\n")
                continue

            table = Table(box=box.ROUNDED, show_lines=True, expand=True, padding=(0, 1))
            table.add_column("Rule ID", style="bold", no_wrap=True, width=9)
            table.add_column("Severity", no_wrap=True, width=10)
            table.add_column("Location", no_wrap=True, width=24)
            table.add_column("Finding", ratio=2)
            table.add_column("Recommendation", ratio=3)

            sorted_findings = sorted(
                findings,
                key=lambda f: (_SEVERITY_ORDER.index(f.severity), f.rule_id),
            )
            for finding in sorted_findings:
                style = _SEVERITY_STYLE[finding.severity]
                raw_loc = (
                    f"{Path(finding.file).name}:{finding.line}"
                    if finding.line
                    else Path(finding.file).name
                )
                table.add_row(
                    finding.rule_id,
                    f"[{style}]{finding.severity.value}[/{style}]",
                    escape(raw_loc),
                    escape(finding.finding),
                    escape(finding.recommendation),
                )

            console.print(table)
            console.print()

        score = _calculate_score(all_findings)
        style = _score_style(score)
        console.rule(style="dim")
        console.print(
            f"[bold]Pipeline Security Score:[/bold] [{style}]{score}/100[/{style}]",
            justify="center",
        )
        console.print()
    finally:
        if fh:
            fh.close()


def render_json(
    findings_by_file: dict[str, list[Finding]],
    output_file: str | None = None,
) -> None:
    all_findings = [f for findings in findings_by_file.values() for f in findings]
    score = _calculate_score(all_findings)
    payload = json.dumps(
        {"score": score, "findings": [f.model_dump() for f in all_findings]},
        indent=2,
        default=str,
    )
    if output_file:
        Path(output_file).write_text(payload, encoding="utf-8")
    else:
        print(payload)
