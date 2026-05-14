from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from cipguard.models import Finding, Severity
from cipguard.reporter import _calculate_score, _open_console, render_json, render_table


def _finding(rule_id: str, severity: Severity, line: int = 1) -> Finding:
    return Finding(
        rule_id=rule_id,
        severity=severity,
        file="fake.yml",
        line=line,
        finding="test finding",
        recommendation="test recommendation",
    )


# ---------------------------------------------------------------------------
# Score calculation
# ---------------------------------------------------------------------------


def test_score_no_findings_is_100() -> None:
    assert _calculate_score([]) == 100


def test_score_one_critical_subtracts_20() -> None:
    assert _calculate_score([_finding("X", Severity.CRITICAL)]) == 80


def test_score_one_high_subtracts_10() -> None:
    assert _calculate_score([_finding("X", Severity.HIGH)]) == 90


def test_score_one_medium_subtracts_5() -> None:
    assert _calculate_score([_finding("X", Severity.MEDIUM)]) == 95


def test_score_mixed_findings() -> None:
    findings = [
        _finding("A", Severity.CRITICAL),
        _finding("B", Severity.CRITICAL),
        _finding("C", Severity.HIGH),
        _finding("D", Severity.MEDIUM),
        _finding("E", Severity.MEDIUM),
    ]
    # 2*20 + 1*10 + 2*5 = 40 + 10 + 10 = 60 => 40
    assert _calculate_score(findings) == 40


def test_score_floors_at_zero() -> None:
    findings = [_finding("X", Severity.CRITICAL)] * 10
    assert _calculate_score(findings) == 0


# ---------------------------------------------------------------------------
# render_json
# ---------------------------------------------------------------------------


def test_render_json_stdout_is_valid_json(capsys: pytest.CaptureFixture) -> None:
    findings = [_finding("GHA-001", Severity.HIGH)]
    render_json({"fake.yml": findings})
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert isinstance(data, dict)
    assert "score" in data and "findings" in data
    assert len(data["findings"]) == 1


def test_render_json_finding_fields_present(capsys: pytest.CaptureFixture) -> None:
    findings = [_finding("GHA-002", Severity.CRITICAL)]
    render_json({"fake.yml": findings})
    obj = json.loads(capsys.readouterr().out)["findings"][0]
    assert set(obj.keys()) >= {"rule_id", "severity", "file", "line", "finding", "recommendation"}


def test_render_json_empty_findings_returns_score_100(capsys: pytest.CaptureFixture) -> None:
    render_json({"fake.yml": []})
    data = json.loads(capsys.readouterr().out)
    assert data == {"score": 100, "findings": []}


def test_render_json_multiple_files_all_flattened(capsys: pytest.CaptureFixture) -> None:
    render_json({
        "a.yml": [_finding("GHA-001", Severity.HIGH)],
        "b.yml": [_finding("GLC-001", Severity.CRITICAL)],
    })
    data = json.loads(capsys.readouterr().out)
    assert len(data["findings"]) == 2


def test_render_json_writes_to_file(tmp_path: Path) -> None:
    out = tmp_path / "findings.json"
    render_json({"fake.yml": [_finding("GHA-001", Severity.HIGH)]}, str(out))
    data = json.loads(out.read_text(encoding="utf-8"))
    assert len(data["findings"]) == 1
    assert data["findings"][0]["rule_id"] == "GHA-001"


# ---------------------------------------------------------------------------
# render_table
# ---------------------------------------------------------------------------


def test_render_table_runs_without_error() -> None:
    findings = [
        _finding("GHA-001", Severity.HIGH),
        _finding("GHA-002", Severity.CRITICAL),
    ]
    # Should not raise
    render_table({"fake.yml": findings})


def test_render_table_writes_to_file(tmp_path: Path) -> None:
    out = tmp_path / "report.txt"
    render_table({"fake.yml": [_finding("GHA-001", Severity.HIGH)]}, str(out))
    content = out.read_text(encoding="utf-8")
    assert "GHA-001" in content
    assert "Pipeline Security Score" in content


def test_render_table_no_findings_file(tmp_path: Path) -> None:
    out = tmp_path / "report.txt"
    render_table({"clean.yml": []}, str(out))
    content = out.read_text(encoding="utf-8")
    assert "No findings" in content


# ---------------------------------------------------------------------------
# _open_console — file handle safety
# ---------------------------------------------------------------------------


def test_open_console_closes_handle_if_console_raises(tmp_path: Path) -> None:
    """If Console() raises after the file is opened, the handle must be closed."""
    out = tmp_path / "out.txt"
    with patch("cipguard.reporter.Console", side_effect=RuntimeError("boom")):
        with pytest.raises(RuntimeError, match="boom"):
            _open_console(str(out))
    # On Windows an open file handle prevents deletion; if we can write to the
    # same path again the handle was properly closed.
    out.write_text("ok", encoding="utf-8")
    assert out.read_text(encoding="utf-8") == "ok"


# ---------------------------------------------------------------------------
# Rich markup injection defence
# ---------------------------------------------------------------------------


def test_render_table_escapes_rich_markup_in_finding_text(tmp_path: Path) -> None:
    """A finding whose text contains Rich markup chars must appear literally, not injected."""
    out = tmp_path / "report.txt"
    poisoned = Finding(
        rule_id="GHA-005",
        severity=Severity.MEDIUM,
        file="fake.yml",
        line=1,
        finding="Job '[bold red]evil[/bold red]' has continue-on-error: true",
        recommendation="Fix it",
    )
    render_table({"fake.yml": [poisoned]}, str(out))
    content = out.read_text(encoding="utf-8")
    # '[bold' must appear literally in output (the opening bracket was not consumed as
    # markup), proving escape() was applied.  The full long string wraps across narrow
    # table cells so we only assert on the unambiguous prefix.
    assert "[bold" in content


def test_render_table_escapes_rich_markup_in_filename(tmp_path: Path) -> None:
    """A file path whose name contains markup chars must appear literally."""
    out = tmp_path / "report.txt"
    f = _finding("GHA-001", Severity.HIGH)
    # Use an opening-tag-only attack: '[red]' in the basename has no '/' so
    # Path.name returns the full component and escape() must sanitise it.
    # Without escape(), Rich consumes '[red]' as markup and the literal brackets
    # vanish from the output; with escape() they must appear as plain text.
    poisoned = f.model_copy(update={"file": "/repo/exploit[red].yml"})
    render_table({"/repo/exploit[red].yml": [poisoned]}, str(out))
    content = out.read_text(encoding="utf-8")
    assert "exploit[red]" in content
