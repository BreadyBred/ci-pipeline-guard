from __future__ import annotations

import json
from pathlib import Path

import pytest

from cipguard.models import Finding, Severity
from cipguard.reporter import _calculate_score, render_json, render_table


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
    assert isinstance(data, list)
    assert len(data) == 1


def test_render_json_finding_fields_present(capsys: pytest.CaptureFixture) -> None:
    findings = [_finding("GHA-002", Severity.CRITICAL)]
    render_json({"fake.yml": findings})
    obj = json.loads(capsys.readouterr().out)[0]
    assert set(obj.keys()) >= {"rule_id", "severity", "file", "line", "finding", "recommendation"}


def test_render_json_empty_findings_returns_empty_list(capsys: pytest.CaptureFixture) -> None:
    render_json({"fake.yml": []})
    data = json.loads(capsys.readouterr().out)
    assert data == []


def test_render_json_multiple_files_all_flattened(capsys: pytest.CaptureFixture) -> None:
    render_json({
        "a.yml": [_finding("GHA-001", Severity.HIGH)],
        "b.yml": [_finding("GLC-001", Severity.CRITICAL)],
    })
    data = json.loads(capsys.readouterr().out)
    assert len(data) == 2


def test_render_json_writes_to_file(tmp_path: Path) -> None:
    out = tmp_path / "findings.json"
    render_json({"fake.yml": [_finding("GHA-001", Severity.HIGH)]}, str(out))
    data = json.loads(out.read_text(encoding="utf-8"))
    assert len(data) == 1
    assert data[0]["rule_id"] == "GHA-001"


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
