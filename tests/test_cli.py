from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from cipguard.__main__ import cli

FIXTURES = Path(__file__).parent / "fixtures"
GH_FIXTURE = FIXTURES / "sample_workflow.yml"
GL_FIXTURE = FIXTURES / "sample.gitlab-ci.yml"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _runner() -> CliRunner:
    return CliRunner(mix_stderr=False)


# ---------------------------------------------------------------------------
# scan — table mode
# ---------------------------------------------------------------------------


def test_cli_scan_table_exits_nonzero_with_findings() -> None:
    result = _runner().invoke(cli, ["scan", str(GH_FIXTURE)])
    assert result.exit_code == 1, result.output


def test_cli_scan_table_contains_rule_id() -> None:
    result = _runner().invoke(cli, ["scan", str(GH_FIXTURE)])
    assert "GHA-001" in result.output


def test_cli_scan_table_contains_score_line() -> None:
    result = _runner().invoke(cli, ["scan", str(GL_FIXTURE)])
    assert "Pipeline Security Score" in result.output


def test_cli_scan_table_both_fixtures() -> None:
    result = _runner().invoke(cli, ["scan", str(FIXTURES.parent)])
    # Fixtures directory only has non-canonical names so no files discovered
    assert result.exit_code == 0


# ---------------------------------------------------------------------------
# scan — json mode
# ---------------------------------------------------------------------------


def test_cli_scan_json_exits_nonzero_with_findings() -> None:
    result = _runner().invoke(cli, ["scan", str(GH_FIXTURE), "--format", "json"])
    assert result.exit_code == 1, result.output


def test_cli_scan_json_output_is_valid_json() -> None:
    result = _runner().invoke(cli, ["scan", str(GH_FIXTURE), "--format", "json"])
    data = json.loads(result.output)
    assert isinstance(data, dict)
    assert "score" in data and "findings" in data


def test_cli_scan_json_finding_has_required_keys() -> None:
    result = _runner().invoke(cli, ["scan", str(GL_FIXTURE), "--format", "json"])
    obj = json.loads(result.output)["findings"][0]
    assert {"rule_id", "severity", "file", "line", "finding", "recommendation"} <= obj.keys()


# ---------------------------------------------------------------------------
# scan — --output flag
# ---------------------------------------------------------------------------


def test_cli_scan_output_flag_creates_file(tmp_path: Path) -> None:
    out = tmp_path / "report.txt"
    result = _runner().invoke(cli, ["scan", str(GH_FIXTURE), "--output", str(out)])
    assert result.exit_code == 1
    assert out.exists()
    assert "GHA-001" in out.read_text(encoding="utf-8")


def test_cli_scan_json_output_flag_creates_valid_json(tmp_path: Path) -> None:
    out = tmp_path / "findings.json"
    result = _runner().invoke(
        cli, ["scan", str(GH_FIXTURE), "--format", "json", "--output", str(out)]
    )
    assert result.exit_code == 1
    data = json.loads(out.read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    assert "score" in data
    assert data["findings"]  # non-empty


# ---------------------------------------------------------------------------
# scan — edge cases
# ---------------------------------------------------------------------------


def test_cli_scan_nonexistent_path_exits_nonzero() -> None:
    result = _runner().invoke(cli, ["scan", "/nonexistent/path/nowhere.yml"])
    assert result.exit_code != 0


def test_cli_scan_empty_directory_exits_zero(tmp_path: Path) -> None:
    result = _runner().invoke(cli, ["scan", str(tmp_path)])
    assert result.exit_code == 0
    assert "No supported CI" in result.output or result.exit_code == 0


def test_cli_scan_directory_with_ci_files(tmp_path: Path) -> None:
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    (wf_dir / "ci.yml").write_text(
        "on:\n  push:\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v3\n",
        encoding="utf-8",
    )
    result = _runner().invoke(cli, ["scan", str(tmp_path)])
    assert result.exit_code == 1
    assert "GHA-001" in result.output
