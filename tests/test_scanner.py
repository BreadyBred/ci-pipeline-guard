from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from cipguard.scanner import scan_file, scan_path

FIXTURES = Path(__file__).parent / "fixtures"
GH_FIXTURE = FIXTURES / "sample_workflow.yml"
GL_FIXTURE = FIXTURES / "sample.gitlab-ci.yml"


def test_scan_file_github_returns_findings() -> None:
    findings = scan_file(GH_FIXTURE)
    assert findings, "Expected findings from GitHub Actions fixture"
    rule_ids = {f.rule_id for f in findings}
    assert rule_ids >= {"GHA-001", "GHA-002", "GHA-003", "GHA-004", "GHA-005"}


def test_scan_file_gitlab_returns_findings() -> None:
    findings = scan_file(GL_FIXTURE)
    assert findings, "Expected findings from GitLab CI fixture"
    rule_ids = {f.rule_id for f in findings}
    assert rule_ids >= {"GLC-001", "GLC-002", "GLC-003", "GLC-004", "GLC-005"}


def test_scan_file_all_findings_carry_file_path() -> None:
    for fixture in (GH_FIXTURE, GL_FIXTURE):
        for finding in scan_file(fixture):
            assert finding.file == str(fixture)


def test_scan_file_malformed_yaml_returns_empty(tmp_path: Path) -> None:
    bad = tmp_path / ".gitlab-ci.yml"
    bad.write_text("key: [unclosed bracket\n", encoding="utf-8")
    assert scan_file(bad) == []


def test_scan_file_oversized_file_returns_empty(tmp_path: Path) -> None:
    """scan_file must silently skip files that exceed the size limit."""
    from cipguard.utils import MAX_FILE_BYTES
    oversized = tmp_path / ".gitlab-ci.yml"
    oversized.write_bytes(b"x: y\n" * (MAX_FILE_BYTES // 4))
    assert scan_file(oversized) == []


def test_scan_file_empty_yaml_returns_empty(tmp_path: Path) -> None:
    empty = tmp_path / ".gitlab-ci.yml"
    empty.write_text("", encoding="utf-8")
    assert scan_file(empty) == []


def test_scan_file_non_ci_yaml_returns_empty(tmp_path: Path) -> None:
    random_yaml = tmp_path / "config.yml"
    random_yaml.write_text("foo: bar\nbaz: 1\n", encoding="utf-8")
    assert scan_file(random_yaml) == []


def test_scan_file_yaml_with_scalar_root_returns_empty(tmp_path: Path) -> None:
    scalar = tmp_path / ".gitlab-ci.yml"
    scalar.write_text("just a string\n", encoding="utf-8")
    assert scan_file(scalar) == []


def test_scan_path_single_github_file() -> None:
    result = scan_path(GH_FIXTURE)
    assert str(GH_FIXTURE) in result
    assert result[str(GH_FIXTURE)]


def test_scan_path_single_gitlab_file() -> None:
    result = scan_path(GL_FIXTURE)
    assert str(GL_FIXTURE) in result
    assert result[str(GL_FIXTURE)]


def test_scan_path_directory_discovers_canonical_names(tmp_path: Path) -> None:
    # Create a properly-named GitHub Actions workflow
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    wf_file = wf_dir / "ci.yml"
    wf_file.write_text(
        "on:\n  push:\n    branches: [main]\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v3\n",
        encoding="utf-8",
    )

    # Create a properly-named GitLab CI file
    gl_file = tmp_path / ".gitlab-ci.yml"
    gl_file.write_text(
        "image: ubuntu:latest\nstages:\n  - build\nbuild:\n  stage: build\n  script:\n    - echo hi\n",
        encoding="utf-8",
    )

    result = scan_path(tmp_path)
    assert str(wf_file) in result
    assert str(gl_file) in result


def test_scan_path_directory_ignores_non_ci_yaml(tmp_path: Path) -> None:
    noise = tmp_path / "docker-compose.yml"
    noise.write_text("version: '3'\nservices:\n  web:\n    image: nginx\n", encoding="utf-8")
    result = scan_path(tmp_path)
    assert str(noise) not in result


def test_scan_path_empty_directory_returns_empty_dict(tmp_path: Path) -> None:
    result = scan_path(tmp_path)
    assert result == {}
