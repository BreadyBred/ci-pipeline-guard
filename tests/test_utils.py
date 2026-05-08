from __future__ import annotations

from pathlib import Path

import pytest

from cipguard.utils import (
    MAX_FILE_BYTES,
    SECRET_KEY_RE,
    detect_ci_format,
    discover_files,
    find_line,
    is_github_actions,
    is_gitlab_ci,
    load_yaml_with_content,
)


# ---------------------------------------------------------------------------
# is_github_actions
# ---------------------------------------------------------------------------


def test_is_github_actions_canonical_path(tmp_path: Path) -> None:
    p = tmp_path / ".github" / "workflows" / "ci.yml"
    p.parent.mkdir(parents=True)
    p.touch()
    assert is_github_actions(p) is True


def test_is_github_actions_rejects_unrelated_yml(tmp_path: Path) -> None:
    p = tmp_path / "config.yml"
    p.touch()
    assert is_github_actions(p) is False


def test_is_github_actions_rejects_partial_path(tmp_path: Path) -> None:
    # Has .github but not workflows
    p = tmp_path / ".github" / "CODEOWNERS"
    p.parent.mkdir(parents=True)
    p.touch()
    assert is_github_actions(p) is False


# ---------------------------------------------------------------------------
# is_gitlab_ci
# ---------------------------------------------------------------------------


def test_is_gitlab_ci_standard_name(tmp_path: Path) -> None:
    assert is_gitlab_ci(tmp_path / ".gitlab-ci.yml") is True
    assert is_gitlab_ci(tmp_path / ".gitlab-ci.yaml") is True


def test_is_gitlab_ci_rejects_other_names(tmp_path: Path) -> None:
    assert is_gitlab_ci(tmp_path / "gitlab-ci.yml") is False
    assert is_gitlab_ci(tmp_path / "sample.gitlab-ci.yml") is False


# ---------------------------------------------------------------------------
# find_line
# ---------------------------------------------------------------------------


def test_find_line_returns_correct_1based_index() -> None:
    lines = ["foo", "bar: value", "baz"]
    assert find_line(lines, "bar") == 2


def test_find_line_returns_none_when_missing() -> None:
    assert find_line(["a", "b", "c"], "z") is None


def test_find_line_returns_first_occurrence() -> None:
    lines = ["token: x", "token: y"]
    assert find_line(lines, "token") == 1


def test_find_line_start_skips_earlier_lines() -> None:
    lines = ["token: x", "other: y", "token: z"]
    assert find_line(lines, "token", start=1) == 3


def test_find_line_start_equal_to_match_line_skips_it() -> None:
    """start=N means 'search from line N+1', so start=1 skips the line 1 match."""
    lines = ["needle: a", "needle: b"]
    first = find_line(lines, "needle")
    assert first == 1
    second = find_line(lines, "needle", start=first)
    assert second == 2


# ---------------------------------------------------------------------------
# discover_files
# ---------------------------------------------------------------------------


def test_discover_files_single_file_returned_directly(tmp_path: Path) -> None:
    f = tmp_path / "any.yml"
    f.write_text("foo: bar\n", encoding="utf-8")
    assert discover_files(f) == [f]


def test_discover_files_finds_github_workflow(tmp_path: Path) -> None:
    wf = tmp_path / ".github" / "workflows" / "ci.yml"
    wf.parent.mkdir(parents=True)
    wf.touch()
    result = discover_files(tmp_path)
    assert wf in result


def test_discover_files_finds_gitlab_ci(tmp_path: Path) -> None:
    gl = tmp_path / ".gitlab-ci.yml"
    gl.touch()
    result = discover_files(tmp_path)
    assert gl in result


def test_discover_files_ignores_non_ci_files(tmp_path: Path) -> None:
    noise = tmp_path / "docker-compose.yml"
    noise.touch()
    result = discover_files(tmp_path)
    assert noise not in result


def test_discover_files_finds_nested_gitlab_ci(tmp_path: Path) -> None:
    nested = tmp_path / "project" / "sub" / ".gitlab-ci.yml"
    nested.parent.mkdir(parents=True)
    nested.touch()
    result = discover_files(tmp_path)
    assert nested in result


def test_discover_files_skips_symlinks(tmp_path: Path) -> None:
    real = tmp_path / ".gitlab-ci.yml"
    real.write_text("stages: [build]\n", encoding="utf-8")
    link = tmp_path / "link.yml"
    try:
        link.symlink_to(real)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not supported on this platform")
    result = discover_files(tmp_path)
    assert real in result
    assert link not in result


# ---------------------------------------------------------------------------
# detect_ci_format
# ---------------------------------------------------------------------------


def test_detect_ci_format_github() -> None:
    data = {
        True: {"push": {}},
        "jobs": {"build": {"runs-on": "ubuntu-latest", "steps": [{"run": "echo hi"}]}},
    }
    assert detect_ci_format(data) == "github"


def test_detect_ci_format_gitlab_via_stages() -> None:
    data = {"stages": ["build", "test"], "build": {"script": ["make"]}}
    assert detect_ci_format(data) == "gitlab"


def test_detect_ci_format_gitlab_via_script_key() -> None:
    data = {"deploy": {"script": ["./deploy.sh"], "environment": "prod"}}
    assert detect_ci_format(data) == "gitlab"


def test_detect_ci_format_unknown() -> None:
    assert detect_ci_format({"foo": "bar", "baz": 1}) is None


# ---------------------------------------------------------------------------
# load_yaml_with_content
# ---------------------------------------------------------------------------


def test_load_yaml_with_content_returns_dict_and_lines(tmp_path: Path) -> None:
    f = tmp_path / "test.yml"
    f.write_text("key: value\nother: 123\n", encoding="utf-8")
    data, lines = load_yaml_with_content(f)
    assert data == {"key": "value", "other": 123}
    assert lines == ["key: value", "other: 123"]


def test_load_yaml_with_content_empty_file_returns_empty_dict(tmp_path: Path) -> None:
    f = tmp_path / "empty.yml"
    f.write_text("", encoding="utf-8")
    data, lines = load_yaml_with_content(f)
    assert data == {}
    assert lines == []


def test_load_yaml_with_content_rejects_oversized_file(tmp_path: Path) -> None:
    """Files exceeding MAX_FILE_BYTES must raise ValueError before YAML parsing."""
    big = tmp_path / ".gitlab-ci.yml"
    big.write_bytes(b"x: y\n" * (MAX_FILE_BYTES // 4))  # well over the limit
    with pytest.raises(ValueError, match="exceeding the"):
        load_yaml_with_content(big)


def test_load_yaml_with_content_accepts_file_at_limit(tmp_path: Path) -> None:
    """A file exactly at the limit must be accepted."""
    f = tmp_path / ".gitlab-ci.yml"
    # Write something smaller than the limit
    f.write_text("stages: [build]\n", encoding="utf-8")
    data, lines = load_yaml_with_content(f)
    assert "stages" in data


# ---------------------------------------------------------------------------
# SECRET_KEY_RE — boundary correctness
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("key", [
    "PASSWORD",
    "MY_PASSWORD",
    "DATABASE_PASSWORD",
    "SECRET",
    "MY_SECRET",
    "TOKEN",
    "GITHUB_TOKEN",
    "API_KEY",
    "MY_API_KEY",
    "PRIVATE_KEY",
    "MY_PRIVATE_KEY",
    "password",
    "db_password",
])
def test_secret_key_re_matches_real_secret_keys(key: str) -> None:
    assert SECRET_KEY_RE.search(key), f"Expected match for {key!r}"


@pytest.mark.parametrize("key", [
    "TOKENIZER",
    "tokenizer",
    "SECRETARY",
    "secretary",
    "PRIVATEKEY_STORE",
    "TOKENSTORE",
    "PASSWORDLESS",
    "SECRETARIAT",
])
def test_secret_key_re_rejects_false_positives(key: str) -> None:
    assert not SECRET_KEY_RE.search(key), f"Unexpected match for {key!r}"
