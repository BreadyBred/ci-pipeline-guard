from __future__ import annotations

from pathlib import Path

import pytest

from cipguard.models import Severity
from cipguard.rules.github import (
    check_gha001,
    check_gha002,
    check_gha003,
    check_gha004,
    check_gha005,
)
from cipguard.rules.gitlab import (
    check_glc001,
    check_glc002,
    check_glc003,
    check_glc004,
    check_glc005,
)
from cipguard.utils import load_yaml_with_content

FIXTURES = Path(__file__).parent / "fixtures"
GH_FIXTURE = FIXTURES / "sample_workflow.yml"
GL_FIXTURE = FIXTURES / "sample.gitlab-ci.yml"


@pytest.fixture(scope="module")
def github_data() -> tuple[dict, list[str]]:
    return load_yaml_with_content(GH_FIXTURE)


@pytest.fixture(scope="module")
def gitlab_data() -> tuple[dict, list[str]]:
    return load_yaml_with_content(GL_FIXTURE)


# ---------------------------------------------------------------------------
# GitHub Actions rules
# ---------------------------------------------------------------------------


def test_gha001_detects_unpinned_tag(github_data: tuple[dict, list[str]]) -> None:
    data, lines = github_data
    findings = check_gha001(data, lines, str(GH_FIXTURE))
    rule_findings = [f for f in findings if f.rule_id == "GHA-001"]
    assert rule_findings, "Expected at least one GHA-001 finding"
    assert all(f.severity == Severity.HIGH for f in rule_findings)
    # actions/checkout@v3 and actions/setup-node@main must be flagged
    flagged_uses = " ".join(f.finding for f in rule_findings)
    assert "checkout@v3" in flagged_uses
    assert "setup-node@main" in flagged_uses


def test_gha001_allows_correctly_pinned_sha(github_data: tuple[dict, list[str]]) -> None:
    data, lines = github_data
    findings = check_gha001(data, lines, str(GH_FIXTURE))
    # upload-artifact is pinned to a real 40-char SHA and must not appear
    assert not any("upload-artifact" in f.finding for f in findings)


def test_gha002_detects_hardcoded_secret(github_data: tuple[dict, list[str]]) -> None:
    data, lines = github_data
    findings = check_gha002(data, lines, str(GH_FIXTURE))
    rule_findings = [f for f in findings if f.rule_id == "GHA-002"]
    assert rule_findings, "Expected at least one GHA-002 finding"
    assert all(f.severity == Severity.CRITICAL for f in rule_findings)
    keys_found = " ".join(f.finding for f in rule_findings)
    assert "DATABASE_PASSWORD" in keys_found
    assert "API_KEY" in keys_found


def test_gha003_detects_prt_head_checkout(github_data: tuple[dict, list[str]]) -> None:
    data, lines = github_data
    findings = check_gha003(data, lines, str(GH_FIXTURE))
    rule_findings = [f for f in findings if f.rule_id == "GHA-003"]
    assert rule_findings, "Expected at least one GHA-003 finding"
    assert all(f.severity == Severity.CRITICAL for f in rule_findings)


def test_gha003_no_false_positive_without_prt() -> None:
    """A workflow without pull_request_target must not trigger GHA-003."""
    data = {
        "on": {"push": {"branches": ["main"]}},
        "jobs": {
            "build": {
                "runs-on": "ubuntu-latest",
                "steps": [
                    {"uses": "actions/checkout@v3", "with": {"ref": "head.sha"}},
                ],
            }
        },
    }
    findings = check_gha003(data, [], "fake.yml")
    assert not findings


def test_gha004_detects_plain_self_hosted(github_data: tuple[dict, list[str]]) -> None:
    data, lines = github_data
    findings = check_gha004(data, lines, str(GH_FIXTURE))
    rule_findings = [f for f in findings if f.rule_id == "GHA-004"]
    assert rule_findings, "Expected at least one GHA-004 finding"
    assert all(f.severity == Severity.MEDIUM for f in rule_findings)


def test_gha004_no_false_positive_with_labels() -> None:
    """A job with additional labels beyond self-hosted must not trigger GHA-004."""
    data = {
        "jobs": {
            "build": {
                "runs-on": ["self-hosted", "linux", "x64"],
                "steps": [],
            }
        }
    }
    findings = check_gha004(data, [], "fake.yml")
    assert not findings


def test_gha005_detects_continue_on_error_security(
    github_data: tuple[dict, list[str]],
) -> None:
    data, lines = github_data
    findings = check_gha005(data, lines, str(GH_FIXTURE))
    rule_findings = [f for f in findings if f.rule_id == "GHA-005"]
    assert rule_findings, "Expected at least one GHA-005 finding"
    assert all(f.severity == Severity.MEDIUM for f in rule_findings)
    assert any("security-scan" in f.finding for f in rule_findings)


# ---------------------------------------------------------------------------
# GitLab CI rules
# ---------------------------------------------------------------------------


def test_glc001_detects_privileged_service(gitlab_data: tuple[dict, list[str]]) -> None:
    data, lines = gitlab_data
    findings = check_glc001(data, lines, str(GL_FIXTURE))
    rule_findings = [f for f in findings if f.rule_id == "GLC-001"]
    assert rule_findings, "Expected at least one GLC-001 finding"
    assert all(f.severity == Severity.CRITICAL for f in rule_findings)


def test_glc002_detects_latest_and_untagged(gitlab_data: tuple[dict, list[str]]) -> None:
    data, lines = gitlab_data
    findings = check_glc002(data, lines, str(GL_FIXTURE))
    assert len(findings) >= 2, "Expected findings for :latest and untagged images"
    assert all(f.rule_id == "GLC-002" for f in findings)
    assert all(f.severity == Severity.MEDIUM for f in findings)


def test_glc002_no_false_positive_on_pinned_image() -> None:
    """An image pinned to a specific non-latest tag must not trigger GLC-002."""
    data = {"build": {"image": "python:3.12-slim", "script": ["python main.py"]}}
    findings = check_glc002(data, [], "fake.yml")
    assert not findings


def test_glc003_detects_plaintext_secret(gitlab_data: tuple[dict, list[str]]) -> None:
    data, lines = gitlab_data
    findings = check_glc003(data, lines, str(GL_FIXTURE))
    rule_findings = [f for f in findings if f.rule_id == "GLC-003"]
    assert rule_findings, "Expected at least one GLC-003 finding"
    assert all(f.severity == Severity.CRITICAL for f in rule_findings)
    keys_found = " ".join(f.finding for f in rule_findings)
    assert "DATABASE_PASSWORD" in keys_found
    assert "API_TOKEN" in keys_found


def test_glc003_no_false_positive_on_variable_ref() -> None:
    """A variable value that is itself a CI variable reference must not be flagged."""
    data = {"variables": {"API_TOKEN": "$CI_JOB_TOKEN"}}
    findings = check_glc003(data, [], "fake.yml")
    assert not findings


def test_glc004_detects_allow_failure_security(
    gitlab_data: tuple[dict, list[str]],
) -> None:
    data, lines = gitlab_data
    findings = check_glc004(data, lines, str(GL_FIXTURE))
    rule_findings = [f for f in findings if f.rule_id == "GLC-004"]
    assert rule_findings, "Expected at least one GLC-004 finding"
    assert all(f.severity == Severity.MEDIUM for f in rule_findings)
    assert any("security-lint" in f.finding for f in rule_findings)


def test_glc005_detects_pipe_to_shell(gitlab_data: tuple[dict, list[str]]) -> None:
    data, lines = gitlab_data
    findings = check_glc005(data, lines, str(GL_FIXTURE))
    rule_findings = [f for f in findings if f.rule_id == "GLC-005"]
    assert rule_findings, "Expected at least one GLC-005 finding"
    assert all(f.severity == Severity.HIGH for f in rule_findings)


def test_glc005_no_false_positive_on_local_script() -> None:
    """A local script execution must not trigger GLC-005."""
    data = {"deploy": {"script": ["./scripts/deploy.sh", "bash ./run.sh"]}}
    findings = check_glc005(data, [], "fake.yml")
    assert not findings


# ---------------------------------------------------------------------------
# Additional edge cases
# ---------------------------------------------------------------------------


def test_gha001_no_at_sign_is_flagged() -> None:
    """An action ref with no @ at all (and not a local action) must be flagged."""
    data = {"jobs": {"build": {"steps": [{"uses": "actions/checkout"}]}}}
    findings = check_gha001(data, [], "fake.yml")
    assert any(f.rule_id == "GHA-001" for f in findings)


def test_gha001_local_action_not_flagged() -> None:
    """A local action starting with ./ must never be flagged."""
    data = {"jobs": {"build": {"steps": [{"uses": "./.github/actions/setup"}]}}}
    findings = check_gha001(data, [], "fake.yml")
    assert not findings


def test_gha001_docker_action_skipped() -> None:
    """docker:// container actions use digest pinning, not Git SHAs; must not be flagged."""
    data = {
        "jobs": {
            "build": {
                "steps": [
                    {"uses": "docker://alpine:3.18.0"},
                    {"uses": "docker://ubuntu@sha256:abc123def456"},
                ]
            }
        }
    }
    findings = check_gha001(data, [], "fake.yml")
    assert not findings


def test_gha003_list_trigger_form() -> None:
    """pull_request_target in a list trigger must still trigger GHA-003."""
    data = {
        True: ["push", "pull_request_target"],
        "jobs": {
            "build": {
                "steps": [
                    {
                        "uses": "actions/checkout@v3",
                        "with": {"ref": "${{ github.event.pull_request.head.ref }}"},
                    }
                ]
            }
        },
    }
    findings = check_gha003(data, ["pull_request_target"], "fake.yml")
    assert any(f.rule_id == "GHA-003" for f in findings)


def test_gha003_string_trigger_form() -> None:
    """pull_request_target as a bare string trigger must still trigger GHA-003."""
    data = {
        True: "pull_request_target",
        "jobs": {
            "ci": {
                "steps": [
                    {
                        "uses": "actions/checkout@v3",
                        "with": {"ref": "${{ github.event.pull_request.head.sha }}"},
                    }
                ]
            }
        },
    }
    findings = check_gha003(data, ["pull_request_target"], "fake.yml")
    assert any(f.rule_id == "GHA-003" for f in findings)


def test_gha004_single_item_list_flagged() -> None:
    """runs-on: [self-hosted] (one-item list) must be flagged."""
    data = {"jobs": {"build": {"runs-on": ["self-hosted"], "steps": []}}}
    findings = check_gha004(data, ["self-hosted"], "fake.yml")
    assert any(f.rule_id == "GHA-004" for f in findings)


def test_gha005_non_security_job_not_flagged() -> None:
    """continue-on-error on a job whose name has no security keyword must not be flagged."""
    data = {"jobs": {"deploy": {"continue-on-error": True, "steps": []}}}
    findings = check_gha005(data, [], "fake.yml")
    assert not findings


def test_glc001_detects_privileged_on_job_itself() -> None:
    """privileged: true directly on a job (not a service) must trigger GLC-001."""
    data = {"build": {"privileged": True, "script": ["docker build ."]}}
    findings = check_glc001(data, ["privileged"], "fake.yml")
    assert any(f.rule_id == "GLC-001" for f in findings)


def test_glc002_digest_pinned_image_not_flagged() -> None:
    """An image pinned by digest (ubuntu@sha256:...) must not be flagged."""
    data = {"build": {"image": "ubuntu@sha256:abc123def456", "script": ["echo hi"]}}
    findings = check_glc002(data, [], "fake.yml")
    assert not findings


def test_glc002_image_dict_form_no_tag_flagged() -> None:
    """image: {name: python} (dict form, no tag) must trigger GLC-002."""
    data = {"build": {"image": {"name": "python"}, "script": ["python --version"]}}
    findings = check_glc002(data, ["python"], "fake.yml")
    assert any(f.rule_id == "GLC-002" for f in findings)


def test_glc003_non_secret_variable_not_flagged() -> None:
    """A variable whose name doesn't match the secret pattern must not be flagged."""
    data = {"variables": {"DEPLOY_ENV": "production", "REGION": "eu-west-1"}}
    findings = check_glc003(data, [], "fake.yml")
    assert not findings


def test_glc005_wget_pattern_flagged() -> None:
    """wget ... | sh must trigger GLC-005."""
    data = {"setup": {"script": ["wget -qO- https://example.com/install.sh | sh"]}}
    findings = check_glc005(data, ["wget"], "fake.yml")
    assert any(f.rule_id == "GLC-005" for f in findings)


def test_glc005_bin_bash_path_flagged() -> None:
    """curl ... | /bin/bash must trigger GLC-005 (absolute shell path)."""
    data = {"setup": {"script": ["curl https://example.com/install | /bin/bash"]}}
    findings = check_glc005(data, ["curl"], "fake.yml")
    assert any(f.rule_id == "GLC-005" for f in findings)


def test_glc005_bin_sh_path_flagged() -> None:
    """wget ... | /bin/sh must trigger GLC-005 (absolute shell path)."""
    data = {"setup": {"script": ["wget -O- https://example.com/setup | /bin/sh"]}}
    findings = check_glc005(data, ["wget"], "fake.yml")
    assert any(f.rule_id == "GLC-005" for f in findings)


def test_glc005_before_script_is_scanned() -> None:
    """curl | bash in before_script (not just script) must trigger GLC-005."""
    data = {
        "build": {
            "before_script": ["curl https://setup.example.com | bash"],
            "script": ["make"],
        }
    }
    findings = check_glc005(data, ["curl"], "fake.yml")
    assert any(f.rule_id == "GLC-005" for f in findings)


def test_glc005_after_script_is_scanned() -> None:
    """curl | bash in after_script must also trigger GLC-005."""
    data = {
        "build": {
            "script": ["make"],
            "after_script": ["curl https://report.example.com | bash"],
        }
    }
    findings = check_glc005(data, ["curl"], "fake.yml")
    assert any(f.rule_id == "GLC-005" for f in findings)


# ---------------------------------------------------------------------------
# Coverage gap: github.py uncovered branches
# ---------------------------------------------------------------------------


def test_gha002_step_level_env_is_scanned() -> None:
    """Secret key inside a step-level env block must be flagged (line 22 branch)."""
    data = {
        "jobs": {
            "build": {
                "steps": [
                    {
                        "name": "Run something",
                        "run": "echo hi",
                        "env": {"API_TOKEN": "hardcoded_value"},
                    }
                ]
            }
        }
    }
    findings = check_gha002(data, ["API_TOKEN"], "fake.yml")
    assert any(f.rule_id == "GHA-002" for f in findings)


def test_gha002_benign_env_key_not_flagged() -> None:
    """An env key with no secret keyword must not be flagged (line 67 continue)."""
    data = {
        "env": {"NODE_ENV": "production", "PORT": "3000"},
        "jobs": {},
    }
    findings = check_gha002(data, [], "fake.yml")
    assert not findings


def test_gha002_non_string_env_value_not_flagged() -> None:
    """An env value that is an integer or None must not be flagged (line 69 continue)."""
    data = {
        "env": {"TOKEN": 12345, "SECRET": None},
        "jobs": {},
    }
    findings = check_gha002(data, [], "fake.yml")
    assert not findings


def test_gha002_proper_secret_reference_not_flagged() -> None:
    """A value of ${{ secrets.X }} must not be flagged (line 72 continue)."""
    data = {
        "env": {"API_TOKEN": "${{ secrets.API_TOKEN }}"},
        "jobs": {},
    }
    findings = check_gha002(data, [], "fake.yml")
    assert not findings


def test_gha003_no_on_trigger_returns_empty() -> None:
    """A workflow dict with no 'on' key at all must return no findings (line 91)."""
    data = {
        "jobs": {
            "build": {
                "steps": [
                    {
                        "uses": "actions/checkout@v3",
                        "with": {"ref": "${{ github.event.pull_request.head.sha }}"},
                    }
                ]
            }
        }
    }
    findings = check_gha003(data, [], "fake.yml")
    assert not findings


# ---------------------------------------------------------------------------
# Coverage gap: gitlab.py uncovered branches
# ---------------------------------------------------------------------------


def test_glc002_image_non_str_non_dict_skipped() -> None:
    """An image value that is neither str nor dict must not raise or flag (line 25)."""
    data = {"build": {"image": 42, "script": ["echo hi"]}}
    findings = check_glc002(data, [], "fake.yml")
    assert not findings


def test_glc002_image_dict_empty_name_skipped() -> None:
    """An image dict with an empty name field must not produce a finding (line 28)."""
    data = {"build": {"image": {"name": "", "entrypoint": ["/bin/sh"]}, "script": ["echo hi"]}}
    findings = check_glc002(data, [], "fake.yml")
    assert not findings


def test_glc003_non_string_variable_value_not_flagged() -> None:
    """A secret-named variable whose value is an integer must not be flagged (line 119)."""
    data = {"variables": {"API_TOKEN": 12345, "SECRET": None}}
    findings = check_glc003(data, [], "fake.yml")
    assert not findings


def test_glc005_script_as_bare_string_is_scanned() -> None:
    """script: 'curl ... | bash' (bare string, not a list) must be flagged (line 177)."""
    data = {"setup": {"script": "curl https://example.com/setup | bash"}}
    findings = check_glc005(data, ["curl"], "fake.yml")
    assert any(f.rule_id == "GLC-005" for f in findings)


def test_glc005_non_string_command_in_list_skipped() -> None:
    """A non-string item inside a script list must not raise (line 182 continue)."""
    data = {"build": {"script": [None, {"nested": "dict"}, "make"]}}
    findings = check_glc005(data, [], "fake.yml")
    assert not findings


# ---------------------------------------------------------------------------
# Crash guards — malformed YAML must never raise (CB-1, CB-2, CB-3)
# ---------------------------------------------------------------------------


def test_gha001_non_dict_job_does_not_crash() -> None:
    """A jobs block where a value is not a dict must not raise."""
    data = {"jobs": {"build": None, "test": "string-job"}}
    findings = check_gha001(data, [], "fake.yml")
    assert findings == []


def test_gha002_non_dict_env_does_not_crash() -> None:
    """An env block that is a list instead of a dict must not raise."""
    data = {
        "env": ["not", "a", "dict"],
        "jobs": {
            "build": {
                "env": "also-not-a-dict",
                "steps": [{"env": 42, "run": "echo hi"}],
            }
        },
    }
    findings = check_gha002(data, [], "fake.yml")
    assert findings == []


def test_gha003_with_non_dict_does_not_crash() -> None:
    """A step where 'with' is a plain string must not raise (CB-2)."""
    data = {
        True: "pull_request_target",
        "jobs": {
            "ci": {
                "steps": [
                    {
                        "uses": "actions/checkout@v3",
                        "with": "ref: ${{ github.event.pull_request.head.sha }}",
                    }
                ]
            }
        },
    }
    findings = check_gha003(data, ["pull_request_target"], "fake.yml")
    assert not findings


# ---------------------------------------------------------------------------
# False-positive guards — delimiter-aware SECURITY_NAME_RE (FP-1)
# ---------------------------------------------------------------------------


def test_gha005_eslint_job_not_flagged() -> None:
    """A job named 'eslint-check' must not trigger GHA-005 (FP-1: 'lint' substring)."""
    data = {
        "jobs": {
            "eslint-check": {"continue-on-error": True, "steps": []},
        }
    }
    findings = check_gha005(data, [], "fake.yml")
    assert not findings


def test_glc004_document_scanner_not_flagged() -> None:
    """A job named 'document-scanner' must not trigger GLC-004 (FP-1: 'scan' substring)."""
    data = {"document-scanner": {"allow_failure": True, "script": ["./scan-docs.sh"]}}
    findings = check_glc004(data, [], "fake.yml")
    assert not findings


def test_gha005_security_scan_job_still_flagged() -> None:
    """A job named 'security-scan' must still be flagged after FP-1 fix."""
    data = {
        "jobs": {
            "security-scan": {"continue-on-error": True, "steps": []},
        }
    }
    findings = check_gha005(data, ["continue-on-error: true"], "fake.yml")
    assert any(f.rule_id == "GHA-005" for f in findings)
