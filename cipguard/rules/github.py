from __future__ import annotations

from cipguard.models import Finding, Severity
from cipguard.utils import (
    SECRET_KEY_RE,
    SECURITY_NAME_RE,
    SHA_RE,
    find_line,
    get_on_triggers,
)


def _iter_env_blocks(data: dict):
    """Yield (key, value, context_label) from all env blocks in the workflow."""
    for k, v in (data.get("env") or {}).items():
        yield k, v, "workflow env"
    for job_name, job in (data.get("jobs") or {}).items():
        for k, v in (job.get("env") or {}).items():
            yield k, v, f"job {job_name!r} env"
        for step in job.get("steps") or []:
            for k, v in (step.get("env") or {}).items():
                yield k, v, f"job {job_name!r} step env"


def check_gha001(data: dict, lines: list[str], file: str) -> list[Finding]:
    """GHA-001: Action not pinned to a full 40-character commit SHA."""
    findings: list[Finding] = []
    for _job_name, job in (data.get("jobs") or {}).items():
        for step in job.get("steps") or []:
            uses = step.get("uses", "")
            if not uses:
                continue
            if uses.startswith("./") or uses.startswith("docker://"):
                continue
            if "@" not in uses:
                line = find_line(lines, uses)
                msg = f"Action '{uses}' has no version pin at all"
                rec = "Pin to a full 40-character commit SHA, e.g. actions/checkout@<sha>"
            else:
                ref = uses.split("@", 1)[1]
                if SHA_RE.match(ref):
                    continue
                line = find_line(lines, uses)
                msg = f"Action '{uses}' pinned to '{ref}' instead of a full commit SHA"
                rec = "Pin to a full 40-character commit SHA to prevent supply chain attacks"
            findings.append(
                Finding(
                    rule_id="GHA-001",
                    severity=Severity.HIGH,
                    file=file,
                    line=line,
                    finding=msg,
                    recommendation=rec,
                )
            )
    return findings


def check_gha002(data: dict, lines: list[str], file: str) -> list[Finding]:
    """GHA-002: Hardcoded secret or token literal in an env block."""
    findings: list[Finding] = []
    for key, value, ctx in _iter_env_blocks(data):
        if not SECRET_KEY_RE.search(str(key)):
            continue
        if not isinstance(value, str) or not value:
            continue
        if "${{" in value:
            continue
        line = find_line(lines, str(key))
        findings.append(
            Finding(
                rule_id="GHA-002",
                severity=Severity.CRITICAL,
                file=file,
                line=line,
                finding=f"Potential hardcoded secret in {ctx}: '{key}'",
                recommendation="Store secrets in GitHub Secrets and reference them via ${{ secrets.NAME }}",
            )
        )
    return findings


def check_gha003(data: dict, lines: list[str], file: str) -> list[Finding]:
    """GHA-003: pull_request_target trigger combined with PR head checkout."""
    triggers = get_on_triggers(data)
    if triggers is None:
        return []

    has_prt = False
    if isinstance(triggers, str):
        has_prt = triggers == "pull_request_target"
    elif isinstance(triggers, list):
        has_prt = "pull_request_target" in triggers
    elif isinstance(triggers, dict):
        has_prt = "pull_request_target" in triggers

    if not has_prt:
        return []

    findings: list[Finding] = []
    for job_name, job in (data.get("jobs") or {}).items():
        for step in job.get("steps") or []:
            if "actions/checkout" not in step.get("uses", ""):
                continue
            ref = str((step.get("with") or {}).get("ref", ""))
            if "head.sha" in ref or "head.ref" in ref:
                line = find_line(lines, "pull_request_target")
                findings.append(
                    Finding(
                        rule_id="GHA-003",
                        severity=Severity.CRITICAL,
                        file=file,
                        line=line,
                        finding=(
                            f"Job '{job_name}' uses pull_request_target with PR head checkout "
                            f"(ref: {ref!r})"
                        ),
                        recommendation=(
                            "Never checkout untrusted PR head in pull_request_target context; "
                            "use the pull_request trigger or validate the ref before checkout"
                        ),
                    )
                )
    return findings


def check_gha004(data: dict, lines: list[str], file: str) -> list[Finding]:
    """GHA-004: Self-hosted runner with no scoping labels."""
    findings: list[Finding] = []
    search_from = 0
    for job_name, job in (data.get("jobs") or {}).items():
        runs_on = job.get("runs-on")
        plain_self_hosted = runs_on == "self-hosted" or runs_on == ["self-hosted"]
        if plain_self_hosted:
            line = find_line(lines, "self-hosted", search_from)
            if line is not None:
                search_from = line
            findings.append(
                Finding(
                    rule_id="GHA-004",
                    severity=Severity.MEDIUM,
                    file=file,
                    line=line,
                    finding=f"Job '{job_name}' uses self-hosted runner with no scoping labels",
                    recommendation=(
                        "Add runner-group or environment labels to restrict execution, "
                        "e.g. runs-on: [self-hosted, linux, production]"
                    ),
                )
            )
    return findings


def check_gha005(data: dict, lines: list[str], file: str) -> list[Finding]:
    """GHA-005: continue-on-error: true on a security-related job."""
    findings: list[Finding] = []
    for job_name, job in (data.get("jobs") or {}).items():
        if not SECURITY_NAME_RE.search(str(job_name)):
            continue
        if job.get("continue-on-error") is True:
            line = find_line(lines, "continue-on-error")
            findings.append(
                Finding(
                    rule_id="GHA-005",
                    severity=Severity.MEDIUM,
                    file=file,
                    line=line,
                    finding=f"Security job '{job_name}' has continue-on-error: true",
                    recommendation=(
                        "Remove continue-on-error or set it to false on security jobs "
                        "to prevent silent failures from masking vulnerabilities"
                    ),
                )
            )
    return findings


def run_github_rules(data: dict, lines: list[str], file: str) -> list[Finding]:
    """Run all GitHub Actions rules and return aggregated findings."""
    findings: list[Finding] = []
    for checker in (check_gha001, check_gha002, check_gha003, check_gha004, check_gha005):
        findings.extend(checker(data, lines, file))
    return findings
