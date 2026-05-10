from __future__ import annotations

from cipguard.models import Finding, Severity
from cipguard.utils import (
    PIPE_EXEC_RE,
    SECRET_KEY_RE,
    SECURITY_NAME_RE,
    find_line,
    get_gitlab_jobs,
)


def _check_image(
    image: str | dict | None,
    file: str,
    lines: list[str],
    context: str,
    start: int = 0,
) -> Finding | None:
    """Return a GLC-002 finding if image is untagged or uses :latest."""
    if isinstance(image, dict):
        name = image.get("name", "")
    elif isinstance(image, str):
        name = image
    else:
        return None

    if not name:
        return None

    if ":" not in name:
        line = find_line(lines, name, start)
        return Finding(
            rule_id="GLC-002",
            severity=Severity.MEDIUM,
            file=file,
            line=line,
            finding=f"Image '{name}' in {context} has no version tag",
            recommendation="Pin the image to a specific tag or digest, e.g. ubuntu:22.04",
        )

    if name.endswith(":latest"):
        line = find_line(lines, name, start)
        return Finding(
            rule_id="GLC-002",
            severity=Severity.MEDIUM,
            file=file,
            line=line,
            finding=f"Image '{name}' in {context} uses the mutable ':latest' tag",
            recommendation="Pin to an immutable version tag or digest, e.g. ubuntu:22.04",
        )

    return None


def check_glc001(data: dict, lines: list[str], file: str) -> list[Finding]:
    """GLC-001: privileged: true in any job or service definition."""
    findings: list[Finding] = []
    search_from = 0
    for job_name, job in get_gitlab_jobs(data).items():
        if job.get("privileged") is True:
            line = find_line(lines, "privileged: true", search_from)
            if line is not None:
                search_from = line
            findings.append(
                Finding(
                    rule_id="GLC-001",
                    severity=Severity.CRITICAL,
                    file=file,
                    line=line,
                    finding=f"Job '{job_name}' runs with privileged: true",
                    recommendation=(
                        "Remove privileged mode; use rootless Docker or Kaniko "
                        "for container builds instead"
                    ),
                )
            )
        for svc in job.get("services") or []:
            if isinstance(svc, dict) and svc.get("privileged") is True:
                line = find_line(lines, "privileged: true", search_from)
                if line is not None:
                    search_from = line
                findings.append(
                    Finding(
                        rule_id="GLC-001",
                        severity=Severity.CRITICAL,
                        file=file,
                        line=line,
                        finding=f"Service in job '{job_name}' runs with privileged: true",
                        recommendation="Remove privileged mode from service definitions",
                    )
                )
    return findings


def check_glc002(data: dict, lines: list[str], file: str) -> list[Finding]:
    """GLC-002: Image tag is :latest or entirely absent."""
    findings: list[Finding] = []
    search_from = 0

    global_image = data.get("image")
    if global_image:
        f = _check_image(global_image, file, lines, "global image", search_from)
        if f:
            if f.line is not None:
                search_from = f.line
            findings.append(f)

    for job_name, job in get_gitlab_jobs(data).items():
        image = job.get("image")
        if image:
            f = _check_image(image, file, lines, f"job '{job_name}'", search_from)
            if f:
                if f.line is not None:
                    search_from = f.line
                findings.append(f)

    return findings


def check_glc003(data: dict, lines: list[str], file: str) -> list[Finding]:
    """GLC-003: Plaintext secret literal in a variables block."""
    findings: list[Finding] = []

    def _scan_vars(variables: dict | None, context: str) -> None:
        for key, value in (variables or {}).items():
            if not SECRET_KEY_RE.search(str(key)):
                continue
            if not isinstance(value, str) or not value:
                continue
            if value.startswith("$"):
                continue
            line = find_line(lines, str(key))
            findings.append(
                Finding(
                    rule_id="GLC-003",
                    severity=Severity.CRITICAL,
                    file=file,
                    line=line,
                    finding=f"Potential hardcoded secret in {context} variables: '{key}'",
                    recommendation=(
                        "Use GitLab CI/CD protected or masked variables, "
                        "or an external secrets manager"
                    ),
                )
            )

    _scan_vars(data.get("variables"), "global")
    for job_name, job in get_gitlab_jobs(data).items():
        _scan_vars(job.get("variables"), f"job '{job_name}'")

    return findings


def check_glc004(data: dict, lines: list[str], file: str) -> list[Finding]:
    """GLC-004: allow_failure: true on a security-related job."""
    findings: list[Finding] = []
    search_from = 0
    for job_name, job in get_gitlab_jobs(data).items():
        if not SECURITY_NAME_RE.search(str(job_name)):
            continue
        if job.get("allow_failure") is True:
            line = find_line(lines, "allow_failure: true", search_from)
            if line is not None:
                search_from = line
            findings.append(
                Finding(
                    rule_id="GLC-004",
                    severity=Severity.MEDIUM,
                    file=file,
                    line=line,
                    finding=f"Security job '{job_name}' has allow_failure: true",
                    recommendation=(
                        "Set allow_failure: false on security jobs so pipeline failures "
                        "are visible and block merges"
                    ),
                )
            )
    return findings


def check_glc005(data: dict, lines: list[str], file: str) -> list[Finding]:
    """GLC-005: Remote code execution via curl|bash or wget|sh in script blocks."""
    findings: list[Finding] = []
    for job_name, job in get_gitlab_jobs(data).items():
        commands: list[str] = []
        for key in ("before_script", "script", "after_script"):
            block = job.get(key) or []
            if isinstance(block, str):
                block = [block]
            commands.extend(block)

        for cmd in commands:
            if not isinstance(cmd, str):
                continue
            if PIPE_EXEC_RE.search(cmd):
                needle = (cmd.strip().splitlines() or [""])[0][:40]
                line = find_line(lines, needle)
                findings.append(
                    Finding(
                        rule_id="GLC-005",
                        severity=Severity.HIGH,
                        file=file,
                        line=line,
                        finding=(
                            f"Job '{job_name}' pipes remote content to shell: "
                            f"{cmd.strip().replace(chr(10), ' ')[:80]}"
                        ),
                        recommendation=(
                            "Download the script first, verify its checksum, "
                            "then execute it explicitly"
                        ),
                    )
                )
    return findings


def run_gitlab_rules(data: dict, lines: list[str], file: str) -> list[Finding]:
    """Run all GitLab CI rules and return aggregated findings."""
    findings: list[Finding] = []
    for checker in (check_glc001, check_glc002, check_glc003, check_glc004, check_glc005):
        findings.extend(checker(data, lines, file))
    return findings
