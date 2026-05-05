from __future__ import annotations

from pathlib import Path

from cipguard.models import Finding
from cipguard.rules.github import run_github_rules
from cipguard.rules.gitlab import run_gitlab_rules
from cipguard.utils import (
    detect_ci_format,
    discover_files,
    is_github_actions,
    is_gitlab_ci,
    load_yaml_with_content,
)


def scan_file(path: Path) -> list[Finding]:
    """Parse and scan a single CI config file, returning all findings."""
    try:
        data, lines = load_yaml_with_content(path)
    except Exception:
        return []

    if not isinstance(data, dict):
        return []

    file_str = str(path)

    if is_github_actions(path):
        return run_github_rules(data, lines, file_str)
    if is_gitlab_ci(path):
        return run_gitlab_rules(data, lines, file_str)

    # Fallback: content-based detection for non-standard filenames
    fmt = detect_ci_format(data)
    if fmt == "github":
        return run_github_rules(data, lines, file_str)
    if fmt == "gitlab":
        return run_gitlab_rules(data, lines, file_str)
    return []


def scan_path(path: Path) -> dict[str, list[Finding]]:
    """Discover all supported CI files under path and scan each one."""
    files = discover_files(path)
    return {str(f): scan_file(f) for f in files}
