from __future__ import annotations

import re
from pathlib import Path

import yaml


SECRET_KEY_RE = re.compile(
    r"(?<![A-Za-z])(PASSWORD|SECRET|TOKEN|API_KEY|PRIVATE_KEY)(?![A-Za-z])",
    re.IGNORECASE,
)

SHA_RE = re.compile(r"^[0-9a-f]{40}$")

# Matches: curl/wget ... | bash/sh  including /bin/bash and /bin/sh paths
PIPE_EXEC_RE = re.compile(
    r"(curl|wget)\b[^\n|]*\|\s*(/bin/)?(ba)?sh\b",
    re.IGNORECASE,
)

SECURITY_NAME_RE = re.compile(
    r"security|scan|sast|audit|lint",
    re.IGNORECASE,
)

# Top-level keys in .gitlab-ci.yml that are not job definitions
_GITLAB_RESERVED: frozenset[str] = frozenset(
    {
        "stages",
        "variables",
        "image",
        "services",
        "before_script",
        "after_script",
        "cache",
        "include",
        "workflow",
        "default",
        "pages",
    }
)

# Reject files larger than this before reading to prevent OOM / YAML bombs.
MAX_FILE_BYTES: int = 512 * 1024  # 512 KB


def load_yaml_with_content(path: Path) -> tuple[dict, list[str]]:
    """Load a YAML file and return (parsed dict, raw lines).

    Raises ValueError when the file exceeds MAX_FILE_BYTES.
    """
    size = path.stat().st_size
    if size > MAX_FILE_BYTES:
        raise ValueError(
            f"{path.name} is {size} bytes, exceeding the {MAX_FILE_BYTES}-byte limit"
        )
    with open(path, "r", encoding="utf-8") as fh:
        content = fh.read()
    data = yaml.safe_load(content) or {}
    return data, content.splitlines()


def find_line(lines: list[str], needle: str, start: int = 0) -> int | None:
    """Return 1-based line number of the first line at or after *start*
    that contains *needle*.

    *start* is a 0-based index into *lines* so callers can resume searching
    after a previously found line.
    """
    for i, line in enumerate(lines[start:], start + 1):
        if line.lstrip().startswith("#"):
            continue
        if needle in line:
            return i
    return None


def is_github_actions(path: Path) -> bool:
    parts = [p.lower() for p in path.parts]
    return ".github" in parts and "workflows" in parts


def is_gitlab_ci(path: Path) -> bool:
    return path.name in (".gitlab-ci.yml", ".gitlab-ci.yaml")


def detect_ci_format(data: dict) -> str | None:
    """Infer CI format from YAML content when the path gives no clue.

    Returns 'github', 'gitlab', or None if format cannot be determined.
    """
    jobs = data.get("jobs")
    if isinstance(jobs, dict):
        for job in jobs.values():
            if isinstance(job, dict) and "steps" in job:
                return "github"

    if "stages" in data:
        return "gitlab"
    for key, val in data.items():
        if isinstance(val, dict) and "script" in val and key not in _GITLAB_RESERVED:
            return "gitlab"

    return None


def discover_files(path: Path) -> list[Path]:
    """Discover all supported CI configuration files at or under path."""
    if path.is_file():
        return [path]
    found: list[Path] = []
    for ext in ("*.yml", "*.yaml"):
        for f in path.rglob(ext):
            if f.is_symlink() or not f.is_file():
                continue
            if is_github_actions(f) or is_gitlab_ci(f):
                found.append(f)
    return sorted(set(found))


def get_gitlab_jobs(data: dict) -> dict[str, dict]:
    """Return non-reserved, non-hidden top-level job definitions."""
    return {
        k: v
        for k, v in data.items()
        if k not in _GITLAB_RESERVED
        and isinstance(v, dict)
        and not str(k).startswith(".")
    }


def get_on_triggers(data: dict) -> dict | list | str | None:
    """Extract the GitHub Actions 'on' trigger value.

    PyYAML 1.1 coerces the bare keyword 'on' to boolean True, so we check both.
    """
    return data.get(True) or data.get("on")
