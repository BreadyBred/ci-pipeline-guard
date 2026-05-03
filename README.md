# ci-pipeline-guard

A CLI security scanner that analyzes CI/CD YAML configuration files for supply
chain attack vectors and security misconfigurations.

Supports **GitHub Actions** (`.github/workflows/*.yml`) and
**GitLab CI** (`.gitlab-ci.yml`).

## Install

```
pip install -r requirements.txt
```

No additional setup required. The scanner runs fully offline.

Requires **Python 3.12+**. Dependencies: PyYAML, Rich, Click, Pydantic.

---

## Detection rules

### GitHub Actions

| ID | Severity | Description |
|---|---|---|
| GHA-001 | HIGH | Action not pinned to a full 40-char commit SHA |
| GHA-002 | CRITICAL | Hardcoded secret or token literal in an `env` block |
| GHA-003 | CRITICAL | `pull_request_target` trigger combined with PR head checkout |
| GHA-004 | MEDIUM | Self-hosted runner with no scoping labels |
| GHA-005 | MEDIUM | `continue-on-error: true` on a security-named job |
