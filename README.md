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

### GitLab CI

| ID | Severity | Description |
|---|---|---|
| GLC-001 | CRITICAL | `privileged: true` in a job or service definition |
| GLC-002 | MEDIUM | Docker image uses `:latest` tag or has no tag |
| GLC-003 | CRITICAL | Plaintext secret literal in a `variables` block |
| GLC-004 | MEDIUM | `allow_failure: true` on a security-named job |
| GLC-005 | HIGH | Remote content piped directly to shell (`curl|bash`, `wget|sh`) |

---

## Security score

Each finding deducts from a base score of 100:

| Severity | Penalty |
|---|---|
| CRITICAL | 20 |
| HIGH | 10 |
| MEDIUM | 5 |

Score is floored at 0. A clean pipeline scores 100.

## Output formats

Use `--format table` (default) for a Rich terminal table, or `--format json`
to get machine-readable output.

---

## Usage

```
python -m cipguard scan PATH [--format table|json] [--output FILE]
```

Scan a single file:

```
python -m cipguard scan .github/workflows/ci.yml
```

Scan an entire repository (recursive):

```
python -m cipguard scan /path/to/repo
```

Write JSON results to a file:

```
python -m cipguard scan . --format json --output results.json
```

---

## Running tests

Install dev dependencies, then run the full suite:

```
pip install -r requirements.txt
pytest
```

Run with coverage:

```
pytest --cov=cipguard --cov-report=term-missing
```
