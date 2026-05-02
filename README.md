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
