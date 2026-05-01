from __future__ import annotations

from enum import Enum

from pydantic import BaseModel


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"


SEVERITY_WEIGHTS: dict[Severity, int] = {
    Severity.CRITICAL: 20,
    Severity.HIGH: 10,
    Severity.MEDIUM: 5,
}


class Finding(BaseModel):
    rule_id: str
    severity: Severity
    file: str
    line: int | None = None
    finding: str
    recommendation: str
