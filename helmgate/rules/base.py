from dataclasses import dataclass
from enum import Enum
from typing import Any


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class Finding:
    rule_id: str
    severity: Severity
    message: str
    path: str  # e.g. "templates/deployment.yaml"
    line_hint: str = ""  # human-readable context, not exact line number


@dataclass
class Rule:
    id: str
    name: str
    severity: Severity
    description: str

    def check(self, manifest: dict[str, Any], path: str) -> list[Finding]:
        """Run rule against a single parsed YAML manifest. Override in subclasses."""
        raise NotImplementedError
