from .base import Rule, Severity, Finding
from .security import SECURITY_RULES
from .best_practices import BEST_PRACTICE_RULES
from .values_rules import ValuesRule, VALUES_RULES, FREE_VALUES_RULES

ALL_RULES: list[Rule] = SECURITY_RULES + BEST_PRACTICE_RULES

FREE_SEVERITIES = {Severity.CRITICAL, Severity.HIGH}
FREE_RULES: list[Rule] = [r for r in ALL_RULES if r.severity in FREE_SEVERITIES]

__all__ = [
    "Rule", "Severity", "Finding",
    "ALL_RULES", "FREE_RULES",
    "ValuesRule", "VALUES_RULES", "FREE_VALUES_RULES",
]
