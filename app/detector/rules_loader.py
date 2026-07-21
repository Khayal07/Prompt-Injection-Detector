"""Load and validate heuristic detection rules from a YAML file.

Rules are config-driven so new attack patterns can be added without code changes.
Each rule's regex is compiled once at load time; invalid rules raise immediately so a
broken config fails fast rather than silently disabling detection.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

import yaml

REQUIRED_FIELDS = ("id", "category", "severity", "weight", "description", "pattern")
VALID_SEVERITIES = {"low", "medium", "high"}
# Compiled case-insensitively and with DOTALL so `.` spans newlines in multi-line inputs.
_REGEX_FLAGS = re.IGNORECASE | re.DOTALL


@dataclass(frozen=True)
class Rule:
    """A single compiled heuristic rule."""

    id: str
    category: str
    severity: str
    weight: float
    description: str
    pattern: str
    regex: re.Pattern

    def matches(self, text: str) -> bool:
        """True if this rule's pattern is found anywhere in `text`."""
        return self.regex.search(text) is not None


class RuleConfigError(ValueError):
    """Raised when the rules file is malformed or a rule is invalid."""


def _validate_rule(raw: dict, index: int) -> None:
    """Validate a single raw rule mapping, raising RuleConfigError on any problem."""
    missing = [f for f in REQUIRED_FIELDS if f not in raw]
    if missing:
        raise RuleConfigError(
            f"rule #{index} (id={raw.get('id', '?')}) missing fields: {missing}"
        )
    if raw["severity"] not in VALID_SEVERITIES:
        raise RuleConfigError(
            f"rule '{raw['id']}' has invalid severity '{raw['severity']}' "
            f"(expected one of {sorted(VALID_SEVERITIES)})"
        )
    weight = raw["weight"]
    if not isinstance(weight, int | float) or not 0.0 <= float(weight) <= 1.0:
        raise RuleConfigError(
            f"rule '{raw['id']}' weight must be a number in [0, 1], got {weight!r}"
        )


def load_rules(path: str | Path) -> list[Rule]:
    """Parse, validate and compile all rules from `path`.

    Raises RuleConfigError if the file is missing, malformed, contains duplicate ids,
    or any rule has an invalid field or uncompilable regex.
    """
    path = Path(path)
    if not path.exists():
        raise RuleConfigError(f"rules file not found: {path}")

    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:  # pragma: no cover - passthrough of parser detail
        raise RuleConfigError(f"failed to parse YAML in {path}: {exc}") from exc

    if not isinstance(data, dict) or "rules" not in data:
        raise RuleConfigError(f"{path} must be a mapping with a top-level 'rules' key")

    raw_rules = data["rules"]
    if not isinstance(raw_rules, list) or not raw_rules:
        raise RuleConfigError(f"{path} 'rules' must be a non-empty list")

    rules: list[Rule] = []
    seen_ids: set[str] = set()
    for index, raw in enumerate(raw_rules):
        if not isinstance(raw, dict):
            raise RuleConfigError(f"rule #{index} is not a mapping")
        _validate_rule(raw, index)

        rule_id = raw["id"]
        if rule_id in seen_ids:
            raise RuleConfigError(f"duplicate rule id: '{rule_id}'")
        seen_ids.add(rule_id)

        try:
            regex = re.compile(raw["pattern"], _REGEX_FLAGS)
        except re.error as exc:
            raise RuleConfigError(
                f"rule '{rule_id}' has an invalid regex: {exc}"
            ) from exc

        rules.append(
            Rule(
                id=rule_id,
                category=raw["category"],
                severity=raw["severity"],
                weight=float(raw["weight"]),
                description=raw["description"],
                pattern=raw["pattern"],
                regex=regex,
            )
        )

    return rules
