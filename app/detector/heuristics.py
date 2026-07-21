"""Fast, rule-based heuristic detection layer.

Evaluates input text against the compiled rule set and produces a heuristic risk score
in [0, 1] plus the list of rules that fired. This layer always runs and is designed to be
sub-millisecond so it can gate the (slower, costlier) LLM classifier.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field

from app.detector.rules_loader import Rule, load_rules

logger = logging.getLogger("pid.heuristics")


@dataclass
class HeuristicResult:
    """Outcome of the heuristic layer for one input."""

    score: float
    matched: list[Rule] = field(default_factory=list)

    @property
    def categories(self) -> list[str]:
        """Distinct categories of the rules that fired, preserving first-seen order."""
        seen: dict[str, None] = {}
        for rule in self.matched:
            seen.setdefault(rule.category, None)
        return list(seen)

    def reasons(self) -> list[str]:
        """Human-readable descriptions for each matched rule."""
        return [f"[{r.category}] {r.description}" for r in self.matched]


def _noisy_or(weights: list[float]) -> float:
    """Combine independent rule weights via noisy-OR.

    score = 1 - Π(1 - w_i). Monotonic in the number and strength of matches, bounded to
    [0, 1]. A single 0.85 rule yields 0.85; two 0.6 rules yield 0.84; etc.
    """
    product = 1.0
    for w in weights:
        product *= 1.0 - w
    return 1.0 - product


class HeuristicEngine:
    """Holds the compiled rules and scores inputs against them.

    The engine is cheap to construct but rules are reloadable at runtime via `reload()`
    so operators can add patterns without restarting the service.
    """

    def __init__(self, rules_path: str):
        self._rules_path = rules_path
        self._rules: list[Rule] = load_rules(rules_path)
        self._mtime: float = self._current_mtime()

    @property
    def rules(self) -> list[Rule]:
        return self._rules

    @property
    def rule_count(self) -> int:
        return len(self._rules)

    def reload(self) -> int:
        """Reload rules from disk. Returns the new rule count. Leaves current rules intact
        if the new config fails to load (the underlying loader raises before assignment)."""
        new_rules = load_rules(self._rules_path)
        self._rules = new_rules
        self._mtime = self._current_mtime()
        return len(self._rules)

    def maybe_reload(self) -> bool:
        """Reload only if the rules file changed on disk since the last load.

        Enables multi-worker reloads without a coordinated signal. A failed reload is
        logged and swallowed so a bad edit never breaks the request path. Returns True
        when a reload happened.
        """
        current = self._current_mtime()
        if current == self._mtime:
            return False
        try:
            self.reload()
            logger.info("rules auto-reloaded (%d rules)", len(self._rules))
            return True
        except Exception as exc:  # noqa: BLE001 - keep serving with the old rules
            logger.warning("rules auto-reload failed, keeping current rules: %s", exc)
            self._mtime = current  # avoid retrying the same broken file every request
            return False

    def _current_mtime(self) -> float:
        try:
            return os.path.getmtime(self._rules_path)
        except OSError:
            return 0.0

    def evaluate(self, text: str) -> HeuristicResult:
        """Score `text` against all rules, returning the score and matched rules."""
        matched = [rule for rule in self._rules if rule.matches(text)]
        score = _noisy_or([r.weight for r in matched]) if matched else 0.0
        return HeuristicResult(score=score, matched=matched)
