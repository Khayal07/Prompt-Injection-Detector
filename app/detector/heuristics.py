"""Fast, rule-based heuristic detection layer.

Evaluates input text against the compiled rule set and produces a heuristic risk score
in [0, 1] plus the list of rules that fired. This layer always runs and is designed to be
sub-millisecond so it can gate the (slower, costlier) LLM classifier.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from app.detector.rules_loader import Rule, load_rules


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
        return len(self._rules)

    def evaluate(self, text: str) -> HeuristicResult:
        """Score `text` against all rules, returning the score and matched rules."""
        matched = [rule for rule in self._rules if rule.matches(text)]
        score = _noisy_or([r.weight for r in matched]) if matched else 0.0
        return HeuristicResult(score=score, matched=matched)
