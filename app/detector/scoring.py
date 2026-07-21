"""Score blending and threshold mapping.

Turns the heuristic score (and optional classifier score) into a final risk score, then
maps that score to a `Label` and recommended `Action` using configured thresholds.
"""

from __future__ import annotations

from app.config import Settings
from app.schemas import Action, Label


def blend_scores(
    heuristic_score: float,
    classifier_score: float | None,
    classifier_weight: float,
) -> float:
    """Combine heuristic and classifier scores into a final risk score in [0, 1].

    When the classifier did not run, the heuristic score stands alone. When it did, the
    two are combined as a weighted average with `classifier_weight` on the classifier.
    """
    if classifier_score is None:
        return _clamp(heuristic_score)
    w = _clamp(classifier_weight)
    return _clamp((1.0 - w) * heuristic_score + w * classifier_score)


def score_to_label(score: float, settings: Settings) -> Label:
    """Map a final risk score to a classification label."""
    if score >= settings.malicious_threshold:
        return Label.MALICIOUS
    if score >= settings.suspicious_threshold:
        return Label.SUSPICIOUS
    return Label.BENIGN


def label_to_action(label: Label) -> Action:
    """Map a label to the recommended action for the calling application."""
    return {
        Label.BENIGN: Action.ALLOW,
        Label.SUSPICIOUS: Action.FLAG,
        Label.MALICIOUS: Action.BLOCK,
    }[label]


def in_ambiguous_band(heuristic_score: float, settings: Settings) -> bool:
    """True when the heuristic score is neither clearly benign nor clearly malicious,
    i.e. it falls in the band where the LLM classifier should be consulted."""
    return (
        settings.heuristic_low_threshold
        < heuristic_score
        < settings.heuristic_high_threshold
    )


def _clamp(value: float, lo: float = 0.0, hi: float = 1.0) -> float:
    return max(lo, min(hi, value))
