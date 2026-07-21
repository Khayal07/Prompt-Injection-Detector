"""Unit tests for score blending and threshold -> label/action mapping."""

from __future__ import annotations

import pytest

from app.config import get_settings
from app.detector.scoring import (
    blend_scores,
    in_ambiguous_band,
    label_to_action,
    score_to_label,
)
from app.schemas import Action, Label

settings = get_settings()


def test_blend_without_classifier_returns_heuristic():
    assert blend_scores(0.42, None, settings.classifier_weight) == pytest.approx(0.42)


def test_blend_weights_classifier():
    # classifier_weight default 0.65 -> 0.35*0.2 + 0.65*0.9 = 0.655
    blended = blend_scores(0.2, 0.9, 0.65)
    assert blended == pytest.approx(0.655)


def test_blend_is_clamped():
    assert blend_scores(1.5, None, 0.65) == 1.0
    assert blend_scores(-0.5, None, 0.65) == 0.0


@pytest.mark.parametrize(
    "score,expected",
    [
        (0.95, Label.MALICIOUS),
        (0.70, Label.MALICIOUS),
        (0.55, Label.SUSPICIOUS),
        (0.40, Label.SUSPICIOUS),
        (0.10, Label.BENIGN),
        (0.0, Label.BENIGN),
    ],
)
def test_score_to_label(score, expected):
    assert score_to_label(score, settings) == expected


@pytest.mark.parametrize(
    "label,action",
    [
        (Label.BENIGN, Action.ALLOW),
        (Label.SUSPICIOUS, Action.FLAG),
        (Label.MALICIOUS, Action.BLOCK),
    ],
)
def test_label_to_action(label, action):
    assert label_to_action(label) == action


def test_ambiguous_band():
    assert in_ambiguous_band(0.5, settings) is True
    assert in_ambiguous_band(0.05, settings) is False  # clearly benign
    assert in_ambiguous_band(0.95, settings) is False  # clearly malicious
