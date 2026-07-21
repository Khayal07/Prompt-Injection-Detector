"""Detection pipeline: orchestrates the heuristic → cascade → classifier → scoring flow.

This is the single entry point the API calls. It decides — per the cascade policy — whether
the LLM classifier is consulted, blends the scores, and produces the final verdict.
"""

from __future__ import annotations

import time
import uuid

from app.config import Settings
from app.detector.classifier import LLMClassifier
from app.detector.heuristics import HeuristicEngine
from app.detector.rules_loader import Rule
from app.detector.scoring import (
    blend_scores,
    in_ambiguous_band,
    label_to_action,
    score_to_label,
)
from app.schemas import (
    CheckRequest,
    CheckResponse,
    ClassifierResult,
    MatchedRule,
)


class DetectionPipeline:
    """Coordinates the heuristic and classifier layers into one verdict."""

    def __init__(
        self,
        settings: Settings,
        engine: HeuristicEngine,
        classifier: LLMClassifier,
    ):
        self._settings = settings
        self._engine = engine
        self._classifier = classifier

    @property
    def engine(self) -> HeuristicEngine:
        return self._engine

    def run(self, request: CheckRequest) -> CheckResponse:
        """Screen one request and return the full verdict."""
        start = time.perf_counter()
        settings = self._settings

        heuristic = self._engine.evaluate(request.text)
        reasons = list(heuristic.reasons())

        classifier_result = ClassifierResult(used=False)
        if self._should_classify(heuristic.score, request):
            classifier_result = self._classifier.classify(request.text, request.context)
            if classifier_result.used and classifier_result.reasoning:
                reasons.append(f"[classifier:{classifier_result.provider}] "
                               f"{classifier_result.reasoning}")
            elif classifier_result.error:
                reasons.append(f"[classifier] skipped: {classifier_result.error}")

        classifier_score = (
            classifier_result.score if classifier_result.used else None
        )
        final_score = blend_scores(
            heuristic.score, classifier_score, settings.classifier_weight
        )
        label = score_to_label(final_score, settings)
        action = label_to_action(label)

        if not reasons:
            reasons.append("No injection patterns detected.")

        latency_ms = (time.perf_counter() - start) * 1000.0
        return CheckResponse(
            request_id=uuid.uuid4().hex,
            risk_score=round(final_score, 4),
            label=label,
            action=action,
            reasons=reasons,
            heuristic_score=round(heuristic.score, 4),
            matched_rules=[_to_matched_rule(r) for r in heuristic.matched],
            classifier=classifier_result,
            latency_ms=round(latency_ms, 2),
        )

    def _should_classify(self, heuristic_score: float, request: CheckRequest) -> bool:
        """Cascade policy: decide whether to invoke the LLM classifier."""
        if request.options.disable_classifier:
            return False
        if not self._classifier.available:
            return False
        if request.options.force_classifier:
            return True
        return in_ambiguous_band(heuristic_score, self._settings)


def _to_matched_rule(rule: Rule) -> MatchedRule:
    return MatchedRule(
        id=rule.id,
        category=rule.category,
        severity=rule.severity,
        weight=rule.weight,
        description=rule.description,
    )
