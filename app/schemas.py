"""Pydantic request/response models for the /check API and internal verdicts."""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field


class Label(str, Enum):
    """Risk classification for an input."""

    BENIGN = "benign"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"


class Action(str, Enum):
    """Recommended action for the calling application to take."""

    ALLOW = "allow"
    FLAG = "flag"
    BLOCK = "block"


class CheckOptions(BaseModel):
    """Per-request overrides for the detection pipeline."""

    force_classifier: bool = Field(
        default=False,
        description="Invoke the LLM classifier even if heuristics are conclusive.",
    )
    disable_classifier: bool = Field(
        default=False,
        description="Skip the LLM classifier entirely (heuristics-only for this request).",
    )


class CheckRequest(BaseModel):
    """Input to POST /check."""

    text: str = Field(..., description="Raw user input to screen.", min_length=1)
    context: str | None = Field(
        default=None,
        description="Optional surrounding context (e.g. the app's system prompt) to help "
        "the classifier judge intent.",
    )
    options: CheckOptions = Field(default_factory=CheckOptions)


class MatchedRule(BaseModel):
    """A heuristic rule that fired against the input."""

    id: str
    category: str
    severity: str
    weight: float
    description: str


class ClassifierResult(BaseModel):
    """Outcome of the LLM classifier layer."""

    used: bool = Field(description="Whether the classifier was invoked for this request.")
    label: Label | None = None
    score: float | None = Field(
        default=None, description="Classifier risk score in [0, 1]."
    )
    reasoning: str | None = None
    provider: str | None = Field(
        default=None, description="Which provider answered (openai / openrouter)."
    )
    latency_ms: float | None = None
    error: str | None = Field(
        default=None, description="Populated when the classifier failed and was skipped."
    )


class CheckResponse(BaseModel):
    """Verdict returned by POST /check."""

    request_id: str
    risk_score: float = Field(description="Final blended risk score in [0, 1].")
    label: Label
    action: Action
    reasons: list[str] = Field(
        default_factory=list,
        description="Human-readable explanation of why this verdict was reached.",
    )
    heuristic_score: float
    matched_rules: list[MatchedRule] = Field(default_factory=list)
    classifier: ClassifierResult
    latency_ms: float


class HealthResponse(BaseModel):
    """Response for GET /health."""

    status: str
    database: str
    classifier_available: bool
    rules_loaded: int
