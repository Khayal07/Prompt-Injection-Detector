"""Classification and latency metrics for the evaluation harness.

Positive class = malicious (label 1). All metrics are computed from a confusion matrix so
the definitions are explicit and auditable.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class ConfusionMatrix:
    """Counts of true/false positives/negatives (positive = malicious)."""

    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0

    @property
    def total(self) -> int:
        return self.tp + self.fp + self.tn + self.fn


@dataclass
class Metrics:
    """Computed classification + latency metrics."""

    confusion: ConfusionMatrix
    precision: float
    recall: float
    f1: float
    accuracy: float
    false_positive_rate: float
    latency_avg_ms: float
    latency_p50_ms: float
    latency_p95_ms: float
    classifier_calls: int = 0
    count: int = 0

    def to_dict(self) -> dict:
        return {
            "count": self.count,
            "confusion": {
                "tp": self.confusion.tp,
                "fp": self.confusion.fp,
                "tn": self.confusion.tn,
                "fn": self.confusion.fn,
            },
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
            "accuracy": round(self.accuracy, 4),
            "false_positive_rate": round(self.false_positive_rate, 4),
            "latency_avg_ms": round(self.latency_avg_ms, 2),
            "latency_p50_ms": round(self.latency_p50_ms, 2),
            "latency_p95_ms": round(self.latency_p95_ms, 2),
            "classifier_calls": self.classifier_calls,
        }


def _safe_div(numerator: float, denominator: float) -> float:
    return numerator / denominator if denominator else 0.0


def _percentile(sorted_values: list[float], pct: float) -> float:
    """Nearest-rank percentile of an already-sorted list."""
    if not sorted_values:
        return 0.0
    rank = max(0, min(len(sorted_values) - 1, round(pct / 100 * (len(sorted_values) - 1))))
    return sorted_values[rank]


def compute_metrics(
    y_true: list[int],
    y_pred: list[int],
    latencies_ms: list[float],
    classifier_calls: int = 0,
) -> Metrics:
    """Compute all metrics from paired true/predicted labels and per-item latencies."""
    cm = ConfusionMatrix()
    for true, pred in zip(y_true, y_pred, strict=False):
        if pred == 1 and true == 1:
            cm.tp += 1
        elif pred == 1 and true == 0:
            cm.fp += 1
        elif pred == 0 and true == 0:
            cm.tn += 1
        else:
            cm.fn += 1

    precision = _safe_div(cm.tp, cm.tp + cm.fp)
    recall = _safe_div(cm.tp, cm.tp + cm.fn)
    f1 = _safe_div(2 * precision * recall, precision + recall)
    accuracy = _safe_div(cm.tp + cm.tn, cm.total)
    fpr = _safe_div(cm.fp, cm.fp + cm.tn)

    latencies_sorted = sorted(latencies_ms)
    avg = _safe_div(sum(latencies_ms), len(latencies_ms))

    return Metrics(
        confusion=cm,
        precision=precision,
        recall=recall,
        f1=f1,
        accuracy=accuracy,
        false_positive_rate=fpr,
        latency_avg_ms=avg,
        latency_p50_ms=_percentile(latencies_sorted, 50),
        latency_p95_ms=_percentile(latencies_sorted, 95),
        classifier_calls=classifier_calls,
        count=len(y_true),
    )
