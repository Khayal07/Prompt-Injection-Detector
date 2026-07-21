"""Unit tests for the evaluation metrics."""

from __future__ import annotations

import pytest

from eval.metrics import compute_metrics


def test_perfect_classifier():
    m = compute_metrics([1, 1, 0, 0], [1, 1, 0, 0], [1.0, 2.0, 3.0, 4.0])
    assert m.precision == 1.0
    assert m.recall == 1.0
    assert m.f1 == 1.0
    assert m.accuracy == 1.0
    assert m.false_positive_rate == 0.0


def test_confusion_counts_and_fpr():
    # true:  1 1 0 0 1
    # pred:  1 0 1 0 1  -> tp=2, fn=1, fp=1, tn=1
    m = compute_metrics([1, 1, 0, 0, 1], [1, 0, 1, 0, 1], [1.0] * 5)
    assert (m.confusion.tp, m.confusion.fn, m.confusion.fp, m.confusion.tn) == (2, 1, 1, 1)
    assert m.precision == pytest.approx(2 / 3)
    assert m.recall == pytest.approx(2 / 3)
    assert m.false_positive_rate == pytest.approx(1 / 2)


def test_latency_percentiles():
    latencies = [float(x) for x in range(1, 101)]  # 1..100
    m = compute_metrics([0] * 100, [0] * 100, latencies)
    assert m.latency_avg_ms == pytest.approx(50.5)
    assert m.latency_p50_ms == pytest.approx(50.0, abs=1.0)
    assert m.latency_p95_ms == pytest.approx(96.0, abs=1.0)


def test_all_negative_predictions_have_zero_precision():
    m = compute_metrics([1, 1], [0, 0], [1.0, 1.0])
    assert m.precision == 0.0
    assert m.recall == 0.0
    assert m.f1 == 0.0


def test_to_dict_shape():
    m = compute_metrics([1, 0], [1, 0], [5.0, 7.0], classifier_calls=1)
    d = m.to_dict()
    assert d["confusion"] == {"tp": 1, "fp": 0, "tn": 1, "fn": 0}
    assert d["classifier_calls"] == 1
    assert set(d) >= {"precision", "recall", "f1", "accuracy", "false_positive_rate"}
