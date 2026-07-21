"""Run the detection pipeline over the labeled dataset and emit a metrics report.

Positive class = malicious. A prediction is counted positive when the pipeline returns a
non-benign label (i.e. it recommends flag or block).

Examples:
    python -m eval.run_eval                       # heuristics-only (offline, free)
    python -m eval.run_eval --full                # enable the LLM classifier cascade
    python -m eval.run_eval --full --limit 60     # cap classifier cost while sampling
"""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from app.config import BASE_DIR, get_settings
from app.detector.classifier import LLMClassifier
from app.detector.heuristics import HeuristicEngine
from app.detector.pipeline import DetectionPipeline
from app.schemas import CheckOptions, CheckRequest, Label
from eval.metrics import Metrics, compute_metrics

DEFAULT_DATASET = BASE_DIR / "data" / "eval_dataset.jsonl"
REPORTS_DIR = BASE_DIR / "eval" / "reports"


@dataclass
class Case:
    """One evaluated example with its true and predicted labels."""

    text: str
    category: str
    source: str
    y_true: int
    y_pred: int
    risk_score: float
    heuristic_score: float
    matched_rule_ids: list[str]
    classifier_used: bool
    classifier_reasoning: str | None
    latency_ms: float


def _load_dataset(path: Path) -> list[dict]:
    if not path.exists():
        raise SystemExit(
            f"dataset not found: {path}\nRun `python -m eval.build_dataset` first."
        )
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            rows.append(json.loads(line))
    return rows


def _predict(pipeline: DetectionPipeline, text: str, use_classifier: bool) -> Case | None:
    options = CheckOptions(disable_classifier=not use_classifier)
    resp = pipeline.run(CheckRequest(text=text, options=options))
    y_pred = 0 if resp.label == Label.BENIGN else 1
    return Case(
        text=text,
        category="",
        source="",
        y_true=0,
        y_pred=y_pred,
        risk_score=resp.risk_score,
        heuristic_score=resp.heuristic_score,
        matched_rule_ids=[r.id for r in resp.matched_rules],
        classifier_used=resp.classifier.used,
        classifier_reasoning=resp.classifier.reasoning,
        latency_ms=resp.latency_ms,
    )


def evaluate(dataset: list[dict], use_classifier: bool) -> tuple[Metrics, list[Case]]:
    settings = get_settings()
    engine = HeuristicEngine(settings.rules_path)
    classifier = LLMClassifier(settings)
    pipeline = DetectionPipeline(settings, engine, classifier)

    cases: list[Case] = []
    for row in dataset:
        case = _predict(pipeline, row["text"], use_classifier)
        case.category = row.get("category", "")
        case.source = row.get("source", "")
        case.y_true = int(row["label"])
        cases.append(case)

    metrics = compute_metrics(
        y_true=[c.y_true for c in cases],
        y_pred=[c.y_pred for c in cases],
        latencies_ms=[c.latency_ms for c in cases],
        classifier_calls=sum(1 for c in cases if c.classifier_used),
    )
    return metrics, cases


def _failures(cases: list[Case]) -> tuple[list[Case], list[Case]]:
    false_positives = [c for c in cases if c.y_true == 0 and c.y_pred == 1]
    false_negatives = [c for c in cases if c.y_true == 1 and c.y_pred == 0]
    return false_positives, false_negatives


def _render_markdown(metrics: Metrics, cases: list[Case], mode: str) -> str:
    m = metrics
    cm = m.confusion
    fps, fns = _failures(cases)
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    lines: list[str] = []
    lines.append("# Evaluation Report")
    lines.append("")
    lines.append(f"- **Generated:** {ts}")
    lines.append(f"- **Mode:** {mode}")
    lines.append(f"- **Dataset size:** {m.count} "
                 f"({cm.tp + cm.fn} malicious, {cm.tn + cm.fp} benign)")
    lines.append(f"- **Classifier calls:** {m.classifier_calls}")
    lines.append("")
    lines.append("## Metrics")
    lines.append("")
    lines.append("| Metric | Value |")
    lines.append("| --- | --- |")
    lines.append(f"| Precision | {m.precision:.3f} |")
    lines.append(f"| Recall | {m.recall:.3f} |")
    lines.append(f"| F1 | {m.f1:.3f} |")
    lines.append(f"| Accuracy | {m.accuracy:.3f} |")
    lines.append(f"| False-positive rate | {m.false_positive_rate:.3f} |")
    lines.append(f"| Latency avg | {m.latency_avg_ms:.2f} ms |")
    lines.append(f"| Latency p50 | {m.latency_p50_ms:.2f} ms |")
    lines.append(f"| Latency p95 | {m.latency_p95_ms:.2f} ms |")
    lines.append("")
    lines.append("## Confusion Matrix")
    lines.append("")
    lines.append("| | Predicted malicious | Predicted benign |")
    lines.append("| --- | --- | --- |")
    lines.append(f"| **Actual malicious** | {cm.tp} (TP) | {cm.fn} (FN) |")
    lines.append(f"| **Actual benign** | {cm.fp} (FP) | {cm.tn} (TN) |")
    lines.append("")
    lines.append("## Failure Analysis")
    lines.append("")
    lines.append(f"**False positives ({len(fps)})** — benign inputs flagged as risky:")
    lines.append("")
    lines += _render_failure_list(fps, is_fp=True)
    lines.append("")
    lines.append(f"**False negatives ({len(fns)})** — attacks that slipped through:")
    lines.append("")
    lines += _render_failure_list(fns, is_fp=False)
    lines.append("")
    lines += _methodology_notes()
    return "\n".join(lines)


def _methodology_notes() -> list[str]:
    """Static caveats that keep the report honest regardless of the run's numbers."""
    return [
        "## Methodology & Limitations",
        "",
        "- **Positive class = malicious.** A prediction counts as positive when the "
        "pipeline returns a non-benign label (flag or block).",
        "- **Dataset composition.** The benchmark mixes a curated seed set with "
        "template-generated synthetic examples. The synthetic portion shares structure "
        "with real attack families, so metrics on it are **optimistic** — treat them as "
        "an upper bound. Run `python -m eval.build_dataset --with-hf` to add independent "
        "public datasets for a less biased estimate.",
        "- **Cascade cost/coverage trade-off.** The LLM classifier is consulted only when "
        "the heuristic score is in the ambiguous band. Inputs the heuristics score at ~0 "
        "are treated as benign and never escalated; a novel attack that evades every rule "
        "can therefore bypass the classifier. Lowering `HEURISTIC_LOW_THRESHOLD` widens "
        "coverage at the cost of more LLM calls.",
        "- **Known weak spots.** Heavily obfuscated payloads, non-English attacks, and "
        "adversarial paraphrases that avoid known trigger words are the most likely "
        "misses. New patterns can be added to `config/rules.yaml` and hot-reloaded.",
        "",
    ]


def _render_failure_list(cases: list[Case], is_fp: bool, limit: int = 12) -> list[str]:
    if not cases:
        return ["_None._"]
    out: list[str] = []
    for c in cases[:limit]:
        text = c.text.replace("\n", " ")
        if len(text) > 140:
            text = text[:137] + "..."
        if is_fp:
            why = (
                f"fired rules {c.matched_rule_ids}"
                if c.matched_rule_ids
                else "classifier over-flagged"
            )
        else:
            why = (
                "no rule matched and heuristic score stayed below threshold"
                if not c.matched_rule_ids
                else f"matched {c.matched_rule_ids} but score below threshold"
            )
        out.append(f"- `{text}` — score={c.risk_score:.2f}; {why}")
    if len(cases) > limit:
        out.append(f"- _...and {len(cases) - limit} more._")
    return out


def _write_reports(metrics: Metrics, cases: list[Case], mode: str) -> tuple[Path, Path]:
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    md_path = REPORTS_DIR / "report.md"
    json_path = REPORTS_DIR / "report.json"

    md_path.write_text(_render_markdown(metrics, cases, mode), encoding="utf-8")

    fps, fns = _failures(cases)
    payload = {
        "mode": mode,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "metrics": metrics.to_dict(),
        "false_positives": [_case_dict(c) for c in fps],
        "false_negatives": [_case_dict(c) for c in fns],
    }
    json_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    return md_path, json_path


def _case_dict(c: Case) -> dict:
    return {
        "text": c.text,
        "category": c.category,
        "source": c.source,
        "risk_score": round(c.risk_score, 4),
        "heuristic_score": round(c.heuristic_score, 4),
        "matched_rule_ids": c.matched_rule_ids,
        "classifier_used": c.classifier_used,
        "classifier_reasoning": c.classifier_reasoning,
    }


def _main() -> None:
    parser = argparse.ArgumentParser(description="Run the detection benchmark.")
    parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
    parser.add_argument("--full", action="store_true",
                        help="Enable the LLM classifier cascade (needs an API key).")
    parser.add_argument("--limit", type=int, default=0,
                        help="Evaluate only the first N examples (0 = all).")
    args = parser.parse_args()

    dataset = _load_dataset(args.dataset)
    if args.limit > 0:
        dataset = dataset[: args.limit]

    mode = "full (heuristics + classifier)" if args.full else "heuristics-only"
    metrics, cases = evaluate(dataset, use_classifier=args.full)
    md_path, json_path = _write_reports(metrics, cases, mode)

    print(f"Mode: {mode}")
    print(json.dumps(metrics.to_dict(), indent=2))
    print(f"\nReports written:\n  {md_path}\n  {json_path}")


if __name__ == "__main__":
    _main()
