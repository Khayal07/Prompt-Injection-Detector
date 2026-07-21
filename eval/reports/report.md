# Evaluation Report

- **Generated:** 2026-07-21 19:38 UTC
- **Mode:** full (heuristics + classifier)
- **Dataset size:** 172 (89 malicious, 83 benign)
- **Classifier calls:** 30

## Metrics

| Metric | Value |
| --- | --- |
| Precision | 1.000 |
| Recall | 1.000 |
| F1 | 1.000 |
| Accuracy | 1.000 |
| False-positive rate | 0.000 |
| Latency avg | 209.43 ms |
| Latency p50 | 0.18 ms |
| Latency p95 | 1162.89 ms |

## Confusion Matrix

| | Predicted malicious | Predicted benign |
| --- | --- | --- |
| **Actual malicious** | 89 (TP) | 0 (FN) |
| **Actual benign** | 0 (FP) | 83 (TN) |

## Failure Analysis

**False positives (0)** — benign inputs flagged as risky:

_None._

**False negatives (0)** — attacks that slipped through:

_None._

## Methodology & Limitations

- **Positive class = malicious.** A prediction counts as positive when the pipeline returns a non-benign label (flag or block).
- **Dataset composition.** The benchmark mixes a curated seed set with template-generated synthetic examples. The synthetic portion shares structure with real attack families, so metrics on it are **optimistic** — treat them as an upper bound. Run `python -m eval.build_dataset --with-hf` to add independent public datasets for a less biased estimate.
- **Cascade cost/coverage trade-off.** The LLM classifier is consulted only when the heuristic score is in the ambiguous band. Inputs the heuristics score at ~0 are treated as benign and never escalated; a novel attack that evades every rule can therefore bypass the classifier. Lowering `HEURISTIC_LOW_THRESHOLD` widens coverage at the cost of more LLM calls.
- **Known weak spots.** Heavily obfuscated payloads, non-English attacks, and adversarial paraphrases that avoid known trigger words are the most likely misses. New patterns can be added to `config/rules.yaml` and hot-reloaded.
