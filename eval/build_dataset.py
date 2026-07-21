"""Assemble the labeled evaluation dataset.

Combines the committed seed examples with generated synthetic examples, and optionally
augments with public Hugging Face datasets (``--with-hf``). Output is a single JSONL file
(``data/eval_dataset.jsonl``) with one ``{text, label, source, category}`` object per line.

Examples:
    python -m eval.build_dataset                 # seed + synthetic (offline, reproducible)
    python -m eval.build_dataset --synthetic 200 # more synthetic examples
    python -m eval.build_dataset --with-hf       # also pull public HF datasets
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from app.config import BASE_DIR
from data.generate_synthetic import generate

SEED_DIR = BASE_DIR / "data" / "seed"
DEFAULT_OUTPUT = BASE_DIR / "data" / "eval_dataset.jsonl"

# Public datasets pulled only when --with-hf is passed. Kept small and well-known.
_HF_SOURCES = [
    # (dataset repo, split, text column, label column, mapping fn description)
    ("deepset/prompt-injections", "train", "text", "label"),
    ("jackhhao/jailbreak-classification", "train", "prompt", "type"),
]


def _read_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            rows.append(json.loads(line))
    return rows


def load_seed() -> list[dict]:
    """Load the curated seed injection + benign examples."""
    return _read_jsonl(SEED_DIR / "injections.jsonl") + _read_jsonl(
        SEED_DIR / "benign.jsonl"
    )


def load_hf() -> list[dict]:
    """Load and normalise public Hugging Face datasets. Requires network + `datasets`."""
    try:
        from datasets import load_dataset  # type: ignore
    except ImportError as exc:  # pragma: no cover - optional dependency
        raise SystemExit(
            "The 'datasets' package is required for --with-hf. "
            "Install it with: pip install datasets"
        ) from exc

    examples: list[dict] = []
    for repo, split, text_col, label_col in _HF_SOURCES:
        ds = load_dataset(repo, split=split)
        for row in ds:
            text = str(row.get(text_col, "")).strip()
            if not text:
                continue
            label = _normalise_hf_label(row.get(label_col))
            if label is None:
                continue
            examples.append(
                {"text": text, "label": label, "source": f"hf:{repo}",
                 "category": "hf"}
            )
    return examples


def _normalise_hf_label(value) -> int | None:
    """Map a Hugging Face label (int or string) to our 1=malicious / 0=benign scheme."""
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, (int, float)):
        return 1 if int(value) == 1 else 0
    if isinstance(value, str):
        v = value.strip().lower()
        if v in {"1", "injection", "jailbreak", "malicious", "harmful", "true"}:
            return 1
        if v in {"0", "benign", "legitimate", "safe", "false"}:
            return 0
    return None


def _dedupe(examples: list[dict]) -> list[dict]:
    """Drop exact-duplicate texts, keeping first occurrence."""
    seen: set[str] = set()
    unique: list[dict] = []
    for ex in examples:
        key = ex["text"].strip().lower()
        if key not in seen:
            seen.add(key)
            unique.append(ex)
    return unique


def build(synthetic_count: int, with_hf: bool, output: Path) -> dict:
    """Build the dataset and write it to `output`. Returns a summary."""
    examples = load_seed()
    examples += generate(synthetic_count)
    if with_hf:
        examples += load_hf()

    examples = _dedupe(examples)

    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8") as fh:
        for ex in examples:
            fh.write(json.dumps(ex, ensure_ascii=False) + "\n")

    malicious = sum(1 for e in examples if e["label"] == 1)
    return {
        "total": len(examples),
        "malicious": malicious,
        "benign": len(examples) - malicious,
        "output": str(output),
    }


def _main() -> None:
    parser = argparse.ArgumentParser(description="Build the evaluation dataset.")
    parser.add_argument("--synthetic", type=int, default=120,
                        help="Number of synthetic examples to generate (default 120).")
    parser.add_argument("--with-hf", action="store_true",
                        help="Augment with public Hugging Face datasets (needs network).")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()

    summary = build(args.synthetic, args.with_hf, args.output)
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    _main()
