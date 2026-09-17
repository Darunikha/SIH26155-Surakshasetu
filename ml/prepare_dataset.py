"""Splits dataset/security_config_dataset.jsonl (5,000 rows, already shuffled)
into per-category train/val JSONL files under ml/datasets/<category>/, ready
for the QLoRA fine-tuning pipeline in ml/requirements.txt to consume.

The source dataset's `category` field doesn't match the ml/datasets/ folder
names 1:1 (e.g. "vendor_normalization" -> "normalization"), so this script
also owns that mapping.

Usage:
    python prepare_dataset.py [--val-fraction 0.1]
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "dataset" / "security_config_dataset.jsonl"
DEST_ROOT = Path(__file__).resolve().parent / "datasets"

# source `category` value -> destination folder name under ml/datasets/
CATEGORY_TO_FOLDER = {
    "finding_classification": "finding_classification",
    "remediation": "remediation",
    "security_explanation": "security_explanations",
    "vendor_normalization": "normalization",
    "cross_vendor_equivalence": "vendor_equivalence",
    "unknown_syntax": "unknown_syntax",
    "edge_cases": "edge_cases",
}


def load_rows() -> dict[str, list[dict]]:
    by_category: dict[str, list[dict]] = {cat: [] for cat in CATEGORY_TO_FOLDER}
    with open(SOURCE, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            row = json.loads(line)
            category = row.get("category")
            if category not in CATEGORY_TO_FOLDER:
                raise ValueError(f"Unknown category '{category}' in {SOURCE} -- update CATEGORY_TO_FOLDER")
            by_category[category].append(row)
    return by_category


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--val-fraction", type=float, default=0.1)
    args = parser.parse_args()

    if not SOURCE.exists():
        raise SystemExit(f"Source dataset not found at {SOURCE}. Run dataset/generate_dataset.py first.")

    by_category = load_rows()

    total_train = 0
    total_val = 0
    print(f"Splitting {SOURCE} into ml/datasets/<category>/{{train,val}}.jsonl (val fraction={args.val_fraction})\n")

    for category, folder in CATEGORY_TO_FOLDER.items():
        rows = by_category[category]
        split_idx = max(1, int(len(rows) * (1 - args.val_fraction))) if rows else 0
        train_rows, val_rows = rows[:split_idx], rows[split_idx:]

        dest_dir = DEST_ROOT / folder
        write_jsonl(dest_dir / "train.jsonl", train_rows)
        write_jsonl(dest_dir / "val.jsonl", val_rows)

        total_train += len(train_rows)
        total_val += len(val_rows)
        print(f"  {category:28s} -> ml/datasets/{folder}/  train={len(train_rows):4d}  val={len(val_rows):4d}")

    print(f"\nTotal: train={total_train}  val={total_val}  (source rows={sum(len(v) for v in by_category.values())})")
    print("\nReady for ml/requirements.txt's QLoRA pipeline. See dataset/README.md for schema and provenance notes.")


if __name__ == "__main__":
    main()
