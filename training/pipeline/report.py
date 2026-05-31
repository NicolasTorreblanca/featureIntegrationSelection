"""Report tables. Metric columns are named `{metric}_{model}`; we split them
back into (model, metric) for human-readable per-dataset and cross-dataset views.
"""
from __future__ import annotations

from typing import Dict

import pandas as pd

# Canonical model names (longest-match split so 'Decision Tree' isn't cut at the space)
MODEL_NAMES = [
    "Random Forest", "Decision Tree", "Naive Bayes",
    "Isolation Forest", "One-Class SVM", "Local Outlier Factor", "Elliptic Envelope",
]


def _split_key(key: str):
    for m in MODEL_NAMES:
        if key.endswith("_" + m):
            return m, key[: -(len(m) + 1)]
    # fallback: split on last underscore
    metric, _, model = key.rpartition("_")
    return model, metric


def per_dataset_table(agg: Dict[str, dict]) -> pd.DataFrame:
    rows = []
    for key, stats in agg.items():
        model, metric = _split_key(key)
        rows.append({"model": model, "metric": metric, **stats})
    return pd.DataFrame(rows)


def cross_dataset_table(aggs_by_dataset: Dict[str, Dict[str, dict]]) -> pd.DataFrame:
    frames = []
    for tag, agg in aggs_by_dataset.items():
        t = per_dataset_table(agg)[["model", "metric", "mean"]].rename(columns={"mean": tag})
        frames.append(t.set_index(["model", "metric"]))
    out = pd.concat(frames, axis=1).reset_index()
    return out
