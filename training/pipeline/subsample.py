"""Deterministic subsampling for the hybrid speed strategy.

Supervised models train on full data; the O(n^2) unsupervised benign training
set is subsampled to `n` rows, identically (same n, same seed scheme) across
all datasets so the cross-dataset comparison stays fair.
"""
from __future__ import annotations

import pandas as pd


def subsample_rows(df: pd.DataFrame, n: int, seed: int) -> pd.DataFrame:
    """Return a deterministic random subsample of `n` rows (no-op if len <= n).

    benign_train is single-class, so a plain seeded sample is the correct
    stratification. Reset index so downstream positional ops are stable.
    """
    if n is None or len(df) <= n:
        return df
    return df.sample(n=n, random_state=seed).reset_index(drop=True)
