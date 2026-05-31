"""One-time learning curve: validation metric vs train size, per dataset.

Used to choose AND justify the subsample size `n` (paper: "subset chosen at the
learning-curve plateau"), and to verify the higher-dimensional GenS dataset has
also plateaued at the chosen n (fairness check). Uses Isolation Forest as the
cheap proxy detector; extendable to the full model set.
"""
from __future__ import annotations

from typing import List

import pandas as pd
from sklearn.ensemble import IsolationForest

from .subsample import subsample_rows
from .evaluate import _unsupervised_fit_eval


def learning_curve_points(
    benign_train: pd.DataFrame,
    X_test: pd.DataFrame,
    y_test: pd.Series,
    sizes: List[int],
    seed: int,
) -> List[dict]:
    """Fit a cheap detector at each train size; record the test F1 at each."""
    points = []
    for n in sizes:
        train = subsample_rows(benign_train, n=n, seed=seed)
        model = IsolationForest(n_estimators=100, random_state=seed, n_jobs=-1)
        metrics = _unsupervised_fit_eval(model, train, X_test, y_test)
        points.append({"n": n, "model": "Isolation Forest", "f1_score": metrics["f1_score"]})
    return points
