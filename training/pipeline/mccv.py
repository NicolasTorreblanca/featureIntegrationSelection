"""Monte-Carlo cross-validation evaluation protocol (thesis Cap. 3.2.9).

One canonical protocol replaces the five ad-hoc 'generations'. Each of K
iterations draws a fresh seeded split (seed = base + i), fits the requested
models, and records one metrics row. `aggregate` returns mean/std/95% CI per
metric so the across-iteration variance is the representativeness diagnostic.
"""
from __future__ import annotations

import inspect
from typing import Dict, List, Optional

import numpy as np
import pandas as pd
from scipy import stats
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.naive_bayes import GaussianNB
from sklearn.tree import DecisionTreeClassifier

from .evaluate import _row_from_model_metrics, _supervised_fit_eval, _unsupervised_fit_eval
from .subsample import subsample_rows

# Default supervised constructors used by unit tests with no tuning. The
# orchestrator injects tuned constructors instead (see Task 9).
_DEFAULT_SUP_CTORS = {
    "Decision Tree": lambda seed: DecisionTreeClassifier(random_state=seed),
    "Random Forest": lambda seed: RandomForestClassifier(n_estimators=50, random_state=seed, n_jobs=-1),
    "Naive Bayes": lambda seed: GaussianNB(),
}


def _callable_takes_seed(fn) -> bool:
    """True if constructor accepts >= 1 argument (test defaults do; frozen lambdas may not)."""
    try:
        return len(inspect.signature(fn).parameters) >= 1
    except (TypeError, ValueError):
        return False


def run_mccv(
    X: pd.DataFrame,
    y: pd.Series,
    models: List[str],
    K: int,
    seed: int,
    constructors: Optional[dict] = None,
) -> List[dict]:
    """Supervised MCCV: K fresh stratified 80/20 splits, one metrics row each."""
    ctors = constructors or _DEFAULT_SUP_CTORS
    Xv, yv = X.values, y.values
    rows = []
    for i in range(K):
        s = seed + i
        X_tr, X_te, y_tr, y_te = train_test_split(
            Xv, yv, test_size=0.2, stratify=yv, random_state=s
        )
        per_model = {}
        for name in models:
            model = ctors[name](s) if _callable_takes_seed(ctors[name]) else ctors[name]()
            per_model[name] = _supervised_fit_eval(model, X_tr, y_tr, X_te, y_te)
        row = {"iteration": i + 1}
        row.update(_row_from_model_metrics(per_model))
        rows.append(row)
    return rows


def aggregate(rows: List[dict]) -> Dict[str, dict]:
    """Mean, std, and 95% CI per numeric metric column across iterations."""
    if not rows:
        return {}
    metric_keys = [k for k in rows[0] if k != "iteration"]
    out: Dict[str, dict] = {}
    for k in metric_keys:
        vals = np.array([r[k] for r in rows if r.get(k) is not None], dtype=float)
        vals = vals[~np.isnan(vals)]
        if len(vals) == 0:
            continue
        mean = float(np.mean(vals))
        std = float(np.std(vals, ddof=1)) if len(vals) > 1 else 0.0
        if len(vals) > 1:
            sem = std / np.sqrt(len(vals))
            h = sem * stats.t.ppf(0.975, len(vals) - 1)
        else:
            h = 0.0
        out[k] = {"mean": mean, "std": std, "ci95_low": mean - h, "ci95_high": mean + h, "n": len(vals)}
    return out


def run_mccv_unsupervised(
    benign_train: pd.DataFrame,
    X_test: pd.DataFrame,
    y_test: pd.Series,
    constructors: dict,
    K: int,
    seed: int,
    n_subsample: int,
) -> List[dict]:
    """Unsupervised MCCV: each iteration resamples benign train to n_subsample (seeded).

    NOTE: `constructors` values must be ZERO-ARG callables (e.g. `lambda: Model(...)`),
    unlike run_mccv which also accepts seed-taking constructors. They are called as ctor().
    """
    rows = []
    for i in range(K):
        s = seed + i
        train = subsample_rows(benign_train, n=n_subsample, seed=s)
        per_model = {}
        for name, ctor in constructors.items():
            per_model[name] = _unsupervised_fit_eval(ctor(), train, X_test, y_test)
        row = {"iteration": i + 1}
        row.update(_row_from_model_metrics(per_model))
        rows.append(row)
    return rows
