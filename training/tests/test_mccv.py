import numpy as np
import pandas as pd
from pipeline.mccv import run_mccv, run_mccv_unsupervised, aggregate


def _supervised_data(n=1500):
    rng = np.random.default_rng(0)
    y = rng.integers(0, 2, size=n)
    X = pd.DataFrame({"f1": y + rng.normal(0, 0.5, n), "f2": rng.normal(0, 1, n)})
    return X, pd.Series(y, name="category")


def test_mccv_runs_k_iterations_and_is_deterministic():
    X, y = _supervised_data()
    rows_a = run_mccv(X, y, models=["Decision Tree"], K=3, seed=42)
    rows_b = run_mccv(X, y, models=["Decision Tree"], K=3, seed=42)
    assert len(rows_a) == 3
    # determinism: identical metric values across two runs with same seed
    assert [r["f1_score_Decision Tree"] for r in rows_a] == \
           [r["f1_score_Decision Tree"] for r in rows_b]


def test_aggregate_reports_mean_std_ci():
    rows = [{"f1_score_DT": 0.8}, {"f1_score_DT": 0.9}, {"f1_score_DT": 0.85}]
    agg = aggregate(rows)
    assert abs(agg["f1_score_DT"]["mean"] - 0.85) < 1e-9
    assert agg["f1_score_DT"]["std"] > 0
    assert "ci95_low" in agg["f1_score_DT"] and "ci95_high" in agg["f1_score_DT"]


def test_run_mccv_accepts_zero_arg_constructors():
    """Task 9 injects zero-arg frozen constructors; run_mccv must call them with no args."""
    from sklearn.tree import DecisionTreeClassifier
    X, y = _supervised_data()
    ctors = {"Decision Tree": lambda: DecisionTreeClassifier(random_state=0)}
    rows = run_mccv(X, y, models=["Decision Tree"], K=2, seed=42, constructors=ctors)
    assert len(rows) == 2
    assert "f1_score_Decision Tree" in rows[0]


def test_run_mccv_unsupervised_runs_and_is_deterministic():
    from sklearn.ensemble import IsolationForest
    rng = np.random.default_rng(0)
    benign = pd.DataFrame({"f1": rng.normal(0, 1, size=2000), "f2": rng.normal(0, 1, size=2000)})
    X_test = pd.DataFrame({"f1": rng.normal(0, 1, size=400), "f2": rng.normal(0, 1, size=400)})
    y_test = pd.Series(rng.integers(0, 2, size=400), name="category")
    ctors = {"Isolation Forest": lambda: IsolationForest(n_estimators=20, random_state=0)}
    a = run_mccv_unsupervised(benign, X_test, y_test, ctors, K=2, seed=42, n_subsample=500)
    b = run_mccv_unsupervised(benign, X_test, y_test, ctors, K=2, seed=42, n_subsample=500)
    assert len(a) == 2
    assert "f1_score_Isolation Forest" in a[0]
    assert [r["f1_score_Isolation Forest"] for r in a] == \
           [r["f1_score_Isolation Forest"] for r in b]
