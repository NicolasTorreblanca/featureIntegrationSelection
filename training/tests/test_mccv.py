import numpy as np
import pandas as pd
from pipeline.mccv import run_mccv, aggregate


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
