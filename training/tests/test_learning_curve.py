import numpy as np
import pandas as pd
from pipeline.learning_curve import learning_curve_points


def test_returns_one_point_per_size_with_metric():
    rng = np.random.default_rng(0)
    n = 4000
    y = rng.integers(0, 2, size=n)
    benign = pd.DataFrame({"f1": rng.normal(size=n)})  # unsup uses benign-only train
    X_test = pd.DataFrame({"f1": rng.normal(size=800)})
    y_test = pd.Series(rng.integers(0, 2, size=800))
    pts = learning_curve_points(
        benign_train=benign[y == 0].reset_index(drop=True),
        X_test=X_test, y_test=y_test,
        sizes=[200, 500, 1000], seed=42,
    )
    assert [p["n"] for p in pts] == [200, 500, 1000]
    assert all("f1_score" in p and "model" in p for p in pts)
