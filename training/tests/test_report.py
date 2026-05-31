import pandas as pd
from pipeline.report import per_dataset_table, cross_dataset_table


def test_per_dataset_table_one_row_per_model_metric():
    agg = {
        "f1_score_Decision Tree": {"mean": 0.9, "std": 0.01, "ci95_low": 0.88, "ci95_high": 0.92, "n": 20},
        "MCC_Decision Tree": {"mean": 0.8, "std": 0.02, "ci95_low": 0.78, "ci95_high": 0.82, "n": 20},
    }
    df = per_dataset_table(agg)
    assert {"model", "metric", "mean", "std", "ci95_low", "ci95_high"}.issubset(df.columns)
    assert len(df) == 2
    assert set(df["model"]) == {"Decision Tree"}


def test_cross_dataset_table_joins_on_model_metric():
    a = {"f1_score_Decision Tree": {"mean": 0.90, "std": 0, "ci95_low": 0, "ci95_high": 0, "n": 1}}
    b = {"f1_score_Decision Tree": {"mean": 0.95, "std": 0, "ci95_low": 0, "ci95_high": 0, "n": 1}}
    out = cross_dataset_table({"OG10": a, "GenS10": b})
    row = out[(out["model"] == "Decision Tree") & (out["metric"] == "f1_score")].iloc[0]
    assert abs(row["OG10"] - 0.90) < 1e-9
    assert abs(row["GenS10"] - 0.95) < 1e-9
