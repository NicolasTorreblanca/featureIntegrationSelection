import json
import numpy as np
import pandas as pd
from pathlib import Path
from pipeline.datasets import DatasetConfig
from train import run_experiment


def test_run_experiment_smoke(tmp_path):
    # Build a tiny GenS-style CSV (multiclass label) on disk
    rng = np.random.default_rng(0)
    n = 1200
    lab = ["normal"] * 800 + list(rng.choice(["dos", "xss"], size=400))
    df = pd.DataFrame({
        "f_good": (np.array([0]*800 + [1]*400) + rng.normal(0, 0.3, n)),
        "f_noise": rng.normal(size=n),
        "label": lab,
    })
    csv = tmp_path / "tiny.csv"
    df.to_csv(csv, index=False)
    cfg = DatasetConfig("TINY", str(csv), "label", "binary_normal", ())

    out_dir = tmp_path / "results" / "TINY"
    meta = run_experiment(
        cfg=cfg, out_dir=out_dir, k=2, seed=42,
        n_trials=2, n_subsample=300, K=2,
    )
    assert (out_dir / "selected_features.json").exists()
    assert (out_dir / "TINY_supervised_mccv.csv").exists()
    assert (out_dir / "TINY_unsupervised_mccv.csv").exists()
    assert (out_dir / "run_metadata.json").exists()
    assert (out_dir / "TINY_summary.csv").exists()
    assert meta["features_used"] == 2

    meta_on_disk = json.loads((out_dir / "run_metadata.json").read_text())
    assert "phase_seconds" in meta_on_disk and "total_seconds" in meta_on_disk
    assert meta_on_disk["phase_seconds"]  # non-empty
