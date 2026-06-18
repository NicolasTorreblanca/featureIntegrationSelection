"""Reshape the per-dataset MCCV outputs into ONE tidy long CSV for plotting.

Reads results/<DS>/<DS>_{supervised,unsupervised}_mccv.csv (wide: one column per
`{metric}_{model}`, one row per MCCV iteration) and writes results/results_long.csv:

    dataset, model, metric, iteration, value

This long/tidy shape is what seaborn consumes directly (one row per observation),
so plot_results.py can let seaborn compute means + error bars from the 20 iterations.
"""
from pathlib import Path
import pandas as pd

ROOT = Path(__file__).resolve().parent
RESULTS = ROOT / "results"
DATASETS = ["OG10", "Gen10", "GenS10"]

# Longest-match so multi-word model names (e.g. "Decision Tree") aren't split at the space.
MODEL_NAMES = [
    "Random Forest", "Decision Tree", "Naive Bayes",
    "Isolation Forest", "One-Class SVM", "Local Outlier Factor", "Elliptic Envelope",
]


def split_key(col: str):
    for m in MODEL_NAMES:
        if col.endswith("_" + m):
            return col[: -(len(m) + 1)], m       # (metric, model)
    metric, _, model = col.rpartition("_")
    return metric, model


def main():
    rows = []
    for ds in DATASETS:
        for kind in ("supervised", "unsupervised"):
            p = RESULTS / ds / f"{ds}_{kind}_mccv.csv"
            if not p.exists():
                print(f"  (skip missing {p})")
                continue
            df = pd.read_csv(p)
            for col in df.columns:
                if col == "iteration":
                    continue
                metric, model = split_key(col)
                for _, r in df.iterrows():
                    rows.append({
                        "dataset": ds, "model": model, "metric": metric,
                        "iteration": int(r["iteration"]), "value": r[col],
                    })
    out = pd.DataFrame(rows)
    dest = RESULTS / "results_long.csv"
    out.to_csv(dest, index=False)
    print(f"wrote {dest}  ({len(out)} rows, "
          f"{out['metric'].nunique()} metrics, {out['model'].nunique()} models, "
          f"{out['dataset'].nunique()} datasets)")


if __name__ == "__main__":
    main()
