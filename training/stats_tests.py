"""
Statistical validation of the clean MCCV results (matches the thesis's approach:
Shapiro-Wilk for normality, Wilcoxon signed-rank for paired differences, plus a
Friedman test across the three datasets).

Input : results/results_long.csv  (dataset, model, metric, iteration, value)
Output: results/stats_tests.csv   (per model+metric+pair: shapiro/wilcoxon/friedman p)
        + a printed summary.

Pairing is by MCCV iteration index (each iteration uses the same seed base+i across
datasets), consistent with comparing methods over shared cross-validation folds.
"""
from pathlib import Path
import warnings
import numpy as np
import pandas as pd
from scipy.stats import shapiro, wilcoxon, friedmanchisquare

warnings.filterwarnings("ignore")
ROOT = Path(__file__).resolve().parent
RESULTS = ROOT / "results"

DATASETS = ["OG10", "Gen10", "GenS10"]
MODELS = ["Random Forest", "Decision Tree", "Naive Bayes",
          "Isolation Forest", "One-Class SVM", "Local Outlier Factor", "Elliptic Envelope"]
METRICS = ["MCC", "f1_score", "auc"]
PAIRS = [("OG10", "Gen10"), ("OG10", "GenS10"), ("Gen10", "GenS10")]


def main():
    df = pd.read_csv(RESULTS / "results_long.csv")

    def vals(ds, m, met):
        s = df[(df.dataset == ds) & (df.model == m) & (df.metric == met)].sort_values("iteration")["value"]
        return s.values

    rows = []
    for met in METRICS:
        for m in MODELS:
            v = {ds: vals(ds, m, met) for ds in DATASETS}
            # Friedman across the three datasets
            try:
                fried_p = friedmanchisquare(v["OG10"], v["Gen10"], v["GenS10"]).pvalue
            except Exception:
                fried_p = float("nan")
            for a, b in PAIRS:
                x, y = v[a], v[b]
                # normality of the paired differences
                try:
                    shap_p = shapiro(y - x).pvalue if not np.allclose(y - x, 0) else 1.0
                except Exception:
                    shap_p = float("nan")
                # paired Wilcoxon signed-rank
                try:
                    wil_p = 1.0 if np.allclose(y - x, 0) else wilcoxon(x, y).pvalue
                except Exception:
                    wil_p = float("nan")
                rows.append({
                    "metric": met, "model": m, "comparison": f"{a} vs {b}",
                    "mean_diff": float(np.mean(y) - np.mean(x)),
                    "shapiro_p_diff": shap_p, "wilcoxon_p": wil_p, "friedman_p": fried_p,
                    "significant_0.05": bool(wil_p < 0.05),
                })
    out = pd.DataFrame(rows)
    out.to_csv(RESULTS / "stats_tests.csv", index=False)

    mcc = out[out.metric == "MCC"]
    nsig = int(mcc["significant_0.05"].sum())
    print(f"wrote {RESULTS / 'stats_tests.csv'}")
    print(f"MCC: {nsig}/{len(mcc)} pairwise comparisons significant at p<0.05")
    print(f"MCC: max Wilcoxon p = {mcc['wilcoxon_p'].max():.2e} (worst case)")


if __name__ == "__main__":
    main()
