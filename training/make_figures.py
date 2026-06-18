"""Generate publication figures from the clean MCCV results.

Reads results/<DS>/<DS>_summary.csv (mean+std per model per metric) and the
learning-curve CSVs, and writes PNG (300 dpi) + PDF to results/figures/.
Print-friendly: colorblind-safe Okabe-Ito palette + hatching for grayscale.
"""
from pathlib import Path
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

ROOT = Path(__file__).resolve().parent
RESULTS = ROOT / "results"
FIGDIR = RESULTS / "figures"
FIGDIR.mkdir(parents=True, exist_ok=True)

DATASETS = ["OG10", "Gen10", "GenS10"]
DS_LABEL = {"OG10": "OG10 (original)", "Gen10": "Gen10 (manual)", "GenS10": "GenS10 (SHAP)"}
# Okabe-Ito colorblind-safe palette + distinct hatches for grayscale print
STYLE = {
    "OG10":   {"color": "#999999", "hatch": ""},
    "Gen10":  {"color": "#0072B2", "hatch": "//"},
    "GenS10": {"color": "#D55E00", "hatch": ".."},
}
MODEL_ORDER = ["Random Forest", "Decision Tree", "Naive Bayes",
               "Isolation Forest", "One-Class SVM", "Local Outlier Factor", "Elliptic Envelope"]
MODEL_SHORT = {"Random Forest": "RF", "Decision Tree": "DT", "Naive Bayes": "NB",
               "Isolation Forest": "IF", "One-Class SVM": "OCSVM",
               "Local Outlier Factor": "LOF", "Elliptic Envelope": "EE"}

summ = {ds: pd.read_csv(RESULTS / ds / f"{ds}_summary.csv") for ds in DATASETS}


def stat(ds, model, metric, col="mean"):
    d = summ[ds]
    v = d[(d.model == model) & (d.metric == metric)]
    return float(v[col].iloc[0]) if len(v) else np.nan


def grouped_bar(metric, title, fname):
    x = np.arange(len(MODEL_ORDER))
    w = 0.26
    fig, ax = plt.subplots(figsize=(10, 5))
    for i, ds in enumerate(DATASETS):
        means = [stat(ds, m, metric, "mean") for m in MODEL_ORDER]
        stds = [stat(ds, m, metric, "std") for m in MODEL_ORDER]
        ax.bar(x + (i - 1) * w, means, w, yerr=stds, capsize=3,
               label=DS_LABEL[ds], color=STYLE[ds]["color"],
               hatch=STYLE[ds]["hatch"], edgecolor="black", linewidth=0.5,
               error_kw={"elinewidth": 0.8})
    ax.set_xticks(x)
    ax.set_xticklabels([MODEL_SHORT[m] for m in MODEL_ORDER])
    ax.set_ylabel(title)
    ax.set_title(f"{title} by model across datasets (mean ± std, 20 MCCV iterations)")
    ax.axhline(0, color="black", linewidth=0.5)
    ax.legend(loc="lower right", framealpha=0.95)
    ax.grid(axis="y", linestyle=":", alpha=0.5)
    fig.tight_layout()
    for ext in ("png", "pdf"):
        fig.savefig(FIGDIR / f"{fname}.{ext}", dpi=300, bbox_inches="tight")
    plt.close(fig)
    print(f"  wrote {fname}.png / .pdf")


def stability_fig():
    """Std of MCC per model per dataset — the variance-stabilization story."""
    x = np.arange(len(MODEL_ORDER))
    w = 0.26
    fig, ax = plt.subplots(figsize=(10, 4.5))
    for i, ds in enumerate(DATASETS):
        stds = [stat(ds, m, "MCC", "std") for m in MODEL_ORDER]
        ax.bar(x + (i - 1) * w, stds, w, label=DS_LABEL[ds],
               color=STYLE[ds]["color"], hatch=STYLE[ds]["hatch"],
               edgecolor="black", linewidth=0.5)
    ax.set_xticks(x)
    ax.set_xticklabels([MODEL_SHORT[m] for m in MODEL_ORDER])
    ax.set_ylabel("MCC std across MCCV iterations")
    ax.set_title("Result stability: lower = more reliable (integration shrinks variance)")
    ax.legend(framealpha=0.95)
    ax.grid(axis="y", linestyle=":", alpha=0.5)
    fig.tight_layout()
    for ext in ("png", "pdf"):
        fig.savefig(FIGDIR / f"fig_stability_mcc_std.{ext}", dpi=300, bbox_inches="tight")
    plt.close(fig)
    print("  wrote fig_stability_mcc_std.png / .pdf")


def learning_curve_fig():
    files = {ds: RESULTS / ds / f"{ds}_learning_curve.csv" for ds in ("OG10", "GenS10")}
    if not all(p.exists() for p in files.values()):
        print("  (skipped learning curve - csv not found for both datasets)")
        return
    fig, ax = plt.subplots(figsize=(7, 4.5))
    for ds, p in files.items():
        d = pd.read_csv(p)
        ax.plot(d["n"], d["f1_score"], marker="o", label=DS_LABEL[ds],
                color=STYLE[ds]["color"])
    ax.axvline(10000, color="black", linestyle="--", linewidth=0.8, label="chosen N = 10,000")
    ax.set_xlabel("benign training subsample size (N)")
    ax.set_ylabel("Isolation Forest F1 (proxy)")
    ax.set_title("Learning curve: F1 saturates by N = 10,000 (subsample justification)")
    ax.legend()
    ax.grid(linestyle=":", alpha=0.5)
    fig.tight_layout()
    for ext in ("png", "pdf"):
        fig.savefig(FIGDIR / f"fig_learning_curve.{ext}", dpi=300, bbox_inches="tight")
    plt.close(fig)
    print("  wrote fig_learning_curve.png / .pdf")


if __name__ == "__main__":
    print(f"Writing figures to {FIGDIR}")
    grouped_bar("MCC", "MCC", "fig_mcc_by_model")
    grouped_bar("f1_score", "F1-score", "fig_f1_by_model")
    grouped_bar("auc", "AUC-ROC", "fig_auc_by_model")
    stability_fig()
    learning_curve_fig()
    print("done.")
