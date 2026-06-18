"""
plot_results.py — configurable figures from results_long.csv (seaborn + matplotlib).

Pipeline:  python build_results_long.py   # once, builds results/results_long.csv
           python plot_results.py          # renders the figures

Produces, split into SUPERVISED and UNSUPERVISED panels (so nothing is overcrowded):
  - raw metric bars (MCC, F1, AUC) with error bars
  - % metric improvement vs the OG10 baseline
  - % time change vs OG10 (positive = faster)
  - learning curve (subsample justification)

EVERYTHING visual lives in the CONFIG block — edit colors/labels/sizes there.
"""
from pathlib import Path
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

# ============================ CONFIG (edit me) ============================
INPUT_CSV = "results/results_long.csv"      # tidy: dataset,model,metric,iteration,value
SUMMARY_DIR = "results"                      # contains <DS>/<DS>_summary.csv
OUTDIR    = "results/figures_pretty"
FORMATS   = ["png", "pdf"]
DPI       = 300

# ---- seaborn look & feel ----
SNS_STYLE   = "whitegrid"
SNS_CONTEXT = "talk"
FONT_SCALE  = 0.85
FONT_FAMILY = "DejaVu Sans"
DESPINE     = True

# ---- colors: one per dataset (light -> dark green, encodes OG10<Gen10<GenS10) ----
PALETTE = {
    "OG10":   "#4bf2ae",       # bright mint  (baseline)
    "Gen10":  "#46c792",       # mid teal-green (manual integration)
    "GenS10": "#2e6e54",       # deep emerald (SHAP integration)
}
BAR_EDGECOLOR = "none"
BAR_EDGEWIDTH = 0

# ---- datasets ----
DATASET_ORDER  = ["OG10", "Gen10", "GenS10"]
DATASET_LABELS = {"OG10": "OG10 (original)", "Gen10": "Gen10 (manual)", "GenS10": "GenS10 (SHAP)"}
BASELINE = "OG10"              # reference for % improvement / % time change

# ---- models, grouped to keep each figure readable ----
MODEL_GROUPS = {
    "Supervised":   ["Random Forest", "Decision Tree", "Naive Bayes"],
    "Unsupervised": ["Isolation Forest", "One-Class SVM", "Local Outlier Factor", "Elliptic Envelope"],
}
MODEL_LABELS = {
    "Random Forest": "RF", "Decision Tree": "DT", "Naive Bayes": "NB",
    "Isolation Forest": "IF", "One-Class SVM": "OCSVM",
    "Local Outlier Factor": "LOF", "Elliptic Envelope": "EE",
}

# ---- which charts to produce ----
PLOT_RAW            = True
PLOT_IMPROVEMENT    = True
PLOT_TIME           = True
PLOT_LEARNING_CURVE = True
PLOT_TIME_FIGS      = True   # absolute average train/predict-time bar charts (log scale)

RAW_METRICS       = {"MCC": "MCC", "f1_score": "F1-Score", "auc": "AUC-ROC"}
IMPROVEMENT_METRIC = ("f1_score", "F1-Score")   # (key, label) — F1 is bounded, so % is clean
TIME_METRIC        = ("train_time", "training time")  # or ("predict_time", "prediction time")
# absolute-time figures: metric key -> y-axis label
TIME_FIG_METRICS   = {"train_time": "Average training time (s)",
                      "predict_time": "Average prediction time (s)"}
TIME_FIG_LOG       = True     # log y-axis (times span orders of magnitude)
TIME_FIG_MODELS    = ["Random Forest", "Decision Tree", "Naive Bayes",
                      "Isolation Forest", "One-Class SVM", "Local Outlier Factor",
                      "Elliptic Envelope"]

# ---- bars / error bars ----
ERRORBAR    = None             # None = mean only (no error bars)
ERR_CAPSIZE = 0.12
FIGSIZE     = (8.5, 5.0)
ANNOTATE_PCT = True            # value labels on the % charts
LEGEND_TITLE = "Dataset"
# Legend placed BELOW the axes (horizontal) so it never overlaps the bars/data.
LEGEND_ANCHOR = (0.5, -0.16)   # (x, y) in axes coords; y < 0 = below the x-axis
LEGEND_NCOL   = 3              # lay the datasets out in a single row
# ==========================================================================


def setup():
    sns.set_theme(style=SNS_STYLE, context=SNS_CONTEXT, font_scale=FONT_SCALE,
                  rc={"font.family": FONT_FAMILY})
    Path(OUTDIR).mkdir(parents=True, exist_ok=True)


def _save(fig, name):
    base = Path(OUTDIR) / name
    for ext in FORMATS:
        fig.savefig(f"{base}.{ext}", dpi=DPI, bbox_inches="tight")
    plt.close(fig)
    print(f"  {base}.{{{','.join(FORMATS)}}}")


def _err_label():
    if ERRORBAR == "sd": return "std"
    if isinstance(ERRORBAR, (list, tuple)): return f"{ERRORBAR[1]}% CI"
    return ""


def _load_summary_means():
    """Return dict[(dataset, model, metric)] -> mean, from the per-dataset summaries."""
    means = {}
    for ds in DATASET_ORDER:
        df = pd.read_csv(Path(SUMMARY_DIR) / ds / f"{ds}_summary.csv")
        for _, r in df.iterrows():
            means[(ds, r["model"], r["metric"])] = float(r["mean"])
    return means


# --------------------------- raw metric bars ---------------------------
def raw_metric(long_df, metric, label, group_name, models):
    sub = long_df[(long_df.metric == metric) & long_df.model.isin(models)].copy()
    if sub.empty:
        return
    fig, ax = plt.subplots(figsize=FIGSIZE)
    sns.barplot(data=sub, x="model", y="value", hue="dataset",
                order=models, hue_order=DATASET_ORDER, palette=PALETTE,
                errorbar=(None if ERRORBAR is None else ERRORBAR),
                capsize=ERR_CAPSIZE, err_kws={"linewidth": 1.0},
                edgecolor=BAR_EDGECOLOR, linewidth=BAR_EDGEWIDTH, ax=ax)
    ax.set_xticks(range(len(models)))
    ax.set_xticklabels([MODEL_LABELS.get(m, m) for m in models])
    ax.set_xlabel(""); ax.set_ylabel(label)
    ax.set_title(f"{label} — {group_name} models")
    ax.axhline(0, color="black", linewidth=0.6)
    h, l = ax.get_legend_handles_labels()
    ax.legend(h, [DATASET_LABELS.get(x, x) for x in l], title=LEGEND_TITLE,
              loc="upper center", bbox_to_anchor=LEGEND_ANCHOR, ncol=LEGEND_NCOL, framealpha=0.95)
    if DESPINE: sns.despine(ax=ax)
    fig.tight_layout()
    _save(fig, f"fig_raw_{metric}_{group_name.lower()}")


# --------------------------- absolute time bars (log scale) ---------------------------
def time_chart(long_df, time_metric, label):
    sub = long_df[(long_df.metric == time_metric) & long_df.model.isin(TIME_FIG_MODELS)].copy()
    if sub.empty:
        return
    fig, ax = plt.subplots(figsize=(11, 5))
    sns.barplot(data=sub, x="model", y="value", hue="dataset",
                order=TIME_FIG_MODELS, hue_order=DATASET_ORDER, palette=PALETTE,
                errorbar=None, edgecolor=BAR_EDGECOLOR, linewidth=BAR_EDGEWIDTH, ax=ax)
    if TIME_FIG_LOG:
        ax.set_yscale("log")
    ax.set_xticks(range(len(TIME_FIG_MODELS)))
    ax.set_xticklabels([MODEL_LABELS.get(m, m) for m in TIME_FIG_MODELS])
    ax.set_xlabel(""); ax.set_ylabel(label)
    ax.set_title(f"{label} by model (log scale)")
    h, l = ax.get_legend_handles_labels()
    ax.legend(h, [DATASET_LABELS.get(x, x) for x in l], title=LEGEND_TITLE,
              loc="upper center", bbox_to_anchor=LEGEND_ANCHOR, ncol=LEGEND_NCOL, framealpha=0.95)
    if DESPINE: sns.despine(ax=ax)
    fig.tight_layout()
    _save(fig, f"fig_time_{time_metric}")


# --------------------- generic computed % grouped bar ---------------------
def _pct_grouped_bar(pct_by_ds, models, group_name, ylabel, title, fname):
    """pct_by_ds: {dataset: [pct per model]}. OG10 is the baseline (0)."""
    x = np.arange(len(models))
    w = 0.8 / len(DATASET_ORDER)
    fig, ax = plt.subplots(figsize=FIGSIZE)
    for i, ds in enumerate(DATASET_ORDER):
        offset = (i - (len(DATASET_ORDER) - 1) / 2) * w
        bars = ax.bar(x + offset, pct_by_ds[ds], w, color=PALETTE[ds],
                      label=DATASET_LABELS[ds], edgecolor=BAR_EDGECOLOR, linewidth=BAR_EDGEWIDTH)
        if ANNOTATE_PCT:
            ax.bar_label(bars, fmt="%+.0f%%", padding=2, fontsize=7)
    ax.set_xticks(x)
    ax.set_xticklabels([MODEL_LABELS.get(m, m) for m in models])
    ax.set_ylabel(ylabel)
    ax.set_title(title)
    ax.axhline(0, color="black", linewidth=0.8)   # = OG10 baseline
    ax.legend(title=LEGEND_TITLE, loc="upper center", bbox_to_anchor=LEGEND_ANCHOR,
              ncol=LEGEND_NCOL, framealpha=0.95)
    if DESPINE: sns.despine(ax=ax)
    fig.tight_layout()
    _save(fig, fname)


def improvement(means, group_name, models):
    metric, label = IMPROVEMENT_METRIC
    pct = {ds: [] for ds in DATASET_ORDER}
    for m in models:
        base = means.get((BASELINE, m, metric), float("nan"))
        for ds in DATASET_ORDER:
            v = means.get((ds, m, metric), float("nan"))
            pct[ds].append(0.0 if ds == BASELINE else (v - base) / base * 100.0)
    _pct_grouped_bar(pct, models, group_name,
                     ylabel=f"{label} improvement vs {BASELINE} (%)",
                     title=f"{label} improvement over {BASELINE} — {group_name} models",
                     fname=f"fig_improvement_{metric}_{group_name.lower()}")


def time_change(means, group_name, models):
    metric, label = TIME_METRIC
    pct = {ds: [] for ds in DATASET_ORDER}
    for m in models:
        base = means.get((BASELINE, m, metric), float("nan"))
        for ds in DATASET_ORDER:
            v = means.get((ds, m, metric), float("nan"))
            # positive = faster (time reduced) relative to OG10
            pct[ds].append(0.0 if ds == BASELINE else (base - v) / base * 100.0)
    _pct_grouped_bar(pct, models, group_name,
                     ylabel=f"{label} change vs {BASELINE} (%, + = faster)",
                     title=f"{label} change vs {BASELINE} — {group_name} models",
                     fname=f"fig_timechange_{metric}_{group_name.lower()}")


def learning_curve():
    fig, ax = plt.subplots(figsize=(7.5, 5))
    for ds in ["OG10", "GenS10"]:
        p = Path(SUMMARY_DIR) / ds / f"{ds}_learning_curve.csv"
        if not p.exists():
            continue
        d = pd.read_csv(p)
        ax.plot(d["n"], d["f1_score"], marker="o", linewidth=2,
                color=PALETTE.get(ds), label=DATASET_LABELS.get(ds, ds))
    ax.axvline(10000, color="black", linestyle="--", linewidth=1, label="chosen N = 10,000")
    ax.set_xlabel("benign training subsample size (N)")
    ax.set_ylabel("Isolation Forest F1 (proxy)")
    ax.set_title("Learning curve: F1 saturates by the chosen N")
    ax.legend(loc="upper center", bbox_to_anchor=(0.5, -0.16), ncol=3, framealpha=0.95)
    if DESPINE: sns.despine(ax=ax)
    fig.tight_layout()
    _save(fig, "fig_learning_curve")


def main():
    setup()
    long_df = pd.read_csv(INPUT_CSV)
    means = _load_summary_means()
    print(f"Figures -> {OUTDIR}")
    for group_name, models in MODEL_GROUPS.items():
        if PLOT_RAW:
            for metric, label in RAW_METRICS.items():
                raw_metric(long_df, metric, label, group_name, models)
        if PLOT_IMPROVEMENT:
            improvement(means, group_name, models)
        if PLOT_TIME:
            time_change(means, group_name, models)
    if PLOT_TIME_FIGS:
        for tm, label in TIME_FIG_METRICS.items():
            time_chart(long_df, tm, label)
    if PLOT_LEARNING_CURVE:
        learning_curve()
    print("done.")


if __name__ == "__main__":
    main()
