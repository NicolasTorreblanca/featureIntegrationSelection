"""Thesis trainer — orchestrates the full pipeline for each dataset.

Example:
    python train.py --dataset GenS10

Outputs land in results/{dataset}/:
    selected_features.json        MI top-K features + scores (leakage-free)
    {tag}_supervised_mccv.csv     K-iteration supervised MCCV rows
    {tag}_unsupervised_mccv.csv   K-iteration unsupervised MCCV rows
    {tag}_summary.csv             per-dataset aggregated table
    run_metadata.json             seed, flags, git sha, runtimes, dataset hash
    studies/                      per-model Optuna trials CSVs + best.json

Learning-curve mode:
    python train.py --dataset GenS10 --learning-curve
"""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd

# Make `pipeline` importable when this file is run directly
sys.path.insert(0, str(Path(__file__).resolve().parent))

from pipeline import data as data_module          # noqa: E402
from pipeline import evaluate as eval_module      # noqa: E402
from pipeline import learning_curve as lc_module  # noqa: E402
from pipeline import mccv as mccv_module          # noqa: E402
from pipeline import report as report_module      # noqa: E402
from pipeline import splits as splits_module      # noqa: E402
from pipeline import tune as tune_module          # noqa: E402


def _sha256_of_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _git_sha(start_dir: Path) -> str:
    try:
        out = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=start_dir,
            capture_output=True,
            text=True,
            check=False,
            timeout=5,
        )
        if out.returncode == 0:
            return out.stdout.strip()
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return "unknown"


def run_experiment(cfg, out_dir, k, seed, n_trials, n_subsample, K):
    """One dataset end-to-end: normalize -> split -> MI(train) -> tune -> MCCV -> report."""
    out_dir = Path(out_dir)
    studies_dir = out_dir / "studies"
    out_dir.mkdir(parents=True, exist_ok=True)
    studies_dir.mkdir(parents=True, exist_ok=True)

    t_start = time.time()
    phase = {}

    # 1. Load + normalize schema
    print(f"[{cfg.tag}] loading {cfg.path} ...", flush=True)
    _t = time.time()
    df = data_module.load_normalized(cfg)
    phase["load"] = time.time() - _t

    # 2. Supervised split first (so MI is fit on train rows only)
    # 3. Leakage-free MI top-k on the supervised training rows
    print(f"[{cfg.tag}] MI top-{k} selection (leakage-free) ...", flush=True)
    _t = time.time()
    sup = splits_module.supervised_split(df, seed=seed)
    train_idx = sup.X_train.index.to_numpy()
    feats, scores = data_module.select_mi_top_k_on(df, train_idx=train_idx, k=k, seed=seed)
    with (out_dir / "selected_features.json").open("w", encoding="utf-8") as f:
        json.dump({"dataset": cfg.tag, "selected_features": feats,
                   "mi_scores": dict(zip(feats, scores)), "seed": seed}, f, indent=2)

    # 4. Reduce to selected features, rebuild splits on reduced frame
    df_red = df[feats + [data_module.TARGET_COLUMN]].copy()
    sup = splits_module.supervised_split(df_red, seed=seed)
    unsup = splits_module.unsupervised_split(df_red, seed=seed)
    phase["split_mi"] = time.time() - _t

    # 5. Tune (sequential, seeded). n_subsample caps unsupervised tuning data.
    print(f"[{cfg.tag}] tuning supervised ({n_trials} trials/model) ...", flush=True)
    _t = time.time()
    sup_tune = tune_module.tune_supervised(sup.X_train, sup.y_train, n_trials=n_trials,
                                           seed=seed, studies_dir=studies_dir)
    phase["tune_supervised"] = time.time() - _t

    print(f"[{cfg.tag}] tuning unsupervised ({n_trials} trials/model, sub={n_subsample}) ...", flush=True)
    _t = time.time()
    unsup_tune = tune_module.tune_unsupervised(unsup.benign_train, unsup.X_valid, unsup.y_valid,
                                               n_trials=n_trials, seed=seed,
                                               studies_dir=studies_dir, tune_subsample=n_subsample)
    phase["tune_unsupervised"] = time.time() - _t

    sup_ctors = eval_module.supervised_constructors(sup_tune, seed=seed)
    unsup_ctors = eval_module.unsupervised_constructors(unsup_tune, seed=seed)

    # 6. MCCV evaluation. Pass the zero-arg constructors DIRECTLY (no wrapping!).
    print(f"[{cfg.tag}] MCCV supervised (K={K}) ...", flush=True)
    _t = time.time()
    sup_rows = mccv_module.run_mccv(sup.X_full, sup.y_full, models=list(sup_ctors),
                                    K=K, seed=seed, constructors=sup_ctors)
    phase["mccv_supervised"] = time.time() - _t

    print(f"[{cfg.tag}] MCCV unsupervised (K={K}) ...", flush=True)
    _t = time.time()
    unsup_rows = mccv_module.run_mccv_unsupervised(unsup.benign_train, unsup.X_test, unsup.y_test,
                                                   constructors=unsup_ctors, K=K, seed=seed,
                                                   n_subsample=n_subsample)
    phase["mccv_unsupervised"] = time.time() - _t

    print(f"[{cfg.tag}] writing results ...", flush=True)
    _t = time.time()
    pd.DataFrame(sup_rows).to_csv(out_dir / f"{cfg.tag}_supervised_mccv.csv", index=False)
    pd.DataFrame(unsup_rows).to_csv(out_dir / f"{cfg.tag}_unsupervised_mccv.csv", index=False)

    sup_agg = mccv_module.aggregate(sup_rows)
    unsup_agg = mccv_module.aggregate(unsup_rows)
    report_module.per_dataset_table({**sup_agg, **unsup_agg}).to_csv(
        out_dir / f"{cfg.tag}_summary.csv", index=False)
    phase["write"] = time.time() - _t

    meta = {"dataset": cfg.tag, "seed": seed, "k": k, "n_trials": n_trials,
            "n_subsample": n_subsample, "K": K, "features_used": len(feats),
            "selected_features": feats,
            "phase_seconds": phase,
            "total_seconds": time.time() - t_start}
    with (out_dir / "run_metadata.json").open("w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)

    print(f"[{cfg.tag}] done in {time.time() - t_start:.1f}s  ->  {out_dir}", flush=True)
    return meta


def _run_learning_curve(cfg, out_dir, args):
    """Learning-curve mode: metric vs benign train size, to choose/justify n."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    df = data_module.load_normalized(cfg)
    sup = splits_module.supervised_split(df, seed=args.seed)
    feats, _ = data_module.select_mi_top_k_on(df, train_idx=sup.X_train.index.to_numpy(),
                                               k=args.k, seed=args.seed)
    df_red = df[feats + [data_module.TARGET_COLUMN]].copy()
    unsup = splits_module.unsupervised_split(df_red, seed=args.seed)
    sizes = [5000, 10000, 20000, 50000]
    pts = lc_module.learning_curve_points(unsup.benign_train, unsup.X_test, unsup.y_test,
                                          sizes=sizes, seed=args.seed)
    pd.DataFrame(pts).to_csv(out_dir / f"{cfg.tag}_learning_curve.csv", index=False)
    print(f"[learning-curve] {cfg.tag} -> {out_dir / (cfg.tag + '_learning_curve.csv')}")
    for p in pts:
        print(f"  n={p['n']:>6}  f1={p['f1_score']:.4f}")
    return 0


def parse_args(argv=None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Train + evaluate thesis ML models on a network-traffic dataset."
    )
    from pipeline.datasets import DATASETS
    p.add_argument("--dataset", required=True, choices=list(DATASETS), help="OG10 | Gen10 | GenS10")
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--k", type=int, default=10)
    p.add_argument("--n-trials", type=int, default=50)
    p.add_argument("--n-subsample", type=int, default=20000, help="Unsupervised benign-train subsample size")
    p.add_argument("--K", type=int, default=20, help="MCCV iterations")
    p.add_argument("--learning-curve", action="store_true", help="Run learning-curve mode instead of full experiment")
    p.add_argument(
        "--results-root",
        default=str(Path(__file__).resolve().parent / "results"),
    )
    return p.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    from pipeline.datasets import DATASETS
    cfg = DATASETS[args.dataset]
    out_dir = Path(args.results_root) / args.dataset
    if args.learning_curve:
        return _run_learning_curve(cfg, out_dir, args)
    meta = run_experiment(cfg, out_dir, k=args.k, seed=args.seed,
                          n_trials=args.n_trials, n_subsample=args.n_subsample, K=args.K)
    print(f"[done] {args.dataset}: {meta['features_used']} features -> {out_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
