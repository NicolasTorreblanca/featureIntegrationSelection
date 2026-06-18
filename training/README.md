# Thesis trainer

Reproducible CLI script that replaces the two `Entrenamiento_*.ipynb` notebooks
with a single tunable command. Trains the seven thesis models on any
input CSV that has a `category` column and writes the result tables that
`Pruebas_Estadisticas_y_Graficos.ipynb` consumes.

## Quick start

```bash
# install
pip install -r requirements.txt

# smoke test (fast: 3 Optuna trials per model)
python train.py \
  --input-csv "../NFStream-SHAP/TonIoT-formodels-allfets-multiclass.csv" \
  --run-tag GEN10 \
  --n-trials 3

# full run for thesis (50 trials per model)
python train.py \
  --input-csv "../NFStream-SHAP/TonIoT-formodels-allfets-multiclass.csv" \
  --run-tag GEN10 \
  --n-trials 50

# ablation: all features (no MI selection)
python train.py \
  --input-csv "../NFStream-SHAP/TonIoT-formodels-allfets-multiclass.csv" \
  --run-tag GEN30_no_mi \
  --no-mi
```

After a smoke-test run, open `results/{run-tag}/run_metadata.json` and look at
`tuning.{supervised,unsupervised}.{model}.seconds_per_trial`. Multiply by 50 to
estimate full-run cost per model before committing.

## CLI

| Flag | Default | Purpose |
|------|---------|---------|
| `--input-csv` | (required) | Path to the dataset CSV. Must contain a `category` column (0=benign, 1=malign). |
| `--run-tag` | (required) | Folder name under `results/`. Use short tags like `OG10`, `GEN10`, `GEN30_no_mi`. |
| `--seed` | `42` | Master seed for all random_state values, the Optuna TPE sampler, and train/test splits. |
| `--no-mi` | off | Skip MI top-K selection; train on all numeric features. |
| `--k` | `10` | K for mutual-information feature selection. Ignored when `--no-mi`. |
| `--n-trials` | `50` | Optuna trials per tuned model. Use `--n-trials 3` for smoke tests. |
| `--tune-subsample` | `50000` | Rows of benign training data sampled for unsupervised tuning. Final model fit always uses the full benign train. Set to `0` to disable. |
| `--results-root` | `./results` | Where per-run output folders are written. |

## What the script does

1. **Load + clean.** Reads the CSV, drops `label` or `proto-number` if present (label-leak), keeps only `int64`/`float64` columns plus the target.
2. **Feature selection (optional).** Mutual-information top-K via `SelectKBest(mutual_info_classif)`. Scaling is applied only for the MI computation; downstream models receive un-scaled features. Pass `--no-mi` to skip.
3. **Splits.**
   - Supervised: 80/20 stratified.
   - Unsupervised: 60/20/20 on benign rows + 20/20 disjoint pools on malign rows. (The notebook drew val/test malign sets with overlapping random samples; this script makes them disjoint so the val score Optuna sees is honest.)
4. **Tune** six models with Optuna over literature-defined ranges (notebook cells 20 + 29). One `TPESampler` per study, seeded from `--seed` so the entire search trajectory is deterministic. Supervised tuning uses 10-fold StratifiedKFold inside each objective. Unsupervised tuning fits on a `--tune-subsample`-row sub-sample of benign train and scores on the full val partition.
5. **Evaluate** in five generations (all five Optuna-winning models, three supervised + four unsupervised; Naive Bayes has no hyperparameters and is included only in the evaluation step).
6. **Persist** all five eval CSVs, the per-model Optuna trial logs, the selected feature list, and a `run_metadata.json` capturing every input that defines the run.

## Output layout

```
results/{run-tag}/
    {tag}_quick_sup.csv         (cell 22 — single 80/20 sup eval)
    {tag}_Evaluaciones_sup.csv  (cell 24 — 10-iter 80/20 sup eval)
    {tag}_SUP_CV10.csv          (cell 25 — nested CV sup eval)  ← analyzer reads
    {tag}_quick_no_sup.csv      (cell 39 — single unsup eval)
    {tag}_unsup_times.csv       (cell 41 — 10-iter sampled unsup eval) ← analyzer reads
    selected_features.json
    run_metadata.json
    studies/
        sup_random_forest_trials.csv
        sup_random_forest_best.json
        sup_decision_tree_*
        unsup_isolation_forest_*
        unsup_one_class_svm_*
        unsup_local_outlier_factor_*
        unsup_elliptic_envelope_*
```

### CSV column schema

Every eval CSV uses the same `{metric}_{model}` schema, one row per iteration:

| Metrics | Models (sup) | Models (unsup) |
|---|---|---|
| `accuracy`, `precision`, `recall`, `f1_score`, `auc`, `MCC`, `TP`, `TN`, `FP`, `FN`, `train_time`, `predict_time` | Random Forest, Decision Tree, Naive Bayes | Isolation Forest, One-Class SVM, Local Outlier Factor, Elliptic Envelope |

`MCC` is present in all five eval files. The notebook only had MCC inside cell 25 (with an `eval_` prefix the analyzer wasn't actually reading) — adding it to every file fixes that silent gap.

## Methodology notes (for the thesis)

- **Determinism.** A single `--seed` controls (a) all `train_test_split` calls, (b) every `random_state` on supervised + unsupervised estimators, and (c) the `TPESampler` per Optuna study. With identical code, identical input CSV, and identical seed, results are byte-identical run-to-run.
- **Hyperparameter ranges** are exactly the ones in notebook cells 20 (supervised) and 29 (unsupervised), unchanged.
- **Search depth.** TPE-Sampler is stochastic by design but seeded here. `--n-trials 50` matches literature norms; `--n-trials 3` exists for smoke-testing only.
- **Sub-sampling for unsupervised tuning.** OCSVM and LOF scale ~quadratically in samples, making 50-trial tuning on a 180k-row benign set prohibitive. Optuna instead tunes on a `--tune-subsample`-row stratified sub-sample (default 50k). The winning hyperparameters are then re-evaluated by fitting the model on the full benign train partition in step 5. This is a standard practice in production ML pipelines and is recorded explicitly in `run_metadata.json` (`flags.tune_subsample`).
- **Val/test disjointness in the unsupervised splits** is a deliberate change from the notebook (which used overlapping random samples from the malign pool). Recorded for honesty in the methodology section.

## Repeatability contract

Anyone with this repo, the same input CSV, and the same `--seed N` should produce byte-identical CSVs in `results/{run-tag}/`. The `run_metadata.json` records the input CSV's SHA-256 so divergent results from divergent inputs are detectable.

## Tested with

- Python 3.11
- pandas ≥ 2.0, numpy ≥ 1.24, scikit-learn ≥ 1.3, optuna ≥ 3.0
