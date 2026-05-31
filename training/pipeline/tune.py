"""Optuna hyperparameter tuning.

Six tuned models (literature ranges from notebook cells 20 + 29):
  Supervised: RandomForest, DecisionTree (NaiveBayes has no hyperparameters)
  Unsupervised: IsolationForest, OneClassSVM, LocalOutlierFactor, EllipticEnvelope

Tuning contract:
  - One TPESampler per study, seeded from --seed (deterministic search)
  - All sklearn estimators get random_state=seed
  - Supervised objectives use 10-fold StratifiedKFold inside (notebook cell 20)
  - Unsupervised objectives use a single pass over (benign_train, X_valid)
    and optimize the composite score (precision + recall + f1, equal weights)
  - Unsupervised tuning may sub-sample benign_train (`tune_subsample` rows)
    to keep OCSVM/LOF/EE wall-clock manageable on large datasets;
    final evaluation in evaluate.py uses the full benign_train.

Persistence:
  - For each model: studies/{model_key}_trials.csv (one row per trial,
    including auxiliary metrics) and studies/{model_key}_best.json
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, Optional

import numpy as np
import optuna
import pandas as pd
from sklearn.covariance import EllipticEnvelope
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    f1_score,
    matthews_corrcoef,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import StratifiedKFold
from sklearn.neighbors import LocalOutlierFactor
from sklearn.svm import OneClassSVM
from sklearn.tree import DecisionTreeClassifier

# Suppress Optuna's noisy per-trial logging; we capture trial details ourselves
optuna.logging.set_verbosity(optuna.logging.WARNING)


@dataclass
class TuneResult:
    best_params: dict
    best_value: float
    n_trials: int
    elapsed_seconds: float
    trials_path: Optional[Path] = None
    best_path: Optional[Path] = None


@dataclass
class SupervisedTuning:
    random_forest: TuneResult
    decision_tree: TuneResult
    elapsed_seconds: float = 0.0


@dataclass
class UnsupervisedTuning:
    isolation_forest: TuneResult
    one_class_svm: TuneResult
    local_outlier_factor: TuneResult
    elliptic_envelope: TuneResult
    elapsed_seconds: float = 0.0


# ---------------------------------------------------------------------------
# Supervised objectives
# ---------------------------------------------------------------------------

def _cv_score(model, X: np.ndarray, y: np.ndarray, seed: int) -> dict:
    """10-fold StratifiedKFold cross-val, returning mean metric values.

    Mirrors notebook cell 20's compute_metrics; auxiliary metrics are
    stashed on the trial via user_attrs by the caller.
    """
    cv = StratifiedKFold(n_splits=10, shuffle=True, random_state=seed)
    accs, precs, recalls, f1s, aucs, mccs = [], [], [], [], [], []

    for train_idx, val_idx in cv.split(X, y):
        X_tr, X_vl = X[train_idx], X[val_idx]
        y_tr, y_vl = y[train_idx], y[val_idx]
        model.fit(X_tr, y_tr)
        y_pred = model.predict(X_vl)

        accs.append(accuracy_score(y_vl, y_pred))
        precs.append(precision_score(y_vl, y_pred, average="macro", zero_division=0))
        recalls.append(recall_score(y_vl, y_pred, average="macro", zero_division=0))
        f1s.append(f1_score(y_vl, y_pred, average="macro"))
        mccs.append(matthews_corrcoef(y_vl, y_pred))

        if hasattr(model, "predict_proba"):
            try:
                y_proba = model.predict_proba(X_vl)
                if y_proba.shape[1] == 2:
                    aucs.append(roc_auc_score(y_vl, y_proba[:, 1]))
                else:
                    aucs.append(roc_auc_score(y_vl, y_proba, average="macro", multi_class="ovr"))
            except Exception:
                aucs.append(0.0)
        else:
            aucs.append(0.0)

    return {
        "accuracy": float(np.mean(accs)),
        "precision": float(np.mean(precs)),
        "recall": float(np.mean(recalls)),
        "f1": float(np.mean(f1s)),
        "auc": float(np.mean(aucs)),
        "MCC": float(np.mean(mccs)),
    }


def _objective_rf(X: np.ndarray, y: np.ndarray, seed: int) -> Callable[[optuna.Trial], float]:
    def obj(trial: optuna.Trial) -> float:
        params = {
            "n_estimators": trial.suggest_int("n_estimators", 100, 300),
            "max_depth": trial.suggest_int("max_depth", 5, 30),
            "max_features": trial.suggest_categorical("max_features", ["sqrt", "log2"]),
        }
        model = RandomForestClassifier(
            **params,
            class_weight="balanced",
            random_state=seed,
            n_jobs=-1,
        )
        scores = _cv_score(model, X, y, seed=seed)
        for k, v in scores.items():
            trial.set_user_attr(k, v)
        return scores["f1"]
    return obj


def _objective_dt(X: np.ndarray, y: np.ndarray, seed: int) -> Callable[[optuna.Trial], float]:
    def obj(trial: optuna.Trial) -> float:
        params = {
            "max_depth": trial.suggest_int("max_depth", 5, 30),
            "min_samples_split": trial.suggest_int("min_samples_split", 2, 10),
            "criterion": trial.suggest_categorical("criterion", ["gini", "entropy", "log_loss"]),
        }
        model = DecisionTreeClassifier(
            **params,
            class_weight="balanced",
            random_state=seed,
        )
        scores = _cv_score(model, X, y, seed=seed)
        for k, v in scores.items():
            trial.set_user_attr(k, v)
        return scores["f1"]
    return obj


# ---------------------------------------------------------------------------
# Unsupervised objectives
# ---------------------------------------------------------------------------

def _composite_score(precision: float, recall: float, f1: float) -> float:
    # Equal-weight (1/3 each), matching notebook cell 29
    return (precision + recall + f1) / 3.0


def _score_unsup_predictions(y_true: np.ndarray, preds_anomaly_flag: np.ndarray) -> dict:
    """Score unsupervised predictions where preds_anomaly_flag has 1=anomaly, 0=normal."""
    if len(np.unique(preds_anomaly_flag)) < 2:
        return {
            "accuracy": 0.0, "precision": 0.0, "recall": 0.0,
            "f1": 0.0, "auc": 0.0, "MCC": 0.0, "score": 0.0,
        }
    acc = accuracy_score(y_true, preds_anomaly_flag)
    prec = precision_score(y_true, preds_anomaly_flag, zero_division=0)
    rec = recall_score(y_true, preds_anomaly_flag, zero_division=0)
    f1 = f1_score(y_true, preds_anomaly_flag, zero_division=0)
    mcc = matthews_corrcoef(y_true, preds_anomaly_flag)
    try:
        auc = roc_auc_score(y_true, preds_anomaly_flag)
    except Exception:
        auc = 0.0
    return {
        "accuracy": float(acc),
        "precision": float(prec),
        "recall": float(rec),
        "f1": float(f1),
        "auc": float(auc),
        "MCC": float(mcc),
        "score": float(_composite_score(prec, rec, f1)),
    }


def _unsup_predict_to_anomaly_flag(raw_preds) -> np.ndarray:
    # sklearn anomaly detectors return +1 = normal, -1 = anomaly.
    # Convert to 1=anomaly, 0=normal to match y_valid/y_test conventions.
    return np.array([0 if p == 1 else 1 for p in raw_preds])


def _objective_iso(
    benign_train: pd.DataFrame, X_valid: pd.DataFrame, y_valid: pd.Series, seed: int
) -> Callable[[optuna.Trial], float]:
    def obj(trial: optuna.Trial) -> float:
        params = {
            "n_estimators": trial.suggest_int("n_estimators", 150, 500),
            "max_samples": trial.suggest_float("max_samples", 0.1, 1.0),
            "contamination": trial.suggest_float("contamination", 0.01, 0.5),
            "max_features": trial.suggest_float("max_features", 0.1, 1.0),
        }
        model = IsolationForest(**params, random_state=seed, n_jobs=-1)
        model.fit(benign_train)
        preds = _unsup_predict_to_anomaly_flag(model.predict(X_valid))
        scores = _score_unsup_predictions(y_valid.values, preds)
        for k, v in scores.items():
            trial.set_user_attr(k, v)
        return scores["score"]
    return obj


def _objective_ocsvm(
    benign_train: pd.DataFrame, X_valid: pd.DataFrame, y_valid: pd.Series, seed: int
) -> Callable[[optuna.Trial], float]:
    def obj(trial: optuna.Trial) -> float:
        params = {
            "nu": trial.suggest_float("nu", 0.01, 0.5),
            "gamma": trial.suggest_categorical("gamma", ["auto", "scale"]),
            "kernel": trial.suggest_categorical("kernel", ["linear", "poly", "rbf"]),
        }
        model = OneClassSVM(**params)
        model.fit(benign_train)
        preds = _unsup_predict_to_anomaly_flag(model.predict(X_valid))
        scores = _score_unsup_predictions(y_valid.values, preds)
        for k, v in scores.items():
            trial.set_user_attr(k, v)
        return scores["score"]
    return obj


def _objective_lof(
    benign_train: pd.DataFrame, X_valid: pd.DataFrame, y_valid: pd.Series, seed: int
) -> Callable[[optuna.Trial], float]:
    def obj(trial: optuna.Trial) -> float:
        params = {
            "n_neighbors": trial.suggest_int("n_neighbors", 5, 50),
            "leaf_size": trial.suggest_int("leaf_size", 30, 120),
            "contamination": trial.suggest_float("contamination", 0.01, 0.2),
            "algorithm": trial.suggest_categorical(
                "algorithm", ["auto", "ball_tree", "kd_tree", "brute"]
            ),
        }
        model = LocalOutlierFactor(**params, novelty=True, n_jobs=-1)
        model.fit(benign_train)
        preds = _unsup_predict_to_anomaly_flag(model.predict(X_valid))
        scores = _score_unsup_predictions(y_valid.values, preds)
        for k, v in scores.items():
            trial.set_user_attr(k, v)
        return scores["score"]
    return obj


def _objective_ee(
    benign_train: pd.DataFrame, X_valid: pd.DataFrame, y_valid: pd.Series, seed: int
) -> Callable[[optuna.Trial], float]:
    def obj(trial: optuna.Trial) -> float:
        params = {
            "contamination": trial.suggest_float("contamination", 0.01, 0.1),
            "support_fraction": trial.suggest_float("support_fraction", 0.1, 1.0),
        }
        try:
            model = EllipticEnvelope(**params, random_state=seed)
            model.fit(benign_train)
            preds = _unsup_predict_to_anomaly_flag(model.predict(X_valid))
            scores = _score_unsup_predictions(y_valid.values, preds)
        except (ValueError, np.linalg.LinAlgError):
            # EE fails on singular covariance; penalize the trial
            scores = {k: 0.0 for k in ("accuracy", "precision", "recall", "f1", "auc", "MCC", "score")}
        for k, v in scores.items():
            trial.set_user_attr(k, v)
        return scores["score"]
    return obj


# ---------------------------------------------------------------------------
# Study runner + persistence
# ---------------------------------------------------------------------------

def _run_study(
    objective: Callable[[optuna.Trial], float],
    n_trials: int,
    seed: int,
    study_name: str,
    studies_dir: Path,
) -> TuneResult:
    sampler = optuna.samplers.TPESampler(seed=seed)
    study = optuna.create_study(
        direction="maximize",
        sampler=sampler,
        study_name=study_name,
    )

    t0 = time.time()
    study.optimize(objective, n_trials=n_trials, show_progress_bar=False)
    elapsed = time.time() - t0

    # Persist all trials with their user_attrs as flat columns
    studies_dir.mkdir(parents=True, exist_ok=True)
    trials_df = study.trials_dataframe(
        attrs=("number", "value", "params", "user_attrs", "state", "duration")
    )
    trials_path = studies_dir / f"{study_name}_trials.csv"
    trials_df.to_csv(trials_path, index=False)

    best_path = studies_dir / f"{study_name}_best.json"
    with best_path.open("w", encoding="utf-8") as f:
        json.dump(
            {
                "best_params": study.best_params,
                "best_value": study.best_value,
                "best_trial_number": study.best_trial.number,
                "n_trials": len(study.trials),
                "elapsed_seconds": elapsed,
                "seed": seed,
            },
            f,
            indent=2,
        )

    return TuneResult(
        best_params=study.best_params,
        best_value=study.best_value,
        n_trials=len(study.trials),
        elapsed_seconds=elapsed,
        trials_path=trials_path,
        best_path=best_path,
    )


def tune_supervised(
    X_train: pd.DataFrame,
    y_train: pd.Series,
    n_trials: int,
    seed: int,
    studies_dir: Path,
) -> SupervisedTuning:
    X = X_train.values
    y = y_train.values

    t0 = time.time()
    rf = _run_study(
        _objective_rf(X, y, seed=seed),
        n_trials=n_trials,
        seed=seed,
        study_name="sup_random_forest",
        studies_dir=studies_dir,
    )
    dt = _run_study(
        _objective_dt(X, y, seed=seed),
        n_trials=n_trials,
        seed=seed,
        study_name="sup_decision_tree",
        studies_dir=studies_dir,
    )
    elapsed = time.time() - t0
    return SupervisedTuning(random_forest=rf, decision_tree=dt, elapsed_seconds=elapsed)


def tune_unsupervised(
    benign_train: pd.DataFrame,
    X_valid: pd.DataFrame,
    y_valid: pd.Series,
    n_trials: int,
    seed: int,
    studies_dir: Path,
    tune_subsample: Optional[int] = 50_000,
) -> UnsupervisedTuning:
    """Tune all four unsupervised models.

    If `tune_subsample` is set and benign_train is larger, draw a random
    sub-sample (without replacement) of that size, used uniformly across
    all four studies. The final model fit in evaluate.py uses the full
    benign_train regardless.
    """
    if tune_subsample is not None and len(benign_train) > tune_subsample:
        benign_for_tuning = benign_train.sample(
            n=tune_subsample, random_state=seed, replace=False
        )
    else:
        benign_for_tuning = benign_train

    t0 = time.time()
    iso = _run_study(
        _objective_iso(benign_for_tuning, X_valid, y_valid, seed=seed),
        n_trials=n_trials,
        seed=seed,
        study_name="unsup_isolation_forest",
        studies_dir=studies_dir,
    )
    ocsvm = _run_study(
        _objective_ocsvm(benign_for_tuning, X_valid, y_valid, seed=seed),
        n_trials=n_trials,
        seed=seed,
        study_name="unsup_one_class_svm",
        studies_dir=studies_dir,
    )
    lof = _run_study(
        _objective_lof(benign_for_tuning, X_valid, y_valid, seed=seed),
        n_trials=n_trials,
        seed=seed,
        study_name="unsup_local_outlier_factor",
        studies_dir=studies_dir,
    )
    ee = _run_study(
        _objective_ee(benign_for_tuning, X_valid, y_valid, seed=seed),
        n_trials=n_trials,
        seed=seed,
        study_name="unsup_elliptic_envelope",
        studies_dir=studies_dir,
    )
    elapsed = time.time() - t0
    return UnsupervisedTuning(
        isolation_forest=iso,
        one_class_svm=ocsvm,
        local_outlier_factor=lof,
        elliptic_envelope=ee,
        elapsed_seconds=elapsed,
    )
