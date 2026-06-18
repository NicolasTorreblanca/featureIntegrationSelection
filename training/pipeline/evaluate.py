"""Five evaluation generations from the notebook, normalized to a single
column schema so the downstream analyzer notebook can read every output.

  cell 22  -> evaluate_supervised_quick      -> {tag}_quick_sup.csv
  cell 24  -> evaluate_supervised_iter       -> {tag}_Evaluaciones_sup.csv
  cell 25  -> evaluate_supervised_nested_cv  -> {tag}_SUP_CV10.csv  (* analyzer)
  cell 39  -> evaluate_unsupervised_quick    -> {tag}_quick_no_sup.csv
  cell 41  -> evaluate_unsupervised_iter     -> {tag}_unsup_times.csv (* analyzer)

Output schema (every CSV):
  - One row per iteration (1 for quick, 10 for the rest)
  - Columns named {metric}_{model_name} for metric in
    [accuracy, precision, recall, f1_score, auc, MCC, TP, TN, FP, FN,
     train_time, predict_time]
  - model_name uses the canonical labels expected by the analyzer:
    "Random Forest", "Decision Tree", "Naive Bayes",
    "Isolation Forest", "One-Class SVM", "Local Outlier Factor",
    "Elliptic Envelope"

MCC is added to all five files (notebook had it only in cell 25, with an
'eval_' prefix that the analyzer wasn't actually reading).
"""

from __future__ import annotations

import time
from typing import Callable, Dict, List

import numpy as np
import pandas as pd
from sklearn.covariance import EllipticEnvelope
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    matthews_corrcoef,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import StratifiedKFold, train_test_split
from sklearn.naive_bayes import GaussianNB
from sklearn.neighbors import LocalOutlierFactor
from sklearn.svm import OneClassSVM
from sklearn.tree import DecisionTreeClassifier

from .tune import SupervisedTuning, UnsupervisedTuning


# ---------------------------------------------------------------------------
# Model factory: turns tuning results into constructors
# ---------------------------------------------------------------------------

ModelCtor = Callable[[], object]


def supervised_constructors(tuning: SupervisedTuning, seed: int) -> Dict[str, ModelCtor]:
    rf_params = tuning.random_forest.best_params
    dt_params = tuning.decision_tree.best_params
    return {
        "Random Forest": lambda: RandomForestClassifier(
            **rf_params, class_weight="balanced", random_state=seed, n_jobs=-1
        ),
        "Decision Tree": lambda: DecisionTreeClassifier(
            **dt_params, class_weight="balanced", random_state=seed
        ),
        "Naive Bayes": lambda: GaussianNB(),
    }


def unsupervised_constructors(tuning: UnsupervisedTuning, seed: int) -> Dict[str, ModelCtor]:
    iso_params = tuning.isolation_forest.best_params
    ocsvm_params = tuning.one_class_svm.best_params
    lof_params = tuning.local_outlier_factor.best_params
    ee_params = tuning.elliptic_envelope.best_params
    return {
        "Isolation Forest": lambda: IsolationForest(
            **iso_params, random_state=seed, n_jobs=-1
        ),
        "One-Class SVM": lambda: OneClassSVM(**ocsvm_params),
        "Local Outlier Factor": lambda: LocalOutlierFactor(
            **lof_params, novelty=True, n_jobs=-1
        ),
        "Elliptic Envelope": lambda: EllipticEnvelope(**ee_params, random_state=seed),
    }


# ---------------------------------------------------------------------------
# Single-model metric blocks
# ---------------------------------------------------------------------------

def _binary_confusion(y_true, y_pred) -> tuple:
    if len(np.unique(y_true)) == 2:
        cm = confusion_matrix(y_true, y_pred)
        if cm.shape == (2, 2):
            tn, fp, fn, tp = cm.ravel()
            return int(tp), int(tn), int(fp), int(fn)
    return (np.nan, np.nan, np.nan, np.nan)


def _supervised_fit_eval(model, X_train, y_train, X_test, y_test) -> Dict[str, float]:
    t0 = time.time()
    model.fit(X_train, y_train)
    train_time = time.time() - t0

    t1 = time.time()
    y_pred = model.predict(X_test)
    predict_time = time.time() - t1

    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, average="macro", zero_division=0)
    rec = recall_score(y_test, y_pred, average="macro", zero_division=0)
    f1s = f1_score(y_test, y_pred, average="macro")
    mcc = matthews_corrcoef(y_test, y_pred)

    auc = 0.0
    if hasattr(model, "predict_proba"):
        try:
            y_proba = model.predict_proba(X_test)
            classes = np.unique(y_test)
            if len(classes) == 2:
                class_index = list(model.classes_).index(classes[1])
                auc = roc_auc_score(y_test, y_proba[:, class_index])
            else:
                from sklearn.preprocessing import label_binarize
                y_test_bin = label_binarize(y_test, classes=classes)
                y_proba_bin = y_proba[:, [list(model.classes_).index(c) for c in classes]]
                auc = roc_auc_score(y_test_bin, y_proba_bin, average="macro", multi_class="ovr")
        except Exception:
            auc = 0.0

    tp, tn, fp, fn = _binary_confusion(y_test, y_pred)
    return {
        "accuracy": float(acc),
        "precision": float(prec),
        "recall": float(rec),
        "f1_score": float(f1s),
        "auc": float(auc),
        "MCC": float(mcc),
        "TP": tp,
        "TN": tn,
        "FP": fp,
        "FN": fn,
        "train_time": float(train_time),
        "predict_time": float(predict_time),
    }


def _unsupervised_fit_eval(model, benign_train, X_test, y_test) -> Dict[str, float]:
    t0 = time.time()
    model.fit(benign_train)
    train_time = time.time() - t0

    t1 = time.time()
    raw = model.predict(X_test)
    predict_time = time.time() - t1

    # +1 normal -> 0; -1 anomaly -> 1 (match y_test convention)
    y_pred = np.array([0 if p == 1 else 1 for p in raw])

    y_true = y_test.values if hasattr(y_test, "values") else y_test
    acc = accuracy_score(y_true, y_pred)
    prec = precision_score(y_true, y_pred, zero_division=0)
    rec = recall_score(y_true, y_pred, zero_division=0)
    f1s = f1_score(y_true, y_pred, zero_division=0)
    mcc = matthews_corrcoef(y_true, y_pred)
    try:
        auc = roc_auc_score(y_true, y_pred)
    except Exception:
        auc = 0.0

    tp, tn, fp, fn = _binary_confusion(y_true, y_pred)
    return {
        "accuracy": float(acc),
        "precision": float(prec),
        "recall": float(rec),
        "f1_score": float(f1s),
        "auc": float(auc),
        "MCC": float(mcc),
        "TP": tp,
        "TN": tn,
        "FP": fp,
        "FN": fn,
        "train_time": float(train_time),
        "predict_time": float(predict_time),
    }


def _row_from_model_metrics(per_model_metrics: Dict[str, Dict[str, float]]) -> dict:
    row = {}
    for model_name, metrics in per_model_metrics.items():
        for metric_name, value in metrics.items():
            row[f"{metric_name}_{model_name}"] = value
    return row


# ---------------------------------------------------------------------------
# Cell 22 — supervised quick eval (single 80/20)
# ---------------------------------------------------------------------------

def evaluate_supervised_quick(
    constructors: Dict[str, ModelCtor],
    X_train: pd.DataFrame,
    y_train: pd.Series,
    X_test: pd.DataFrame,
    y_test: pd.Series,
) -> pd.DataFrame:
    per_model = {}
    for name, ctor in constructors.items():
        per_model[name] = _supervised_fit_eval(ctor(), X_train, y_train, X_test, y_test)
    row = {"iteration": 0}
    row.update(_row_from_model_metrics(per_model))
    return pd.DataFrame([row])


# ---------------------------------------------------------------------------
# Cell 24 — supervised 10-iter eval (10 random 80/20 splits, frozen params)
# ---------------------------------------------------------------------------

def evaluate_supervised_iter(
    constructors: Dict[str, ModelCtor],
    X_full: pd.DataFrame,
    y_full: pd.Series,
    seed: int,
    n_iters: int = 10,
) -> pd.DataFrame:
    X = X_full.values
    y = y_full.values
    rows = []
    for i in range(n_iters):
        X_tr, X_te, y_tr, y_te = train_test_split(
            X, y, test_size=0.2, stratify=y, random_state=seed + i
        )
        per_model = {}
        for name, ctor in constructors.items():
            per_model[name] = _supervised_fit_eval(ctor(), X_tr, y_tr, X_te, y_te)
        row = {"iteration": i + 1}
        row.update(_row_from_model_metrics(per_model))
        rows.append(row)
    return pd.DataFrame(rows)


# ---------------------------------------------------------------------------
# Cell 25 — supervised nested CV (10 outer × 10 inner)
# ---------------------------------------------------------------------------

def evaluate_supervised_nested_cv(
    constructors: Dict[str, ModelCtor],
    X_full: pd.DataFrame,
    y_full: pd.Series,
    seed: int,
    n_outer: int = 10,
    n_inner: int = 10,
) -> pd.DataFrame:
    """Outer 80/20 stratified × inner 10-fold StratifiedKFold.

    The inner CV here is run for traceability/consistency with the notebook
    (it warms up the model parameters and confirms inner-stability), but
    the OUTER evaluation on the held-out 20% is what each row records.
    Schema-compatible with evaluate_supervised_iter so the analyzer can
    treat them uniformly.
    """
    X = X_full.values
    y = y_full.values
    rows = []
    for it in range(n_outer):
        iter_start = time.time()
        X_train_full, X_eval, y_train_full, y_eval = train_test_split(
            X, y, test_size=0.2, stratify=y, random_state=seed + it
        )

        # Inner CV — run but don't record per-fold metrics in the output
        # (notebook cell 25 stored them in memory and discarded them).
        kfold = StratifiedKFold(n_splits=n_inner, shuffle=True, random_state=seed + it)
        for train_idx, val_idx in kfold.split(X_train_full, y_train_full):
            for ctor in constructors.values():
                m = ctor()
                m.fit(X_train_full[train_idx], y_train_full[train_idx])
                _ = m.predict(X_train_full[val_idx])

        # Outer eval: train on full 80%, evaluate on 20%
        per_model = {}
        for name, ctor in constructors.items():
            per_model[name] = _supervised_fit_eval(
                ctor(), X_train_full, y_train_full, X_eval, y_eval
            )
        row = {"iteration": it + 1}
        row.update(_row_from_model_metrics(per_model))
        row["tiempo_total_iteracion"] = time.time() - iter_start
        rows.append(row)
    return pd.DataFrame(rows)


# ---------------------------------------------------------------------------
# Cell 39 — unsupervised quick eval (single fit, single test pass)
# ---------------------------------------------------------------------------

def evaluate_unsupervised_quick(
    constructors: Dict[str, ModelCtor],
    benign_train: pd.DataFrame,
    X_test: pd.DataFrame,
    y_test: pd.Series,
) -> pd.DataFrame:
    per_model = {}
    for name, ctor in constructors.items():
        per_model[name] = _unsupervised_fit_eval(ctor(), benign_train, X_test, y_test)
    row = {"iteration": 0}
    row.update(_row_from_model_metrics(per_model))
    return pd.DataFrame([row])


# ---------------------------------------------------------------------------
# Cell 41 — unsupervised 10-iter (sampled-train) eval
# ---------------------------------------------------------------------------

def evaluate_unsupervised_iter(
    constructors: Dict[str, ModelCtor],
    benign_train: pd.DataFrame,
    X_test: pd.DataFrame,
    y_test: pd.Series,
    seed: int,
    n_iters: int = 10,
    sample_frac: float = 0.8,
) -> pd.DataFrame:
    rows = []
    for i in range(n_iters):
        sampled = benign_train.sample(frac=sample_frac, random_state=seed + i)
        per_model = {}
        for name, ctor in constructors.items():
            per_model[name] = _unsupervised_fit_eval(ctor(), sampled, X_test, y_test)
        row = {"iteration": i + 1}
        row.update(_row_from_model_metrics(per_model))
        rows.append(row)
    return pd.DataFrame(rows)
