"""Data loading and feature selection.

Mirrors notebook cells 4, 6, 8, 10:
  - load CSV
  - drop label-leak columns ('label' or 'proto-number') if present
  - StandardScaler + SelectKBest(mutual_info_classif) for MI top-K selection
  - return un-scaled selected columns (downstream models do their own scaling
    where needed; tree models don't need it, OCSVM/LOF/EE fit scaling at runtime)
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional

import numpy as np
import pandas as pd
from sklearn.feature_selection import SelectKBest, mutual_info_classif
from sklearn.preprocessing import StandardScaler

from .datasets import DatasetConfig

LABEL_LEAK_COLUMNS = ("label", "proto-number")
TARGET_COLUMN = "category"


@dataclass
class PreparedData:
    df: pd.DataFrame                # un-scaled, selected columns + 'category'
    selected_features: List[str]    # feature column names actually used
    full_feature_set: List[str]     # all numeric features available pre-selection
    mi_scores: Optional[List[float]] = None  # MI scores per selected feature (None if --no-mi)


def load_csv(path: str) -> pd.DataFrame:
    df = pd.read_csv(path)
    if TARGET_COLUMN not in df.columns:
        raise ValueError(
            f"Input CSV missing required '{TARGET_COLUMN}' column. "
            f"Found columns: {list(df.columns)[:10]}..."
        )
    return df


def drop_label_leak_columns(df: pd.DataFrame) -> pd.DataFrame:
    to_drop = [c for c in LABEL_LEAK_COLUMNS if c in df.columns]
    if to_drop:
        df = df.drop(columns=to_drop)
    return df


def _numeric_feature_columns(df: pd.DataFrame) -> List[str]:
    X = df.drop(columns=[TARGET_COLUMN]).select_dtypes(include=["int64", "float64"])
    return list(X.columns)


def select_mi_top_k(
    df: pd.DataFrame,
    k: int,
    seed: int,
) -> tuple[List[str], List[float]]:
    """Return the top-K feature names by mutual information with 'category'.

    Scaling is applied only to compute MI (mutual_info_classif uses a kNN-based
    estimator that is sensitive to feature scale). The returned column names
    refer back to the un-scaled DataFrame.
    """
    feature_cols = _numeric_feature_columns(df)
    X = df[feature_cols].values
    y = df[TARGET_COLUMN].values

    X_scaled = StandardScaler().fit_transform(X)

    selector = SelectKBest(
        score_func=lambda X, y: mutual_info_classif(X, y, random_state=seed),
        k=k,
    )
    selector.fit(X_scaled, y)

    mask = selector.get_support()
    selected = [feature_cols[i] for i in range(len(feature_cols)) if mask[i]]
    scores = [float(selector.scores_[i]) for i in range(len(feature_cols)) if mask[i]]
    return selected, scores


def select_mi_top_k_on(
    df: pd.DataFrame,
    train_idx: "np.ndarray",
    k: int,
    seed: int,
) -> tuple[list[str], list[float]]:
    """MI top-K selection fit ONLY on the rows in train_idx (leakage-free).

    Returns (feature_names, mi_scores). The same names are later applied to
    both train and test columns by the caller.
    """
    feature_cols = _numeric_feature_columns(df)
    train = df.iloc[train_idx]
    X = train[feature_cols].values
    y = train[TARGET_COLUMN].values
    X_scaled = StandardScaler().fit_transform(X)
    scores = mutual_info_classif(X_scaled, y, random_state=seed)
    order = np.argsort(scores)[::-1][:k]
    selected = [feature_cols[i] for i in order]
    sel_scores = [float(scores[i]) for i in order]
    return selected, sel_scores


def normalize_frame(df: pd.DataFrame, cfg: DatasetConfig) -> pd.DataFrame:
    """Produce a uniform binary `category` target + drop leak/aux columns.

    - label_map == "binary_normal": derive category = (label != 'normal'), drop source label.
    - label_map is None: source label_col already binary; rename to category if needed.
    Then drop cfg.drop_cols (if present).
    """
    df = df.copy()
    if cfg.label_map == "binary_normal":
        df[TARGET_COLUMN] = (df[cfg.label_col].astype(str).str.lower() != "normal").astype(int)
        if cfg.label_col != TARGET_COLUMN:
            df = df.drop(columns=[cfg.label_col])
    elif cfg.label_map is None:
        if cfg.label_col != TARGET_COLUMN:
            df = df.rename(columns={cfg.label_col: TARGET_COLUMN})
    else:
        raise ValueError(f"Unknown label_map: {cfg.label_map}")

    drop = [c for c in cfg.drop_cols if c in df.columns and c != TARGET_COLUMN]
    if drop:
        df = df.drop(columns=drop)
    return df


def load_normalized(cfg: DatasetConfig) -> pd.DataFrame:
    """Load a dataset CSV from disk and normalize its schema.

    Resets to a clean 0..n-1 RangeIndex so that train-row positions captured
    via `X_train.index` are valid for positional `iloc` in leakage-free MI
    selection (avoids silent wrong-row selection on non-default indices).
    """
    df = pd.read_csv(cfg.path)
    df = normalize_frame(df, cfg)
    return df.reset_index(drop=True)


def prepare(
    input_csv: str,
    use_mi: bool = True,
    k: int = 10,
    seed: int = 42,
) -> PreparedData:
    df = load_csv(input_csv)
    df = drop_label_leak_columns(df)

    full_features = _numeric_feature_columns(df)

    if use_mi:
        selected, scores = select_mi_top_k(df, k=k, seed=seed)
        out_df = df[selected + [TARGET_COLUMN]].copy()
        return PreparedData(
            df=out_df,
            selected_features=selected,
            full_feature_set=full_features,
            mi_scores=scores,
        )

    # --no-mi path: keep all numeric features
    out_df = df[full_features + [TARGET_COLUMN]].copy()
    return PreparedData(
        df=out_df,
        selected_features=full_features,
        full_feature_set=full_features,
        mi_scores=None,
    )
