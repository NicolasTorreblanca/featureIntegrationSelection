"""Train/val/test partitioning.

Supervised (mirrors notebook cell 14):
  - 80/20 stratified train/test from the full dataset

Unsupervised (mirrors notebook cell 16, with one bug fix):
  - Benign rows: 60% train, 20% val, 20% test
  - Malign rows: 20% val, 20% test, drawn from disjoint pools
  - Notebook drew val and test malign sets independently from the full malign
    set with different seeds, so they could overlap (~4% expected overlap).
    Here val and test malign pools are explicitly disjoint so val scores
    used by Optuna are an honest signal for tuning.
"""

from __future__ import annotations

from dataclasses import dataclass

import pandas as pd
from sklearn.model_selection import train_test_split

from .data import TARGET_COLUMN


@dataclass
class SupervisedSplit:
    X_train: pd.DataFrame
    X_test: pd.DataFrame
    y_train: pd.Series
    y_test: pd.Series
    X_full: pd.DataFrame
    y_full: pd.Series


@dataclass
class UnsupervisedSplit:
    benign_train: pd.DataFrame   # 60% benign, no 'category' column
    X_valid: pd.DataFrame        # 20% benign + 20% malign (disjoint from test)
    y_valid: pd.Series
    X_test: pd.DataFrame         # 20% benign + 20% malign (disjoint from val)
    y_test: pd.Series


def supervised_split(df: pd.DataFrame, seed: int = 42) -> SupervisedSplit:
    X = df.drop(columns=[TARGET_COLUMN])
    y = df[TARGET_COLUMN]
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, stratify=y, random_state=seed
    )
    return SupervisedSplit(
        X_train=X_train,
        X_test=X_test,
        y_train=y_train,
        y_test=y_test,
        X_full=X,
        y_full=y,
    )


def unsupervised_split(df: pd.DataFrame, seed: int = 42) -> UnsupervisedSplit:
    df_benign = df[df[TARGET_COLUMN] == 0]
    df_malign = df[df[TARGET_COLUMN] == 1]

    # Benign: 60/20/20 train/val/test
    benign_train, benign_rest = train_test_split(
        df_benign, test_size=0.4, random_state=seed
    )
    benign_val, benign_test = train_test_split(
        benign_rest, test_size=0.5, random_state=seed + 1
    )
    benign_train = benign_train.drop(columns=[TARGET_COLUMN])

    # Malign: 40% pool, 50/50 split (= 20% val + 20% test, disjoint).
    # Matches notebook proportions but with explicit disjointness.
    malign_pool, _ = train_test_split(df_malign, test_size=0.6, random_state=seed + 2)
    malign_val, malign_test = train_test_split(
        malign_pool, test_size=0.5, random_state=seed + 3
    )

    X_valid = pd.concat(
        [
            benign_val.drop(columns=[TARGET_COLUMN]),
            malign_val.drop(columns=[TARGET_COLUMN]),
        ],
        ignore_index=True,
    )
    y_valid = pd.Series(
        [0] * len(benign_val) + [1] * len(malign_val),
        name=TARGET_COLUMN,
    )

    X_test = pd.concat(
        [
            benign_test.drop(columns=[TARGET_COLUMN]),
            malign_test.drop(columns=[TARGET_COLUMN]),
        ],
        ignore_index=True,
    )
    y_test = pd.Series(
        [0] * len(benign_test) + [1] * len(malign_test),
        name=TARGET_COLUMN,
    )

    return UnsupervisedSplit(
        benign_train=benign_train,
        X_valid=X_valid,
        y_valid=y_valid,
        X_test=X_test,
        y_test=y_test,
    )
