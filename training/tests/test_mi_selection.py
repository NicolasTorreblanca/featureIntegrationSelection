import numpy as np
import pandas as pd
from pipeline.data import select_mi_top_k_on, TARGET_COLUMN


def _frame(seed=0):
    rng = np.random.default_rng(seed)
    n = 1000
    y = rng.integers(0, 2, size=n)
    # f_good correlates with y; f_noise does not
    df = pd.DataFrame({
        "f_good": y + rng.normal(0, 0.1, size=n),
        "f_mid": y * 0.3 + rng.normal(0, 1, size=n),
        "f_noise": rng.normal(size=n),
        TARGET_COLUMN: y,
    })
    return df


def test_selects_k_features_and_ranks_informative_first():
    df = _frame()
    feats, scores = select_mi_top_k_on(df, train_idx=np.arange(len(df)), k=2, seed=42)
    assert len(feats) == 2
    assert "f_good" in feats            # most informative must be picked
    assert TARGET_COLUMN not in feats


def test_only_train_rows_influence_selection():
    df = _frame()
    # Corrupt the TEST half's labels; selection must be unaffected (train-only fit)
    train_idx = np.arange(0, 500)
    test_idx = np.arange(500, 1000)
    df_corrupt = df.copy()
    df_corrupt.loc[test_idx, TARGET_COLUMN] = 0  # destroy test signal
    feats_a, _ = select_mi_top_k_on(df, train_idx=train_idx, k=2, seed=42)
    feats_b, _ = select_mi_top_k_on(df_corrupt, train_idx=train_idx, k=2, seed=42)
    assert feats_a == feats_b           # test labels never consulted


def test_deterministic_under_same_seed():
    df = _frame()
    a = select_mi_top_k_on(df, train_idx=np.arange(len(df)), k=2, seed=7)
    b = select_mi_top_k_on(df, train_idx=np.arange(len(df)), k=2, seed=7)
    assert a == b
