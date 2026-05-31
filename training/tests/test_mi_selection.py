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


def test_train_only_selection_differs_from_full_frame():
    """Genuine leakage guard: train-only and full-frame fits must pick different
    winners. f_trainonly is near-perfect in train but anti-correlated in test
    (so its MI collapses over the full frame); g is mildly informative everywhere.
    If select_mi_top_k_on ignored train_idx, both calls would return the same
    list and this test would fail."""
    rng = np.random.default_rng(3)
    n = 1000
    y = rng.integers(0, 2, size=n)
    train_idx = np.arange(0, 500)
    all_idx = np.arange(0, n)

    f = y.astype(float).copy()
    f[500:] = 1.0 - y[500:]                  # anti-correlated in the test half
    f = f + rng.normal(0, 0.01, size=n)      # near-perfect in train; ~0 MI over full frame
    g = y + rng.normal(0, 1.0, size=n)       # mildly informative everywhere

    df = pd.DataFrame({"f_trainonly": f, "g": g, TARGET_COLUMN: y})

    train_feats, _ = select_mi_top_k_on(df, train_idx=train_idx, k=1, seed=0)
    full_feats, _ = select_mi_top_k_on(df, train_idx=all_idx, k=1, seed=0)

    assert train_feats == ["f_trainonly"]    # train-only sees the train-perfect feature
    assert full_feats == ["g"]               # full-frame: f's MI collapses, g wins
    assert train_feats != full_feats         # => function genuinely respects train_idx


def test_deterministic_under_same_seed():
    df = _frame()
    a = select_mi_top_k_on(df, train_idx=np.arange(len(df)), k=2, seed=7)
    b = select_mi_top_k_on(df, train_idx=np.arange(len(df)), k=2, seed=7)
    assert a == b
