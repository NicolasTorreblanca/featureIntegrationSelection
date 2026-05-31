import numpy as np
import pandas as pd
from pipeline.subsample import subsample_rows


def _df(n=10000):
    return pd.DataFrame({"a": np.arange(n), "b": np.arange(n) * 2})


def test_returns_exact_n():
    out = subsample_rows(_df(), n=2000, seed=1)
    assert len(out) == 2000


def test_no_op_when_n_ge_len():
    df = _df(500)
    out = subsample_rows(df, n=2000, seed=1)
    assert len(out) == 500
    assert out.equals(df)


def test_deterministic_under_same_seed():
    a = subsample_rows(_df(), n=2000, seed=42)
    b = subsample_rows(_df(), n=2000, seed=42)
    assert a.equals(b)


def test_different_seed_different_sample():
    a = subsample_rows(_df(), n=2000, seed=1)
    b = subsample_rows(_df(), n=2000, seed=2)
    assert not a.equals(b)
