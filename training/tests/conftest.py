"""Shared pytest fixtures: tiny synthetic frames that mimic each dataset's schema."""
import numpy as np
import pandas as pd
import pytest


@pytest.fixture
def rng():
    return np.random.default_rng(0)


@pytest.fixture
def og_frame(rng):
    """Mimics Ton-IoT-OGFets.csv: binary `category`, plus `label` and `type` leaks."""
    n = 2000
    y = np.r_[np.zeros(1300, int), np.ones(700, int)]
    df = pd.DataFrame({
        "f1": rng.normal(size=n),
        "f2": rng.normal(size=n),
        "f3": rng.integers(0, 5, size=n).astype(float),
        "label": y,                                  # binary leak (dup of category)
        "type": np.where(y == 0, "normal", "dos"),   # multiclass leak (string)
        "category": y,
    })
    return df


@pytest.fixture
def gens_frame(rng):
    """Mimics TonIoT-30ShapFets.csv: NO category; multiclass string `label`."""
    n = 2000
    benign = ["normal"] * 1300
    attacks = list(rng.choice(["dos", "ddos", "xss"], size=700))
    lab = benign + attacks
    df = pd.DataFrame({
        "proto_tcp": rng.normal(size=n),
        "H_L0.01_weight": rng.normal(size=n),
        "src_pkts": rng.integers(0, 9, size=n).astype(float),
        "label": lab,
    })
    return df
