import pandas as pd
from pipeline.data import normalize_frame, TARGET_COLUMN
from pipeline.datasets import DatasetConfig


def test_gens_multiclass_becomes_binary(gens_frame):
    cfg = DatasetConfig("GenS10", "x.csv", "label", "binary_normal", ())
    out = normalize_frame(gens_frame, cfg)
    assert TARGET_COLUMN in out.columns
    assert "label" not in out.columns               # original label dropped
    assert set(out[TARGET_COLUMN].unique()) == {0, 1}
    assert int((out[TARGET_COLUMN] == 0).sum()) == 1300   # all 'normal'
    assert int((out[TARGET_COLUMN] == 1).sum()) == 700


def test_og_drops_label_and_type_keeps_category(og_frame):
    cfg = DatasetConfig("OG10", "x.csv", "category", None, ("label", "type"))
    out = normalize_frame(og_frame, cfg)
    assert TARGET_COLUMN in out.columns
    assert "label" not in out.columns and "type" not in out.columns
    assert set(out[TARGET_COLUMN].unique()) == {0, 1}
