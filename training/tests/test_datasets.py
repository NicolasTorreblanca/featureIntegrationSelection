from pipeline.datasets import DATASETS, DatasetConfig


def test_three_datasets_registered():
    assert set(DATASETS) == {"OG10", "Gen10", "GenS10"}


def test_configs_have_required_fields():
    for tag, cfg in DATASETS.items():
        assert isinstance(cfg, DatasetConfig)
        assert cfg.path.endswith(".csv")
        assert cfg.label_col
        assert isinstance(cfg.drop_cols, tuple)


def test_gens_uses_label_with_binary_map():
    cfg = DATASETS["GenS10"]
    assert cfg.label_col == "label"
    assert cfg.label_map == "binary_normal"


def test_og_and_gen_use_category_no_map():
    assert DATASETS["OG10"].label_col == "category"
    assert DATASETS["OG10"].label_map is None
    assert "type" in DATASETS["OG10"].drop_cols
    assert "label" in DATASETS["OG10"].drop_cols
    assert DATASETS["Gen10"].label_col == "category"
    assert DATASETS["Gen10"].label_map is None
    assert "proto-number" in DATASETS["Gen10"].drop_cols


def test_temporal_leak_columns_dropped():
    # stime/ltime are absolute timestamps that perfectly proxy the label
    # (single-feature AUC 1.0). They MUST be dropped or models "learn the clock".
    assert "stime" in DATASETS["Gen10"].drop_cols
    assert "ltime" in DATASETS["GenS10"].drop_cols
