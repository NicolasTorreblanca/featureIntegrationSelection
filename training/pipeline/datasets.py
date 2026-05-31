"""Registry of the three modeling datasets and their schema adapters.

All three share the same ToN-IoT instance base (461,043 rows, 300k benign /
161k attack) but differ in feature pool and label encoding. Paths are relative
to the repo root (featureIntegrationSelection/).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, Tuple


@dataclass(frozen=True)
class DatasetConfig:
    tag: str
    path: str
    label_col: str                       # source label column in the CSV
    label_map: Optional[str] = None      # None = already binary; "binary_normal" = normal->0 else->1
    drop_cols: Tuple[str, ...] = field(default_factory=tuple)  # leak/aux columns to drop


DATASETS = {
    "OG10": DatasetConfig(
        tag="OG10",
        path="Ton-IoT-OGFets.csv",
        label_col="category",
        label_map=None,
        drop_cols=("label", "type"),
    ),
    "Gen10": DatasetConfig(
        tag="Gen10",
        path="TonIoT-ManualFets.csv",
        label_col="category",
        label_map=None,
        # 'stime' (absolute start time) is a TEMPORAL LEAK: AUC 1.0 vs label
        # (benign/attack captured in separate sessions). Dropped. See 'duration'
        # which is a legit relative feature and is kept.
        drop_cols=("proto-number", "stime"),
    ),
    "GenS10": DatasetConfig(
        tag="GenS10",
        path="TonIoT-30ShapFets.csv",
        label_col="label",
        label_map="binary_normal",
        # 'ltime' (absolute last time) is a TEMPORAL LEAK: AUC 1.0 vs label. Dropped.
        # 'dur' (duration) is a legit relative feature and is kept.
        drop_cols=("ltime",),
    ),
}
