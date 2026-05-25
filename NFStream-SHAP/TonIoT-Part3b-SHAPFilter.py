# TonIoT-Part3b-SHAPFilter.py  (UNION edition)
#
# Filtra cada _processed.csv para conservar solo las columnas listadas en la
# UNION de los tres top10_global.csv producidos por shap_analysis_multidataset.py:
#   - output/ToN-IoT/top10_global.csv
#   - output/BoT-IoT/top10_global.csv
#   - output/N-BaIoT/top10_global.csv
# mas la columna 'label' que Part4 necesita para muestrear por clase.
#
# Lee los tres archivos SHAP en cada corrida. Si alguna columna del union no
# esta en el _processed.csv de entrada, falla loudly con un diagnostico.
#
# Entrada : Ton-IoT-Processed/*_processed.csv  (de Part3)
#           output/{ToN-IoT,BoT-IoT,N-BaIoT}/top10_global.csv  (del SHAP analysis)
# Salida  : Ton-IoT-SHAP/*_shap.csv

import os
import pandas as pd
from pathlib import Path

SCRIPT_DIR    = Path(__file__).resolve().parent
OUTPUT_ROOT   = SCRIPT_DIR.parent.parent / "output"
SHAP_DATASETS = ("ToN-IoT", "BoT-IoT", "N-BaIoT")
INPUT_FOLDER  = SCRIPT_DIR / "Ton-IoT-Processed"
OUTPUT_FOLDER = SCRIPT_DIR / "Ton-IoT-SHAP"


def load_shap_union():
    """Lee los 3 top10_global.csv y devuelve la union ordenada de sus columnas
    (preservando el orden de aparicion: primero ToN-IoT, luego BoT-IoT,
    luego N-BaIoT). Reporta overlaps si existen."""
    seen   = set()
    ordered_union = []
    per_dataset   = {}

    for name in SHAP_DATASETS:
        path = OUTPUT_ROOT / name / "top10_global.csv"
        if not path.exists():
            raise FileNotFoundError(
                f"SHAP results not found at {path}. "
                "Run shap_analysis_multidataset.py first."
            )
        df = pd.read_csv(path, index_col=0)
        feats = df.index.tolist()
        per_dataset[name] = feats
        for f in feats:
            if f not in seen:
                ordered_union.append(f)
                seen.add(f)

    print(f"SHAP top-10 per dataset:")
    for name, feats in per_dataset.items():
        print(f"  {name:<10s} ({len(feats):2d}): {feats}")
    overlaps = [f for f in seen
                if sum(f in feats for feats in per_dataset.values()) > 1]
    if overlaps:
        print(f"Cross-dataset overlaps ({len(overlaps)}): {overlaps}")
    print(f"Union total ({len(ordered_union)}): {ordered_union}")
    return ordered_union


def filter_to_union(processed_csv: Path, output_csv: Path, features: list):
    df = pd.read_csv(processed_csv)
    missing = [f for f in features if f not in df.columns]
    if missing:
        raise RuntimeError(
            f"SHAP-union columns missing from {processed_csv.name}: {missing}. "
            "Check Part2's SELECTED_FEATURES + Part3's CATEGORICAL_COLS/NUMERIC_COLS "
            "wiring (every union column must reach _processed.csv either as raw "
            "numeric or via one-hot expansion of a categorical)."
        )
    keep = features + ['label']
    df[keep].to_csv(output_csv, index=False)
    print(f"Guardado: {output_csv.name} ({len(df)} filas, {len(keep)} columnas)")


if __name__ == "__main__":
    OUTPUT_FOLDER.mkdir(parents=True, exist_ok=True)
    features = load_shap_union()

    processed_files = [f for f in os.listdir(INPUT_FOLDER)
                       if f.endswith("_processed.csv")]
    if not processed_files:
        raise RuntimeError(
            f"No _processed.csv files in {INPUT_FOLDER}. Run Part3 first."
        )

    for file in processed_files:
        in_path  = INPUT_FOLDER / file
        out_path = OUTPUT_FOLDER / file.replace("_processed.csv", "_shap.csv")
        if out_path.exists():
            print(f"Ya existe: {out_path.name} — omitido.")
            continue
        filter_to_union(in_path, out_path, features)

    print(f"\nFiltro SHAP union completado. Salida en: {OUTPUT_FOLDER}")
