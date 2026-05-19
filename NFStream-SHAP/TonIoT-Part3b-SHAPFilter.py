# TonIoT-Part3b-SHAPFilter.py
#
# Filtra cada _processed.csv para conservar solo las columnas listadas en
# output/ToN-IoT/top10_global.csv (producido por shap_analysis_multidataset.py),
# más la columna 'label' que Part4 necesita para muestrear por clase.
#
# Lee el archivo SHAP en cada corrida — si se re-corre el análisis SHAP y el
# top-10 cambia, este script automáticamente usa la nueva lista.
#
# Entrada : Ton-IoT-Processed/*_processed.csv  (de Part3)
#           output/ToN-IoT/top10_global.csv    (del análisis SHAP)
# Salida  : Ton-IoT-SHAP/*_shap.csv

import os
import pandas as pd
from pathlib import Path

SCRIPT_DIR    = Path(__file__).resolve().parent
SHAP_RESULTS  = SCRIPT_DIR.parent.parent / "output" / "ToN-IoT" / "top10_global.csv"
INPUT_FOLDER  = SCRIPT_DIR / "Ton-IoT-Processed"
OUTPUT_FOLDER = SCRIPT_DIR / "Ton-IoT-SHAP"


def load_shap_features():
    if not SHAP_RESULTS.exists():
        raise FileNotFoundError(
            f"SHAP results not found at {SHAP_RESULTS}. "
            "Run shap_analysis_multidataset.py first."
        )
    df = pd.read_csv(SHAP_RESULTS, index_col=0)
    features = df.index.tolist()
    print(f"SHAP feature list ({len(features)}): {features}")
    return features


def filter_to_shap(processed_csv: Path, output_csv: Path, features: list):
    df = pd.read_csv(processed_csv)
    missing = [f for f in features if f not in df.columns]
    if missing:
        raise RuntimeError(
            f"SHAP-required columns missing from {processed_csv.name}: {missing}. "
            "Check Part1 vocabulary normalization "
            "(proto / conn_state / service / dns_rejected values)."
        )
    keep = features + ['label']
    df[keep].to_csv(output_csv, index=False)
    print(f"Guardado: {output_csv} ({len(df)} filas, {len(keep)} columnas)")


if __name__ == "__main__":
    OUTPUT_FOLDER.mkdir(parents=True, exist_ok=True)
    features = load_shap_features()

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
        filter_to_shap(in_path, out_path, features)

    print(f"\nFiltro SHAP completado. Salida en: {OUTPUT_FOLDER}")
