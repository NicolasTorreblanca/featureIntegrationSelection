# TonIoT-Part2-integrator-of-features.py  (NFStream-SHAP variant)
#
# Igual a NFStream/Part2 (entropía + wavelet + mutual-information sobre
# características crudas) excepto:
#   1. Referencias de columnas usan guión bajo (no guión).
#   2. La derivación sintética de conn-state (S0/SF/OTH desde packet counts)
#      se elimina — ahora usamos el conn_state upstream que viene de Part1
#      (NFStream's flow.connection_state). Sin este cambio nunca aparecería
#      'REJ' en conn_state y SHAP perdería conn_state_REJ.
#   3. Fail-fast si la carpeta de entrada está vacía.
#
# Entrada : DATASETS/*_base.csv     (de Part1)
# Salida  : Ton-IoT-MultiFet/*_combined.csv

import os
import pandas as pd
import numpy as np
import pywt
from scipy.stats import entropy
from sklearn.metrics import mutual_info_score
from collections import defaultdict
from pathlib import Path

SELECTED_FEATURES = [
    'conn_state', 'service', 'http_status_code', 'src_ip_bytes', 'dst_ip_bytes',
    'dst_port', 'src_pkts', 'dst_pkts', 'proto',
    'MI_dir_L5_weight', 'HH_L3_weight', 'HH_L0.01_weight',
    'HpHp_L0.01_weight', 'HpHp_L0.01_mean', 'HpHp_L0.01_std', 'HpHp_L0.01_magnitude',
    'N_IN_Conn_P_DstIP', 'N_IN_Conn_P_SrcIP', 'state_number', 'proto_number',
    'stime', 'max', 'mean', 'min', 'stddev', 'label',
]

_PROTO_TO_NUM = {"tcp": 6, "udp": 17, "Other": 0, "None": -1}
_STATE_TO_NUM = {"S0": 1, "SF": 2, "REJ": 3, "OTH": 0, "Other": -1, "None": -2}


def compute_nbaiot_features(values):
    values = np.array(values, dtype=float)
    if len(values) < 4:
        values = np.pad(values, (0, 4 - len(values)), 'constant')
    coeffs = pywt.wavedec(values, 'db1', level=2)
    approx = coeffs[0]
    rounded = np.round(values).astype(int)
    labels_true = np.arange(len(rounded))
    mi_score = mutual_info_score(labels_true, rounded)
    return {
        'MI_dir_L5_weight':     mi_score,
        'HH_L3_weight':         entropy(values + 1e-6),
        'HH_L0.01_weight':      np.sum(np.power(values / np.sum(values + 1e-6), 0.01)),
        'HpHp_L0.01_weight':    np.sum(np.square(values)),
        'HpHp_L0.01_mean':      np.mean(approx),
        'HpHp_L0.01_std':       np.std(approx),
        'HpHp_L0.01_magnitude': np.linalg.norm(approx),
    }


def enrich_dataset(df):
    src_ip_counter = defaultdict(int)
    dst_ip_counter = defaultdict(int)
    enriched_rows = []

    required_fields = [
        'src_ip', 'dst_ip', 'src_pkts', 'dst_pkts',
        'src_ip_bytes', 'dst_ip_bytes', 'proto', 'dst_port',
        'stime', 'conn_state', 'service', 'label',
    ]

    for _, row in df.iterrows():
        if any(pd.isna(row.get(f)) for f in required_fields):
            continue

        try:
            src_ip      = row['src_ip']
            dst_ip      = row['dst_ip']
            src_bytes   = row['src_ip_bytes']
            dst_bytes   = row['dst_ip_bytes']
            src_pkts    = row['src_pkts']
            dst_pkts    = row['dst_pkts']
            proto_str   = row['proto']
            dst_port    = row['dst_port']
            stime       = row['stime']
            conn_state  = row['conn_state']     # upstream — NO synthetic derivation
            service     = row['service']

            src_ip_counter[src_ip] += 1
            dst_ip_counter[dst_ip] += 1

            signal_values = [src_bytes, dst_bytes, src_pkts, dst_pkts]
            nbaiot_feats  = compute_nbaiot_features(signal_values)

            feature_row = {
                'conn_state':         conn_state,
                'service':            service,
                'http_status_code':   row.get('http_status_code', -1),
                'src_ip_bytes':       src_bytes,
                'dst_ip_bytes':       dst_bytes,
                'dst_port':           dst_port,
                'src_pkts':           src_pkts,
                'dst_pkts':           dst_pkts,
                'proto':              proto_str,
                **nbaiot_feats,
                'N_IN_Conn_P_SrcIP':  src_ip_counter[src_ip],
                'N_IN_Conn_P_DstIP':  dst_ip_counter[dst_ip],
                'state_number':       _STATE_TO_NUM.get(conn_state, -1),
                'proto_number':       _PROTO_TO_NUM.get(proto_str, -1),
                'stime':              stime,
                'max':                np.max(signal_values),
                'mean':               np.mean(signal_values),
                'min':                np.min(signal_values),
                'stddev':             np.std(signal_values),
                'label':              row['label'],
            }

            filtered_row = {key: feature_row[key] for key in SELECTED_FEATURES}
            enriched_rows.append(filtered_row)

        except Exception as e:
            print(f"Error enriqueciendo fila: {e}")

    return pd.DataFrame(enriched_rows)


if __name__ == "__main__":
    script_dir    = Path(__file__).resolve().parent
    input_folder  = script_dir / "DATASETS"
    output_folder = script_dir / "Ton-IoT-MultiFet"
    output_folder.mkdir(parents=True, exist_ok=True)

    base_files = [f for f in os.listdir(input_folder) if f.endswith("_base.csv")]
    if not base_files:
        raise RuntimeError(
            f"No _base.csv files in {input_folder}. Run Part1 first."
        )

    processed_files = 0
    skipped_files   = 0

    for file in base_files:
        output_name = file.replace("_base.csv", "_combined.csv")
        output_path = output_folder / output_name

        if output_path.exists():
            print(f"Ya existe: {output_name} — omitido.")
            skipped_files += 1
            continue

        input_path = input_folder / file
        print(f"\nEnriqueciendo: {file}")
        df_base = pd.read_csv(input_path)
        df_enriched = enrich_dataset(df_base)

        if not df_enriched.empty:
            df_enriched.to_csv(output_path, index=False)
            print(f"Guardado: {output_path}")
            processed_files += 1
        else:
            print(f"{file} fue omitido por falta de datos válidos.")

    print(f"\n{processed_files} archivos enriquecidos.")
    print(f"{skipped_files} archivos ya existían y fueron omitidos.")
