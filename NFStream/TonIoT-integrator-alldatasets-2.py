import os
import pandas as pd
import numpy as np
import pywt
from scipy.stats import entropy
from sklearn.metrics import mutual_info_score
from collections import defaultdict

def compute_nbaiot_features(values):
    """Calcula características tipo N-BaIoT desde una lista de valores."""
    values = np.array(values, dtype=float)
    if len(values) < 4:
        values = np.pad(values, (0, 4 - len(values)), 'constant')

    coeffs = pywt.wavedec(values, 'db1', level=2)
    approx = coeffs[0]

    rounded_vals = np.round(values).astype(int)
    labels_true = np.arange(len(rounded_vals))
    mi_score = mutual_info_score(labels_true, rounded_vals)

    return {
        'MI-dir-L5-weight': mi_score,
        'HH-L3-weight': entropy(values + 1e-6),
        'HH-L0.01-weight': np.sum(np.power(values / np.sum(values + 1e-6), 0.01)),
        'HpHp-L0.01-weight': np.sum(np.square(values)),
        'HpHp-L0.01-mean': np.mean(approx),
        'HpHp-L0.01-std': np.std(approx),
        'HpHp-L0.01-magnitude': np.linalg.norm(approx)
    }

def enrich_dataset(df):
    src_ip_counter = defaultdict(int)
    dst_ip_counter = defaultdict(int)

    enriched_rows = []

    for _, row in df.iterrows():
        try:
            # Valores base
            src_ip = row['src-ip']
            dst_ip = row['dst-ip']
            src_bytes = row['src-ip-bytes']
            dst_bytes = row['dst-ip-bytes']
            src_pkts = row['src2dst_packets']
            dst_pkts = row['dst2src_packets']
            proto = row['protocol']
            stime = row['stime']

            # Contadores IP
            src_ip_counter[src_ip] += 1
            dst_ip_counter[dst_ip] += 1

            if src_pkts > 0 and dst_pkts == 0:
                conn_state = "S0"
            elif src_pkts > 0 and dst_pkts > 0:
                conn_state = "SF"
            else:
                conn_state = "OTH"
            state_map = {"S0": 1, "SF": 2, "OTH": 0}
            state_number = state_map.get(conn_state, 0)

            # Señales para N-BaIoT
            signal_values = [src_bytes, dst_bytes, src_pkts, dst_pkts]

            # N-BaIoT
            nbaiot_feats = compute_nbaiot_features(signal_values)

            # BoT-IoT
            botiot_feats = {
                'N-IN-Conn-P-SrcIP': src_ip_counter[src_ip],
                'N-IN-Conn-P-DstIP': dst_ip_counter[dst_ip],
                'state-number': state_number,
                'proto-number': proto,
                'stime': stime,
                'max': np.max(signal_values),
                'mean': np.mean(signal_values),
                'min': np.min(signal_values),
                'stddev': np.std(signal_values)
            }

            # ToN-IoT
            toniot_feats = {
                'dns-query': row.get('dns-query', ''),
                'dns-rejected': row.get('dns-rejected', 0),
                'dns-RD': row.get('dns-RD', 0),
                'state': row.get('state', 'OTH'),
                'service': row.get('service', '-'),
                'http-status-code': row.get('http-status-code', -1),
                'src-bytes': src_bytes,
                'dst-ip-bytes': dst_bytes
            }

            enriched_rows.append({
                **toniot_feats,
                **nbaiot_feats,
                **botiot_feats,
                'label': row['label']
            })
        except Exception as e:
            print(f"Error enriqueciendo fila: {e}")

    return pd.DataFrame(enriched_rows)

if __name__ == "__main__":
    script_dir = os.path.dirname(os.path.abspath(__file__))
    input_folder = os.path.join(script_dir, "DATASETS")
    output_folder = os.path.join(script_dir, "Ton-IoT-MultiFet")
    os.makedirs(output_folder, exist_ok=True)

    processed_files = 0
    skipped_files = 0

    for file in os.listdir(input_folder):
        if file.endswith("_base.csv"):
            output_name = file.replace("_base.csv", "_combined.csv")
            output_path = os.path.join(output_folder, output_name)

            if os.path.exists(output_path):
                print(f"Ya existe: {output_name} — omitido.")
                skipped_files += 1
                continue

            input_path = os.path.join(input_folder, file)
            print(f"\nEnriqueciendo: {file}")
            df_base = pd.read_csv(input_path)
            df_enriched = enrich_dataset(df_base)
            df_enriched.to_csv(output_path, index=False)
            print(f"Guardado: {output_path}")
            processed_files += 1

    print(f"\n{processed_files} archivos enriquecidos.")
    print(f"{skipped_files} archivos ya existían y fueron omitidos.")
