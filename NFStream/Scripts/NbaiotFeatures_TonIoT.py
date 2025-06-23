# generate_nbaiot_features.py

import pandas as pd
import numpy as np
import pywt
from scipy.stats import entropy
from sklearn.metrics import mutual_info_score
import os

def extract_nbaiot_selected_features(flow_id, group):
    result = {}

    signal = group['src-ip-bytes'].values
    if len(signal) < 4:
        signal = np.pad(signal, (0, 4 - len(signal)), 'constant')

    result['flow_id'] = flow_id

    # MI-dir-L5-weight
    result['MI-dir-L5-weight'] = mutual_info_score(group['src-ip-bytes'], group['dst-ip-bytes'])

    # HH-L3-weight
    hist_L3, _ = np.histogram(signal, bins=8, density=True)
    result['HH-L3-weight'] = entropy(hist_L3 + 1e-10)

    # HH-L0.01-weight
    hist_L001, _ = np.histogram(signal, bins=100, density=True)
    result['HH-L0.01-weight'] = entropy(hist_L001 + 1e-10)

    # HpHp-L0.01-* features
    coeffs = pywt.wavedec(signal, 'db1', level=2)
    cA = coeffs[0]

    result['HpHp-L0.01-weight'] = np.sum(np.square(cA))
    result['HpHp-L0.01-mean'] = np.mean(cA)
    result['HpHp-L0.01-std'] = np.std(cA)
    result['HpHp-L0.01-magnitude'] = np.linalg.norm(cA)

    result['label'] = group['label'].iloc[0]
    return result

if __name__ == '__main__':
    script_dir = os.path.dirname(os.path.abspath(__file__))
    input_file = os.path.join(script_dir, "DATASETS", "raw_flows.csv")
    output_file = os.path.join(script_dir, "DATASETS", "TonIoT_nbaiot_selected_features.csv")

    if not os.path.exists(input_file):
        print(f"No se encontró el archivo de entrada: {input_file}")
        exit()

    print("Leyendo archivo...")
    df = pd.read_csv(input_file)

    print("Extrayendo características por flujo...")
    results = []

    for flow_id, group in df.groupby('flow_id'):
        try:
            result = extract_nbaiot_selected_features(flow_id, group)
            results.append(result)
        except Exception as e:
            print(f"Error en flujo {flow_id}: {e}")
            continue

    features_df = pd.DataFrame(results)
    features_df.to_csv(output_file, index=False)

    print(f"Características tipo N-BaIoT guardadas en: {output_file}")
