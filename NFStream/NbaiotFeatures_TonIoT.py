import nfstream
import pandas as pd
import os
import numpy as np
import pywt
from scipy.stats import pearsonr
from sklearn.metrics import mutual_info_score

# Solo las características top de los artículos
TOP_FEATURES = {
    'HH-L0.01-weight', 
    'MI-dir-L5-weight', 
    'HH-L3-weight',
    'HH-L0.01-magnitude',
    'MI-dir-L5-mean',
    'MI-dir-L5-variance',
    'HpHp-L0.1-pcc',
    'HpHp-L5-magnitude',
    'HpHp-L3-weight',
    'label'  # We'll keep this in the set but handle it differently
}

def extract_top_features(flow):
    features = {}
    if not hasattr(flow, 'splt_vectors') or len(flow.splt_vectors[0]) < 10:
        return None
    
    packet_sizes = flow.splt_vectors[0]
    packet_times = flow.splt_vectors[1]
    
    # 1. HH-L0.01 features
    if 'HH-L0.01-weight' in TOP_FEATURES or 'HH-L0.01-magnitude' in TOP_FEATURES:
        coeffs_L001 = pywt.wavedec(packet_sizes, 'db1', level=1)
        if coeffs_L001:
            if 'HH-L0.01-weight' in TOP_FEATURES:
                features['HH-L0.01-weight'] = np.sum(np.square(coeffs_L001[0]))
            if 'HH-L0.01-magnitude' in TOP_FEATURES:
                features['HH-L0.01-magnitude'] = np.linalg.norm(coeffs_L001[0])
    
    # 2. MI-dir-L5 features
    if any(f in TOP_FEATURES for f in ['MI-dir-L5-weight', 'MI-dir-L5-mean', 'MI-dir-L5-variance']):
        level = min(5, pywt.dwt_max_level(len(packet_sizes), 'db1'))
        coeffs_L5 = pywt.wavedec(packet_sizes, 'db1', level=level)
        time_coeffs_L5 = pywt.wavedec(packet_times, 'db1', level=level)
        if coeffs_L5 and time_coeffs_L5:
            if 'MI-dir-L5-weight' in TOP_FEATURES:
                features['MI-dir-L5-weight'] = mutual_info_score(coeffs_L5[0], time_coeffs_L5[0])
            if 'MI-dir-L5-mean' in TOP_FEATURES:
                features['MI-dir-L5-mean'] = np.mean(coeffs_L5[0])
            if 'MI-dir-L5-variance' in TOP_FEATURES:
                features['MI-dir-L5-variance'] = np.var(coeffs_L5[0])
    
    # 3. HpHp features
    if 'HpHp-L0.1-pcc' in TOP_FEATURES:
        coeffs_L01 = pywt.wavedec(packet_sizes, 'db1', level=1)
        if len(coeffs_L01[0]) > 2:
            features['HpHp-L0.1-pcc'], _ = pearsonr(coeffs_L01[0][:-1], coeffs_L01[0][1:])
    
    if 'HpHp-L5-magnitude' in TOP_FEATURES:
        level = min(5, pywt.dwt_max_level(len(packet_sizes), 'db1'))
        coeffs_L5 = pywt.wavedec(packet_sizes, 'db1', level=level)
        if coeffs_L5:
            features['HpHp-L5-magnitude'] = np.linalg.norm(coeffs_L5[0])
    
    if 'HpHp-L3-weight' in TOP_FEATURES:
        level = min(3, pywt.dwt_max_level(len(packet_sizes), 'db1'))
        coeffs_L3 = pywt.wavedec(packet_sizes, 'db1', level=level)
        if coeffs_L3:
            features['HpHp-L3-weight'] = np.sum(np.abs(coeffs_L3[0]))
    
    return features  # We'll add the label in the process_pcap function

def process_pcap(file_path, label):
    stream = nfstream.NFStreamer(
        source=file_path,
        splt_analysis=True,
        statistical_analysis=False,
        n_dissections=0,
        performance_report=0  # Disable multiprocessing to avoid issues
    )

    flows = []
    for flow in stream:
        features = extract_top_features(flow)
        if features:
            features['label'] = label  # Add the label here instead of modifying the flow object
            flows.append(features)

    return flows

if __name__ == '__main__':
    script_dir = os.path.dirname(os.path.abspath(__file__))
    pcap_folder = os.path.join(script_dir, "PCAP")
    datasets_folder = os.path.join(script_dir, "DATASETS")
    os.makedirs(datasets_folder, exist_ok=True)

    all_flows = []

    # Recorrer todo el árbol de carpetas (same as your original code)
    for root, dirs, files in os.walk(pcap_folder):
        for pcap_file in files:
            if pcap_file.endswith(".pcap"):
                file_path = os.path.join(root, pcap_file)
                
                # Extraer la carpeta que representa la clase (última carpeta antes del archivo)
                label = os.path.basename(os.path.dirname(file_path))
                
                print(f"Procesando {file_path} como {label}...")
                flows = process_pcap(file_path, label)
                all_flows.extend(flows)

    # Convertir a DataFrame y guardar
    df = pd.DataFrame(all_flows)
    
    # Ensure we only keep the features we want
    final_features = [f for f in TOP_FEATURES if f in df.columns]
    df = df[final_features]
    
    output_file = os.path.join(datasets_folder, "N-BaIoT_TopFeatures_labeled.csv")
    df.to_csv(output_file, index=False)

    print(f"Dataset completo guardado en: {output_file}")