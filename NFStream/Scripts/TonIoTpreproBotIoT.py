# generate_flows_from_pcap.py (versión optimizada para bajo consumo de memoria)

import nfstream
import pandas as pd
import os
import numpy as np
from collections import defaultdict
import time

# Mapeo etiquetas ToN-IoT a nombres limpios
LABEL_MAPPING = {
    'Normal': 'normal',
    'NormalDdos': 'ddos',
    'NormalDos': 'dos',
    'NormalBackdoor': 'backdoor',
    'NormalRunsomware': 'ransomware',
    'NormalScanning': 'scanning',
    'NormalXss': 'xss',
    'PasswordNormal': 'password',
    'InjectionNormal': 'injection',
    'MITM': 'mitm'
}

# Contadores por IP
src_ip_counter = defaultdict(int)
dst_ip_counter = defaultdict(int)

def process_pcap(file_path, label):
    print(f"Procesando {file_path} como {label}...")

    stream = nfstream.NFStreamer(
        source=file_path,
        statistical_analysis=True,
        splt_analysis=True,
        n_dissections=20
    )

    flows = []

    for flow in stream:
        src_ip = flow.src_ip or "0.0.0.0"
        dst_ip = flow.dst_ip or "0.0.0.0"
        protocol = flow.protocol or 0

        # Tiempo de inicio (en milisegundos desde epoch)
        start_time = getattr(flow, "bidirectional_first_seen_ms", 0.0)

        # Métricas para estadísticas
        bytes_list = [flow.src2dst_bytes, flow.dst2src_bytes]
        packets_list = [flow.src2dst_packets, flow.dst2src_packets]
        all_values = bytes_list + packets_list

        # Contadores IP
        src_ip_counter[src_ip] += 1
        dst_ip_counter[dst_ip] += 1

        # Estado estilo Zeek
        if flow.src2dst_packets > 0 and flow.dst2src_packets == 0:
            conn_state = "S0"
        elif flow.src2dst_packets > 0 and flow.dst2src_packets > 0:
            conn_state = "SF"
        else:
            conn_state = "OTH"

        state_map = {"S0": 1, "SF": 2, "OTH": 0}
        state_number = state_map.get(conn_state, 0)

        flows.append({
            'N-IN-Conn-P-SrcIP': src_ip_counter[src_ip],
            'N-IN-Conn-P-DstIP': dst_ip_counter[dst_ip],
            'state-number': state_number,
            'proto-number': protocol,
            'stime': start_time,
            'max': np.max(all_values),
            'mean': np.mean(all_values),
            'min': np.min(all_values),
            'stddev': np.std(all_values),
            'label': label
        })

    return flows

if __name__ == '__main__':
    script_dir = os.path.dirname(os.path.abspath(__file__))
    pcap_folder = os.path.join(script_dir, "PCAP")
    output_folder = os.path.join(script_dir, "DATASETS")
    os.makedirs(output_folder, exist_ok=True)

    total_pcap = 0

    for root, dirs, files in os.walk(pcap_folder):
        for pcap_file in files:
            if pcap_file.endswith((".pcap", ".pcapng")):
                file_path = os.path.join(root, pcap_file)
                raw_label = os.path.basename(os.path.dirname(file_path))
                label = LABEL_MAPPING.get(raw_label, None)

                if label is None:
                    print(f"Omitido: carpeta '{raw_label}' no está mapeada.")
                    continue

                print(f"\nLeyendo archivo: {file_path}")
                start_time = time.time()
                flows = process_pcap(file_path, label)
                elapsed = time.time() - start_time
                print(f"Archivo procesado en {elapsed:.2f} segundos.")

                if flows:
                    total_pcap += 1
                    # Crear nombre único para el archivo de salida
                    output_name = os.path.splitext(pcap_file)[0] + "_flows.csv"
                    output_path = os.path.join(output_folder, output_name)
                    pd.DataFrame(flows).to_csv(output_path, index=False)
                    print(f"Guardado en: {output_path}")

    print(f"\n{total_pcap} archivos PCAP procesados y convertidos individualmente a CSV.")
