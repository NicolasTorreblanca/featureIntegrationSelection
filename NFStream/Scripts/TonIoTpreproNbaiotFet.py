# generate_flows_from_pcap.py

import nfstream
import pandas as pd
import os

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
        src_port = flow.src_port or 0
        dst_port = flow.dst_port or 0
        protocol = flow.protocol or "UNK"

        flows.append({
            "flow_id": f"{src_ip}-{dst_ip}-{src_port}-{dst_port}-{protocol}",
            "src-ip-bytes": flow.src2dst_bytes,
            "dst-ip-bytes": flow.dst2src_bytes,
            "label": label
        })

    return flows

if __name__ == '__main__':
    script_dir = os.path.dirname(os.path.abspath(__file__))
    pcap_folder = os.path.join(script_dir, "PCAP")
    output_folder = os.path.join(script_dir, "DATASETS")
    os.makedirs(output_folder, exist_ok=True)

    all_flows = []
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

                flows = process_pcap(file_path, label)
                if flows:
                    total_pcap += 1
                    all_flows.extend(flows)

    if not all_flows:
        print("No se extrajeron flujos válidos.")
        exit()

    df = pd.DataFrame(all_flows)
    output_file = os.path.join(output_folder, "raw_flows.csv")
    df.to_csv(output_file, index=False)
    print(f"{total_pcap} archivos PCAP procesados. Flujos guardados en: {output_file}")
