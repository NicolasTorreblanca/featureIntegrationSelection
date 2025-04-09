import nfstream
import pandas as pd
import os

# Mapeo de clases a números
label_map = {
    "Normal": 0,
    "MITM": 1,
    "NormalDdos": 2,
    "NormalDos": 3,
    "NormalScanning": 4,
    "NormalXss": 5,
    "NormalRunsomware": 6,
    "InjectionNormal": 7,
    "PasswordNormal": 8,
    "NormalBackdoor": 9
}

def process_pcap(file_path, label_id):
    """Procesa un archivo PCAP con NFStreamer y añade una etiqueta numérica."""
    print(f"Procesando {file_path} como clase {label_id}...")

    stream = nfstream.NFStreamer(
        source=file_path,
        statistical_analysis=True,
        splt_analysis=True,
        n_dissections=20
    )

    flows = []
    for flow in stream:
        if flow.src2dst_packets > 0 and flow.dst2src_packets == 0:
            conn_state = 0
        elif flow.src2dst_packets > 0 and flow.dst2src_packets > 0:
            conn_state = 1
        else:
            conn_state = 2

        flows.append({
            "dst-port": flow.dst_port,
            "conn-state": conn_state,
            "src-pkts": flow.src2dst_packets,
            "proto": flow.protocol,
            "src-ip-bytes": flow.src2dst_bytes,
            "dst-ip-bytes": flow.dst2src_bytes,
            "class": label_id
        })

    return flows

if __name__ == '__main__':
    script_dir = os.path.dirname(os.path.abspath(__file__))
    pcap_folder = os.path.join(script_dir, "PCAP")
    datasets_folder = os.path.join(script_dir, "DATASETS")

    os.makedirs(datasets_folder, exist_ok=True)

    all_flows = []

    for root, dirs, files in os.walk(pcap_folder):
        for pcap_file in files:
            if pcap_file.endswith(".pcap"):
                file_path = os.path.join(root, pcap_file)

                # Extraer nombre de la carpeta de clase
                folder_name = os.path.basename(os.path.dirname(file_path))

                # Obtener ID de clase (si está definido en el diccionario)
                if folder_name in label_map:
                    label_id = label_map[folder_name]
                    all_flows.extend(process_pcap(file_path, label_id))
                else:
                    print(f"[ADVERTENCIA] Carpeta sin etiqueta numérica: {folder_name}")

    df = pd.DataFrame(all_flows)
    output_file = os.path.join(datasets_folder, "TonIoT_6fet.csv")
    df.to_csv(output_file, index=False)

    print(f"Dataset etiquetado con números guardado en: {output_file}")
