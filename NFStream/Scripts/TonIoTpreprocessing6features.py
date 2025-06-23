import nfstream
import pandas as pd
import os

def process_pcap(file_path, label):
    """Procesa un archivo PCAP con NFStreamer y añade una etiqueta."""
    print(f"Procesando {file_path} como {label}...")

    stream = nfstream.NFStreamer(
        source=file_path,
        statistical_analysis=True,
        splt_analysis=True,
        n_dissections=20
    )

    flows = []
    for flow in stream:
        # Lógica tipo Zeek para conn-state
        if flow.src2dst_packets > 0 and flow.dst2src_packets == 0:
            conn_state = "S0"
        elif flow.src2dst_packets > 0 and flow.dst2src_packets > 0:
            conn_state = "S1"
        else:
            conn_state = "OTH"

        flows.append({
            "dst-port": flow.dst_port,
            "conn-state": conn_state,
            "src-pkts": flow.src2dst_packets,
            "proto": flow.protocol,
            "src-ip-bytes": flow.src2dst_bytes,
            "dst-ip-bytes": flow.dst2src_bytes,
            "label": label
        })

    return flows

if __name__ == '__main__':
    script_dir = os.path.dirname(os.path.abspath(__file__))
    pcap_folder = os.path.join(script_dir, "PCAP")
    datasets_folder = os.path.join(script_dir, "DATASETS")

    os.makedirs(datasets_folder, exist_ok=True)

    all_flows = []

    # Recorrer todo el árbol de carpetas
    for root, dirs, files in os.walk(pcap_folder):
        for pcap_file in files:
            if pcap_file.endswith(".pcap"):
                file_path = os.path.join(root, pcap_file)
                
                # Extraer la carpeta que representa la clase (última carpeta antes del archivo)
                label = os.path.basename(os.path.dirname(file_path))
                
                # Procesar el archivo con etiqueta
                all_flows.extend(process_pcap(file_path, label))

    # Convertir a DataFrame y guardar
    df = pd.DataFrame(all_flows)
    output_file = os.path.join(datasets_folder, "TonIoT_labeled.csv")
    df.to_csv(output_file, index=False)

    print(f"Dataset completo guardado en: {output_file}")
