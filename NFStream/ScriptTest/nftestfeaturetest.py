import nfstream
import pandas as pd
import os

def process_pcap(file_path):
    """ Procesa un archivo PCAP con NFStreamer y devuelve solo ciertas características """
    print(f"Procesando {file_path}...")

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
            conn_state = 0  # No hubo respuesta
        elif flow.src2dst_packets > 0 and flow.dst2src_packets > 0:
            conn_state = 1  # Conexión establecida
        else:
            conn_state = 2  # Otro tipo de flujo

        flows.append({
            "dst-port": flow.dst_port,
            "conn-state": conn_state,
            "src-pkts": flow.src2dst_packets,
            "proto": flow.protocol,
            "src-ip-bytes": flow.src2dst_bytes,
            "dst-ip-bytes": flow.dst2src_bytes
        })

    return flows

if __name__ == '__main__':
    script_dir = os.path.dirname(os.path.abspath(__file__))
    pcap_folder = os.path.join(script_dir, "PCAP")
    datasets_folder = os.path.join(script_dir, "DATASETS")

    os.makedirs(pcap_folder, exist_ok=True)
    os.makedirs(datasets_folder, exist_ok=True)

    all_flows = []

    for pcap_file in os.listdir(pcap_folder):
        if pcap_file.endswith(".pcap"):
            file_path = os.path.join(pcap_folder, pcap_file)
            all_flows.extend(process_pcap(file_path))

    df = pd.DataFrame(all_flows)
    output_file = os.path.join(datasets_folder, "MITMTonIoT.csv")
    df.to_csv(output_file, index=False)

    print(f"Dataset guardado en: {output_file}")
