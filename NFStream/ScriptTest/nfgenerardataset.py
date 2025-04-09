import nfstream
import pandas as pd
import os

def process_pcap(file_path):
    """ Procesa un archivo PCAP con NFStreamer y devuelve una lista de diccionarios """
    print(f"Procesando {file_path}...")

    # NFStreamer procesa los flujos en paralelo internamente
    stream = nfstream.NFStreamer(
        source=file_path,
        statistical_analysis=True,
        splt_analysis=True,
        n_dissections=20
    )

    # Convertir a lista de diccionarios con atributos de cada flujo
    flows = []
    for flow in stream:
        flows.append({
            "src_ip": flow.src_ip,
            "dst_ip": flow.dst_ip,
            "src_port": flow.src_port,
            "dst_port": flow.dst_port,
            "protocol": flow.protocol,
            "bidirectional_first_seen_ms": flow.bidirectional_first_seen_ms,
            "bidirectional_last_seen_ms": flow.bidirectional_last_seen_ms,
            "bidirectional_packets": flow.bidirectional_packets,
            "bidirectional_bytes": flow.bidirectional_bytes,
            "src2dst_packets": flow.src2dst_packets,
            "src2dst_bytes": flow.src2dst_bytes,
            "dst2src_packets": flow.dst2src_packets,
            "dst2src_bytes": flow.dst2src_bytes
        })

    return flows

if __name__ == '__main__':
    # Obtener la ruta del script actual
    script_dir = os.path.dirname(os.path.abspath(__file__))  

    # Construir la ruta de la carpeta PCAP
    pcap_folder = os.path.join(script_dir, "PCAP")

    

    # Lista para almacenar todos los flujos
    all_flows = []

    # Iterar sobre cada archivo PCAP
    for pcap_file in os.listdir(pcap_folder):
        if pcap_file.endswith(".pcap"):  # Verificar que es un archivo PCAP
            file_path = os.path.join(pcap_folder, pcap_file)
            all_flows.extend(process_pcap(file_path))

    # Convertir a DataFrame
    df = pd.DataFrame(all_flows)

    # Guardar en un archivo CSV
    
    datasets_folder = os.path.join(script_dir, "DATASETS")
    
    output_file = os.path.join(datasets_folder, "MITMTonIoT.csv")
    df.to_csv(output_file, index=False)

    print(f"Dataset guardado en: {output_file}")
