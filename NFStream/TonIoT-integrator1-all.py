import nfstream
import pandas as pd
import os
import time

# Mapeo etiquetas ToN-IoT a etiquetas limpias
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
        try:
            flows.append({
                # Identificadores
                'src-ip': flow.src_ip or "0.0.0.0",
                'dst-ip': flow.dst_ip or "0.0.0.0",
                'src-port': flow.src_port or 0,
                'dst-port': flow.dst_port or 0,
                'protocol': flow.protocol or 0,
                'stime': getattr(flow, "bidirectional_first_seen_ms", 0.0),

                # ToN-IoT features
                'dns-query': getattr(flow, "dns_query", ""),
                'dns-rejected': int(getattr(flow, "dns_rejected", False)),
                'dns-RD': int(getattr(flow, "dns_rd", False)),
                'state': getattr(flow, "connection_state", "OTH"),
                'service': getattr(flow, "requested_service", "-"),
                'http-status-code': getattr(flow, "http_response_status_code", -1),

                # Raw metrics for future processing
                'src-ip-bytes': flow.src2dst_bytes,
                'dst-ip-bytes': flow.dst2src_bytes,
                'src2dst_packets': flow.src2dst_packets,
                'dst2src_packets': flow.dst2src_packets,

                # Etiqueta
                'label': label
            })
        except Exception as e:
            print(f"Error en flujo: {e}")

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
                    df = pd.DataFrame(flows)
                    output_name = os.path.splitext(pcap_file)[0] + "_base.csv"
                    output_path = os.path.join(output_folder, output_name)
                    df.to_csv(output_path, index=False)
                    print(f"Guardado en: {output_path}")

    print(f"\n{total_pcap} archivos PCAP procesados y flujos base generados.")
