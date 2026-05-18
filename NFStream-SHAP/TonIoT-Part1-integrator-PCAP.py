# TonIoT-Part1-integrator-PCAP.py  (NFStream-SHAP variant)
#
# Convierte PCAPs en CSVs con nombres y valores estilo Zeek
# (proto como string, dns_rejected como F/T, src_pkts/dst_pkts en lugar de
# src2dst_packets/dst2src_packets, columnas con guión bajo).
#
# Esta normalización es lo que permite que el OneHotEncoder de Part3 produzca
# columnas con los nombres exactos que SHAP seleccionó en su top-10 global
# (proto_tcp, conn_state_REJ, service_dns, dns_rejected_F, etc.).
#
# Entrada : .pcap/.pcapng bajo PCAP/Normal/ y PCAP/Attacks/<clase>/
# Salida  : un _base.csv por archivo PCAP en NFStream-SHAP/DATASETS/

import os
import time
from pathlib import Path

import nfstream
import pandas as pd

# Mapeo de carpetas a etiquetas canónicas. La clave es el nombre de la carpeta
# hoja que contiene los .pcap; el valor es la etiqueta que se usa en todos los
# pipelines downstream (Part4 TARGET_SIZES, Part4b clase_a_numero).
#
# Nota: la carpeta 'RunsomWare' tiene la grafía original; la etiqueta canónica
# en todo el sistema es 'ransomware'. Si la carpeta se renombra alguna vez,
# actualizar la clave aquí y solo aquí.
LABEL_MAPPING = {
    # Subcarpetas de PCAP/Attacks/
    'BackDoor':   'backdoor',
    'DDos':       'ddos',
    'DoS':        'dos',
    'Injection':  'injection',
    'MITM':       'mitm',
    'Password':   'password',
    'RunsomWare': 'ransomware',
    'Scanning':   'scanning',
    'XSS':        'xss',
    # Hermana de Attacks/
    'Normal':     'normal',
}

# ----------------------------------------------------------------------------
# Normalizadores de vocabulario (de NFStream → Zeek)
# ----------------------------------------------------------------------------
# El CSV que entrenó al SHAP analyzer (Ton-IoT-Complete.csv) usa:
#   proto         ∈ {tcp, udp, Other, None}
#   conn_state    ∈ {S0, SF, REJ, OTH, Other, None}
#   service       ∈ {dns, http, '-', Other, None}
#   dns_rejected  ∈ {F, T, '-', Other, None}
#
# Estas funciones convierten los valores que entrega NFStream a ese
# vocabulario. Cualquier valor inesperado cae en "Other" o "None" (faltante)
# y el caller emite un WARN una vez para detectar drift.

_proto_warn_seen = set()
_conn_state_warn_seen = set()
_service_warn_seen = set()

def proto_to_str(proto_int):
    """IANA protocol number → Zeek string."""
    if proto_int is None:
        return "None"
    mapping = {6: "tcp", 17: "udp"}
    if proto_int not in mapping and proto_int not in _proto_warn_seen:
        print(f"WARN: unexpected proto value {proto_int!r}, mapping to 'Other'")
        _proto_warn_seen.add(proto_int)
    return mapping.get(proto_int, "Other")


def dns_bool_to_zeek_str(value):
    """Boolean/None → Zeek F/T/-."""
    if value is None:
        return "-"
    return "T" if bool(value) else "F"


def normalize_conn_state(value):
    """NFStream connection_state → Zeek conn_state vocabulary."""
    if value is None or value == "":
        return "None"
    allowed = {"S0", "SF", "REJ", "OTH"}
    if value in allowed:
        return value
    if value not in _conn_state_warn_seen:
        print(f"WARN: unexpected conn_state value {value!r}, mapping to 'Other'")
        _conn_state_warn_seen.add(value)
    return "Other"


def normalize_service(value):
    """NFStream requested_service → Zeek service vocabulary."""
    if value is None or value == "":
        return "None"
    allowed = {"-", "dns", "http"}
    if value in allowed:
        return value
    if value not in _service_warn_seen:
        print(f"WARN: unexpected service value {value!r}, mapping to 'Other'")
        _service_warn_seen.add(value)
    return "Other"


# ----------------------------------------------------------------------------
# Procesamiento de un PCAP individual
# ----------------------------------------------------------------------------
def process_pcap(file_path, label):
    """Lee un archivo PCAP con NFStreamer y devuelve una lista de filas (dicts)
    con nombres y valores en convención Zeek."""
    print(f"Procesando {file_path} como {label}...")

    stream = nfstream.NFStreamer(
        source=file_path,
        statistical_analysis=True,
        splt_analysis=True,
        n_dissections=20,
    )

    flows = []
    for flow in stream:
        try:
            flows.append({
                # Identificadores
                'src_ip':   flow.src_ip or "0.0.0.0",
                'dst_ip':   flow.dst_ip or "0.0.0.0",
                'src_port': flow.src_port or 0,
                'dst_port': flow.dst_port or 0,
                'proto':    proto_to_str(flow.protocol),
                'stime':    getattr(flow, "bidirectional_first_seen_ms", 0.0),

                # ToN-IoT / Zeek features (convertidas)
                'dns_query':    getattr(flow, "dns_query", "") or "",
                'dns_rejected': dns_bool_to_zeek_str(getattr(flow, "dns_rejected", None)),
                'dns_RD':       dns_bool_to_zeek_str(getattr(flow, "dns_rd", None)),
                'conn_state':   normalize_conn_state(getattr(flow, "connection_state", None)),
                'service':      normalize_service(getattr(flow, "requested_service", None)),
                'http_status_code': getattr(flow, "http_response_status_code", -1),

                # Métricas crudas (renombradas a estilo Zeek)
                'src_ip_bytes': flow.src2dst_bytes,
                'dst_ip_bytes': flow.dst2src_bytes,
                'src_pkts':     flow.src2dst_packets,
                'dst_pkts':     flow.dst2src_packets,

                # Etiqueta
                'label': label,
            })
        except Exception as e:
            print(f"Error en flujo: {e}")

    return flows


# ----------------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------------
if __name__ == '__main__':
    script_dir    = Path(__file__).resolve().parent
    pcap_folder   = script_dir.parent.parent / "PCAP"      # CololocovsLaChile01032026/PCAP/
    output_folder = script_dir / "DATASETS"
    output_folder.mkdir(parents=True, exist_ok=True)

    if not pcap_folder.exists():
        raise FileNotFoundError(
            f"PCAP folder not found at {pcap_folder}. "
            "Expected layout: <project>/PCAP/Normal/ and <project>/PCAP/Attacks/<clase>/"
        )

    total_pcap = 0
    for root, _, files in os.walk(pcap_folder):
        for pcap_file in files:
            if not pcap_file.endswith((".pcap", ".pcapng")):
                continue

            file_path = os.path.join(root, pcap_file)
            raw_label = os.path.basename(os.path.dirname(file_path))
            label = LABEL_MAPPING.get(raw_label)
            if label is None:
                print(f"Omitido: carpeta '{raw_label}' no está mapeada.")
                continue

            print(f"\nLeyendo archivo: {file_path}")
            start = time.time()
            flows = process_pcap(file_path, label)
            print(f"Archivo procesado en {time.time() - start:.2f} segundos.")

            if flows:
                total_pcap += 1
                df = pd.DataFrame(flows)
                out_name = os.path.splitext(pcap_file)[0] + "_base.csv"
                out_path = output_folder / out_name
                df.to_csv(out_path, index=False)
                print(f"Guardado en: {out_path}")

    print(f"\n{total_pcap} archivos PCAP procesados y flujos base generados.")
