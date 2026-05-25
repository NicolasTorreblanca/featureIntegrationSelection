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
# Derivadores con fallback (cubren campos que NFStream no siempre populariza)
# ----------------------------------------------------------------------------
# NFStream 6.6.0 retorna None para flow.connection_state y flow.requested_service
# en todos los flujos extraídos de los PCAPs de ToN-IoT. Estos derivadores
# intentan primero el valor upstream y caen a una síntesis razonable cuando
# está vacío, manteniendo el comportamiento del NFStream/Part2 original
# (que sintetizaba conn_state desde packet counts) pero aplicándolo aquí en
# Part1 para que el resto del pipeline reciba valores correctos desde el
# primer _base.csv.
#
# Limitación conocida: Zeek's "REJ" requiere ver TCP RST en respuesta a SYN,
# lo cual no puede inferirse solo desde contadores de paquetes. La síntesis
# solo emite {S0, SF, OTH} — conn_state_REJ permanecerá vacío en el testbed.

def derive_conn_state(flow):
    """flow.connection_state primero, fallback a síntesis desde packet counts."""
    upstream = getattr(flow, "connection_state", None)
    if upstream is not None and upstream != "":
        return normalize_conn_state(upstream)

    src_pkts = getattr(flow, "src2dst_packets", 0) or 0
    dst_pkts = getattr(flow, "dst2src_packets", 0) or 0
    if src_pkts > 0 and dst_pkts == 0:
        return "S0"
    elif src_pkts > 0 and dst_pkts > 0:
        return "SF"
    else:
        return "OTH"


def derive_service(flow):
    """flow.requested_service primero, fallback a flow.application_name (nDPI)
    mapeado al vocabulario Zeek {dns, http, -, Other, None}."""
    upstream = getattr(flow, "requested_service", None)
    if upstream is not None and upstream != "":
        return normalize_service(upstream)

    app = getattr(flow, "application_name", None)
    if app is None or app == "":
        return "None"

    app_lower = str(app).lower()
    if "dns" in app_lower:
        return "dns"
    if "http" in app_lower:
        return "http"
    if app_lower in ("unknown", "unrated"):
        return "-"
    # nDPI puede devolver muchos protocolos (TLS, SSH, FTP, etc.) que no son
    # parte del vocabulario Zeek que SHAP analizó. No emitimos WARN — son
    # valores legítimos, simplemente colapsan en "Other".
    return "Other"


# ----------------------------------------------------------------------------
# Procesamiento de un PCAP individual
# ----------------------------------------------------------------------------
def _to_ascii_safe_path(p):
    """Convierte un path a su forma 8.3 (corta, solo ASCII) en Windows
    cuando contiene caracteres no-ASCII. Workaround para el bug de
    nfstream multiprocessing que mangla 'Nicolás' a 'Nicols' al pasar el
    path a los workers. No-op en otras plataformas o si el path ya es ASCII."""
    if os.name != 'nt':
        return p
    try:
        p.encode('ascii')
        return p  # already ASCII, no conversion needed
    except UnicodeEncodeError:
        pass
    import ctypes
    buf = ctypes.create_unicode_buffer(260)
    rv = ctypes.windll.kernel32.GetShortPathNameW(p, buf, 260)
    return buf.value if rv else p


def process_pcap(file_path, label):
    """Lee un archivo PCAP con NFStreamer y devuelve una lista de filas (dicts)
    con nombres y valores en convención Zeek."""
    pcap_path = _to_ascii_safe_path(str(file_path))
    print(f"Procesando {pcap_path} como {label}...")

    stream = nfstream.NFStreamer(
        source=pcap_path,
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
                'ltime':    getattr(flow, "bidirectional_last_seen_ms", 0.0),
                'dur':      (getattr(flow, "bidirectional_duration_ms", 0) or 0) / 1000.0,

                # ToN-IoT / Zeek features (convertidas)
                'dns_query':    getattr(flow, "dns_query", "") or "",
                'dns_rejected': dns_bool_to_zeek_str(getattr(flow, "dns_rejected", None)),
                'dns_RD':       dns_bool_to_zeek_str(getattr(flow, "dns_rd", None)),
                'conn_state':   derive_conn_state(flow),
                'service':      derive_service(flow),
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
