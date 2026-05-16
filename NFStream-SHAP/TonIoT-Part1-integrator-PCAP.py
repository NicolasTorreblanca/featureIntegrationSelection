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
