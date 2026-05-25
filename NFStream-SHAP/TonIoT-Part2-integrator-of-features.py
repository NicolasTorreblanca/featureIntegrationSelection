# TonIoT-Part2-integrator-of-features.py  (NFStream-SHAP variant — Kitsune edition)
#
# Computa el feature space integrado a partir de _base.csv (Part1).
# El output _combined.csv contiene las 30 columnas que la union de los SHAP
# top-10 de ToN-IoT, BoT-IoT y N-BaIoT requiere (despues de one-hot en Part3).
#
# Cambios respecto a la version anterior:
#   * Agregadas features estilo Kitsune (Mirsky et al. 2018) con estadisticas
#     damped incrementales: H_L{0.01,0.1,1,3}_weight, H_L0.01_mean,
#     MI_dir_L{0.01,0.1,1}_weight, MI_dir_L0.1_mean, HH_jit_L1_mean.
#   * Agregadas features BoT-IoT: ltime, dur (vienen de Part1), TnBPDstIP
#     (running counter), sum (agregacion sobre el signal vector).
#   * Procesa los archivos en orden temporal global (ordenados por stime del
#     primer flow) para que el estado damped de Kitsune sea correcto.
#   * SELECTED_FEATURES cubre la union de los 3 SHAP top-10s pre-one-hot.
#
# Entrada : DATASETS/*_base.csv     (de Part1)
# Salida  : Ton-IoT-MultiFet/*_combined.csv

import math
import os
from collections import defaultdict
from pathlib import Path

import numpy as np
import pandas as pd


# ============================================================================
# SELECTED_FEATURES — columnas que Part2 emite a _combined.csv
# ============================================================================
SELECTED_FEATURES = [
    # Categoricals (one-hot'd en Part3)
    'proto', 'conn_state', 'service', 'dns_rejected',
    # ToN-IoT raw numerics
    'src_ip_bytes', 'dst_ip_bytes', 'src_pkts', 'dst_pkts', 'http_status_code',
    # NetFlow context
    'dst_port', 'stime',
    # BoT-IoT specific
    'ltime', 'dur', 'TnBPDstIP', 'sum',
    # Connection counters
    'N_IN_Conn_P_DstIP', 'N_IN_Conn_P_SrcIP',
    # Statistical aggregations sobre el signal vector
    'max', 'mean', 'min', 'stddev',
    # Encodings numericos de categoricals (auxiliares)
    'state_number', 'proto_number',
    # Kitsune N-BaIoT features
    'H_L0.01_weight', 'H_L0.1_weight', 'H_L1_weight', 'H_L3_weight', 'H_L0.01_mean',
    'MI_dir_L0.01_weight', 'MI_dir_L0.1_weight', 'MI_dir_L1_weight', 'MI_dir_L0.1_mean',
    'HH_jit_L1_mean',
    # Target
    'label',
]

_PROTO_TO_NUM = {"tcp": 6, "udp": 17, "Other": 0, "None": -1}
_STATE_TO_NUM = {"S0": 1, "SF": 2, "REJ": 3, "OTH": 0, "Other": -1, "None": -2}


# ============================================================================
# Kitsune-style damped incremental statistics
# (Mirsky et al. 2018, "Kitsune: An Ensemble of Autoencoders for Online
#  Network Intrusion Detection".)
# ============================================================================
class _DampedStat:
    """Single damped statistic accumulator para una (stream, lambda)."""
    __slots__ = ('lam', 'last_t', 'count', 'lin_sum', 'sq_sum')

    def __init__(self, lam):
        self.lam = lam
        self.last_t = None
        self.count = 0.0
        self.lin_sum = 0.0
        self.sq_sum = 0.0

    def update(self, t_ms, value):
        if self.last_t is not None and t_ms > self.last_t:
            dt = (t_ms - self.last_t) / 1000.0   # ms -> seconds
            decay = math.exp(-self.lam * dt)
            self.count *= decay
            self.lin_sum *= decay
            self.sq_sum *= decay
        self.count += 1.0
        self.lin_sum += value
        self.sq_sum += value * value
        self.last_t = t_ms

    def weight(self):
        return self.count

    def mean(self):
        return self.lin_sum / self.count if self.count > 0 else 0.0

    def std(self):
        if self.count <= 0:
            return 0.0
        m = self.mean()
        var = max(0.0, self.sq_sum / self.count - m * m)
        return math.sqrt(var)


class KitsuneExtractor:
    """Mantiene el estado damped por stream-id y por lambda para las 10
    features N-BaIoT que SHAP selecciono. Process flows en orden temporal."""

    LAMBDAS_H      = (0.01, 0.1, 1.0, 3.0)   # H_Lx_weight para 0.01/0.1/1/3, H_Lx_mean para 0.01
    LAMBDAS_MI_DIR = (0.01, 0.1, 1.0)        # MI_dir_Lx_weight para 0.01/0.1/1, mean para 0.1
    LAMBDAS_HH_JIT = (1.0,)                  # solo HH_jit_L1_mean

    def __init__(self):
        # H family: stats per source IP (signal = bytes totales del flow)
        self._H = {}            # src_ip -> {lam: _DampedStat}
        # MI_dir family: stats per (src_ip, dst_ip) direccional (signal = src_bytes)
        self._MIdir = {}        # (src_ip, dst_ip) -> {lam: _DampedStat}
        # HH_jit family: jitter (inter-arrival time) per host-host pair (sin direccion)
        self._HHjit = {}        # frozenset({src_ip, dst_ip}) -> {lam: _DampedStat}
        self._HHjit_lastt = {}  # frozenset({src_ip, dst_ip}) -> t_last_ms

    def update_and_extract(self, t_ms, src_ip, dst_ip, src_bytes, dst_bytes):
        flow_bytes = float(src_bytes or 0) + float(dst_bytes or 0)
        dir_bytes  = float(src_bytes or 0)
        hh_key     = frozenset((src_ip, dst_ip))

        # --- H (per source IP)
        H_for_src = self._H.setdefault(
            src_ip, {lam: _DampedStat(lam) for lam in self.LAMBDAS_H}
        )
        for lam in self.LAMBDAS_H:
            H_for_src[lam].update(t_ms, flow_bytes)

        # --- MI_dir (per (src,dst) ordered tuple, directional bytes)
        mi_key = (src_ip, dst_ip)
        MIdir_for_pair = self._MIdir.setdefault(
            mi_key, {lam: _DampedStat(lam) for lam in self.LAMBDAS_MI_DIR}
        )
        for lam in self.LAMBDAS_MI_DIR:
            MIdir_for_pair[lam].update(t_ms, dir_bytes)

        # --- HH_jit (inter-arrival jitter, per unordered host-host pair)
        last_t = self._HHjit_lastt.get(hh_key)
        jitter = float(t_ms - last_t) if last_t is not None else 0.0
        self._HHjit_lastt[hh_key] = t_ms
        HHjit_for_pair = self._HHjit.setdefault(
            hh_key, {lam: _DampedStat(lam) for lam in self.LAMBDAS_HH_JIT}
        )
        for lam in self.LAMBDAS_HH_JIT:
            HHjit_for_pair[lam].update(t_ms, jitter)

        return {
            'H_L0.01_weight':       H_for_src[0.01].weight(),
            'H_L0.1_weight':        H_for_src[0.1].weight(),
            'H_L1_weight':          H_for_src[1.0].weight(),
            'H_L3_weight':          H_for_src[3.0].weight(),
            'H_L0.01_mean':         H_for_src[0.01].mean(),
            'MI_dir_L0.01_weight':  MIdir_for_pair[0.01].weight(),
            'MI_dir_L0.1_weight':   MIdir_for_pair[0.1].weight(),
            'MI_dir_L1_weight':     MIdir_for_pair[1.0].weight(),
            'MI_dir_L0.1_mean':     MIdir_for_pair[0.1].mean(),
            'HH_jit_L1_mean':       HHjit_for_pair[1.0].mean(),
        }


# ============================================================================
# Enriquecimiento de un DataFrame de _base.csv
# ============================================================================
def enrich_dataset(df, kitsune, dst_bytes_running):
    """Aplica Kitsune + agregaciones + counters al DataFrame de un _base.csv.
    El KitsuneExtractor y el dict dst_bytes_running se pasan desde el caller
    para que su estado persista entre archivos (procesados en orden temporal).
    Devuelve un DataFrame ya filtrado a SELECTED_FEATURES."""
    src_ip_counter = defaultdict(int)
    dst_ip_counter = defaultdict(int)
    enriched_rows = []

    required_fields = [
        'src_ip', 'dst_ip', 'src_pkts', 'dst_pkts',
        'src_ip_bytes', 'dst_ip_bytes', 'proto', 'dst_port',
        'stime', 'ltime', 'dur', 'conn_state', 'service', 'dns_rejected', 'label',
    ]

    # Procesar en orden temporal (importante para Kitsune)
    df = df.sort_values('stime', kind='mergesort').reset_index(drop=True)

    for _, row in df.iterrows():
        if any(pd.isna(row.get(f)) for f in required_fields):
            continue
        try:
            src_ip      = row['src_ip']
            dst_ip      = row['dst_ip']
            src_bytes   = row['src_ip_bytes']
            dst_bytes   = row['dst_ip_bytes']
            src_pkts    = row['src_pkts']
            dst_pkts    = row['dst_pkts']
            proto_str   = row['proto']
            dst_port    = row['dst_port']
            stime       = row['stime']
            ltime       = row['ltime']
            dur         = row['dur']
            conn_state  = row['conn_state']
            service     = row['service']

            # Counters
            src_ip_counter[src_ip] += 1
            dst_ip_counter[dst_ip] += 1
            dst_bytes_running[dst_ip] += float(src_bytes or 0) + float(dst_bytes or 0)

            # Signal vector + agregaciones
            signal_values = [src_bytes, dst_bytes, src_pkts, dst_pkts]
            sig_arr       = np.asarray(signal_values, dtype=float)

            # Kitsune features
            kits = kitsune.update_and_extract(
                stime, src_ip, dst_ip, src_bytes, dst_bytes
            )

            feature_row = {
                'proto':              proto_str,
                'conn_state':         conn_state,
                'service':            service,
                'dns_rejected':       row['dns_rejected'],
                'src_ip_bytes':       src_bytes,
                'dst_ip_bytes':       dst_bytes,
                'src_pkts':           src_pkts,
                'dst_pkts':           dst_pkts,
                'http_status_code':   row.get('http_status_code', -1),
                'dst_port':           dst_port,
                'stime':              stime,
                'ltime':              ltime,
                'dur':                dur,
                'TnBPDstIP':          dst_bytes_running[dst_ip],
                'sum':                float(sig_arr.sum()),
                'N_IN_Conn_P_DstIP':  dst_ip_counter[dst_ip],
                'N_IN_Conn_P_SrcIP':  src_ip_counter[src_ip],
                'max':                float(sig_arr.max()),
                'mean':               float(sig_arr.mean()),
                'min':                float(sig_arr.min()),
                'stddev':             float(sig_arr.std()),
                'state_number':       _STATE_TO_NUM.get(conn_state, -1),
                'proto_number':       _PROTO_TO_NUM.get(proto_str, -1),
                **kits,
                'label':              row['label'],
            }
            enriched_rows.append({k: feature_row[k] for k in SELECTED_FEATURES})

        except Exception as e:
            print(f"Error enriqueciendo fila: {e}")

    return pd.DataFrame(enriched_rows)


# ============================================================================
# Main — procesa todos los _base.csv en orden temporal global
# ============================================================================
if __name__ == "__main__":
    script_dir    = Path(__file__).resolve().parent
    input_folder  = script_dir / "DATASETS"
    output_folder = script_dir / "Ton-IoT-MultiFet"
    output_folder.mkdir(parents=True, exist_ok=True)

    base_files = [f for f in os.listdir(input_folder) if f.endswith("_base.csv")]
    if not base_files:
        raise RuntimeError(
            f"No _base.csv files in {input_folder}. Run Part1 first."
        )

    # Validar que los _base.csv tengan ltime/dur (necesitan Part1 actualizado).
    sample = pd.read_csv(input_folder / base_files[0], nrows=1)
    missing = {'ltime', 'dur'} - set(sample.columns)
    if missing:
        raise RuntimeError(
            f"_base.csv files no traen las columnas {missing}. "
            "Re-run Part1 (esta version emite ltime y dur) antes de Part2."
        )

    # Ordenar archivos por su primer stime para procesarlos cronologicamente.
    def first_stime(filename):
        try:
            return pd.read_csv(input_folder / filename, usecols=['stime'], nrows=1)['stime'].iloc[0]
        except Exception:
            return float('inf')

    print("Ordenando archivos por stime para procesamiento temporal correcto...")
    base_files_sorted = sorted(base_files, key=first_stime)

    # Estado compartido entre archivos.
    kitsune           = KitsuneExtractor()
    dst_bytes_running = defaultdict(float)

    processed_files = 0
    skipped_files   = 0

    for file in base_files_sorted:
        output_name = file.replace("_base.csv", "_combined.csv")
        output_path = output_folder / output_name

        if output_path.exists():
            print(f"Ya existe: {output_name} — omitido.")
            skipped_files += 1
            continue

        print(f"\nEnriqueciendo: {file}")
        df_base     = pd.read_csv(input_folder / file)
        df_enriched = enrich_dataset(df_base, kitsune, dst_bytes_running)

        if not df_enriched.empty:
            df_enriched.to_csv(output_path, index=False)
            print(f"Guardado: {output_path}  ({len(df_enriched)} filas, "
                  f"{df_enriched.shape[1]} columnas)")
            processed_files += 1
        else:
            print(f"{file} fue omitido por falta de datos validos.")

    print(f"\n{processed_files} archivos enriquecidos.")
    print(f"{skipped_files} archivos ya existian y fueron omitidos.")
    print(f"Kitsune state final: {len(kitsune._H)} unique src_ips, "
          f"{len(kitsune._MIdir)} unique (src,dst) pairs.")
