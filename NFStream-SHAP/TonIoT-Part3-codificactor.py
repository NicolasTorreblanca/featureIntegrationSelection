# TonIoT-Part3-codificactor.py  (NFStream-SHAP variant)
#
# Diferencias respecto a NFStream/Part3:
#   - proto se trata como categórica (string).
#   - dns_rejected se trata como categórica.
#   - El OneHotEncoder se pre-fitea con el vocabulario conocido para que las
#     columnas de salida (proto_tcp, conn_state_REJ, service_dns, ...)
#     siempre existan, aun si no aparecen en los flujos procesados en esta
#     corrida. Esto evita que Part3b falle por columnas ausentes.
#
# Entrada : Ton-IoT-MultiFet/*_combined.csv  (de Part2)
# Salida  : Ton-IoT-Processed/*_processed.csv

import os
import pandas as pd
from pathlib import Path
from sklearn.preprocessing import MinMaxScaler, OneHotEncoder

CATEGORICAL_COLS = ['proto', 'conn_state', 'service', 'dns_rejected']
NUMERIC_COLS = [
    'http_status_code', 'src_ip_bytes', 'dst_ip_bytes', 'dst_port',
    'src_pkts', 'dst_pkts',
    'MI_dir_L5_weight', 'HH_L3_weight', 'HH_L0.01_weight',
    'HpHp_L0.01_weight', 'HpHp_L0.01_mean', 'HpHp_L0.01_std', 'HpHp_L0.01_magnitude',
    'N_IN_Conn_P_DstIP', 'N_IN_Conn_P_SrcIP', 'state_number', 'proto_number',
    'stime', 'max', 'mean', 'min', 'stddev',
]
LABEL_COL = 'label'

# Vocabulario conocido (corresponde a las columnas one-hot en Ton-IoT-Complete.csv).
KNOWN_VOCAB = {
    'proto':        ['tcp', 'udp', 'Other', 'None'],
    'conn_state':   ['OTH', 'Other', 'REJ', 'S0', 'SF'],
    'service':      ['-', 'Other', 'dns', 'http', 'None'],
    'dns_rejected': ['-', 'F', 'Other', 'None'],
}


def build_prefit_encoder():
    """Pre-entrena el encoder con el vocabulario conocido. Esto garantiza que
    columnas como proto_tcp / conn_state_REJ / service_dns / dns_rejected_F
    existan en la salida aun cuando no aparezcan flujos con esos valores."""
    # Construye un mini-DataFrame con todas las combinaciones del vocabulario.
    max_len = max(len(v) for v in KNOWN_VOCAB.values())
    seed = {}
    for col in CATEGORICAL_COLS:
        vals = list(KNOWN_VOCAB[col])
        # Pad para que todas las columnas tengan el mismo largo
        vals = vals + [vals[-1]] * (max_len - len(vals))
        seed[col] = vals
    seed_df = pd.DataFrame(seed)
    encoder = OneHotEncoder(sparse_output=False, handle_unknown='ignore')
    encoder.fit(seed_df[CATEGORICAL_COLS])
    return encoder


def preprocess_dataframe(df, encoder, scaler=None, fit_scaler=False):
    # dns_rejected may be absent if Part2 did not emit it; inject as 'None'
    # so the pre-fitted encoder still produces dns_rejected_* columns (all-zero).
    for col in CATEGORICAL_COLS:
        if col not in df.columns:
            df[col] = 'None'

    df = df.dropna(subset=CATEGORICAL_COLS + NUMERIC_COLS + [LABEL_COL])
    if df.empty:
        return pd.DataFrame(), scaler

    if fit_scaler:
        scaler = MinMaxScaler()
        df[NUMERIC_COLS] = scaler.fit_transform(df[NUMERIC_COLS])
    else:
        df[NUMERIC_COLS] = scaler.transform(df[NUMERIC_COLS])

    encoded = encoder.transform(df[CATEGORICAL_COLS])
    encoded_df = pd.DataFrame(
        encoded,
        columns=encoder.get_feature_names_out(CATEGORICAL_COLS),
        index=df.index,
    )
    df = pd.concat([df.drop(columns=CATEGORICAL_COLS), encoded_df], axis=1)
    return df, scaler


def align_columns(df, reference_columns):
    for col in reference_columns:
        if col not in df.columns:
            df[col] = 0
    return df[reference_columns]


if __name__ == "__main__":
    script_dir    = Path(__file__).resolve().parent
    input_folder  = script_dir / "Ton-IoT-MultiFet"
    output_folder = script_dir / "Ton-IoT-Processed"
    output_folder.mkdir(parents=True, exist_ok=True)

    encoder = build_prefit_encoder()
    reference_columns = None
    scaler = None
    processed = 0
    skipped = 0

    combined_files = sorted([f for f in os.listdir(input_folder)
                             if f.endswith("_combined.csv")])
    if not combined_files:
        raise RuntimeError(
            f"No _combined.csv files in {input_folder}. Run Part2 first."
        )

    for idx, file in enumerate(combined_files):
        input_path  = input_folder / file
        output_path = output_folder / file.replace("_combined.csv", "_processed.csv")

        print(f"Procesando: {file}")
        df = pd.read_csv(input_path)
        try:
            if idx == 0:
                df_processed, scaler = preprocess_dataframe(
                    df, encoder, fit_scaler=True
                )
                if df_processed.empty:
                    print(f"{file} vacío tras procesamiento — omitido.")
                    continue
                reference_columns = df_processed.columns.tolist()
            else:
                df_processed, _ = preprocess_dataframe(
                    df, encoder, scaler=scaler, fit_scaler=False
                )
                if df_processed.empty:
                    print(f"{file} vacío tras procesamiento — omitido.")
                    continue
                df_processed = align_columns(df_processed, reference_columns)

            df_processed.to_csv(output_path, index=False)
            print(f"Guardado: {output_path}")
            processed += 1
        except Exception as e:
            print(f"Error procesando {file}: {e}")
            skipped += 1

    print(f"\n{processed} archivos procesados correctamente.")
    print(f"{skipped} archivos omitidos por error o estar vacíos.")
