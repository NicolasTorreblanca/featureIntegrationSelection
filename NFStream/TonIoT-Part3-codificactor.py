# Primera parte del Script
# TonIoT-Part3-codificactor.py
# 
# Se ejecuta sobre los archivos CSV con caracteristicas integradas
# 
# Lo que hace es hacer las transformaciones
# 
# Entrada: Archivos CSV con caracteristicas integradas (_combined.csv)
# Salida : Archivos CSV con todas las caracteristicas (_processed.csv)
#
# Usa Min max scaler para la normalizacion
# Usa OneHotEncoder para la codificacion de las variables categoricas.

import os
import pandas as pd
from sklearn.preprocessing import MinMaxScaler, OneHotEncoder

# Columnas categóricas y numéricas
CATEGORICAL_COLS = ['state', 'service', 'conn-state']
NUMERIC_COLS = [
    'http-status-code', 'src-bytes', 'dst-ip-bytes', 'dst-port', 'src-pkts', 'proto',
    'MI-dir-L5-weight', 'HH-L3-weight', 'HH-L0.01-weight',
    'HpHp-L0.01-weight', 'HpHp-L0.01-mean', 'HpHp-L0.01-std', 'HpHp-L0.01-magnitude',
    'N-IN-Conn-P-DstIP', 'N-IN-Conn-P-SrcIP', 'state-number', 'proto-number',
    'stime', 'max', 'mean', 'min', 'stddev'
]
LABEL_COL = 'label'

def preprocess_dataframe(df, encoder=None, scaler=None, fit=False):
    # Eliminar nulos en columnas críticas
    df = df.dropna(subset=CATEGORICAL_COLS + NUMERIC_COLS + [LABEL_COL])

    if df.empty:
        return pd.DataFrame(), encoder, scaler

    # Escalamiento Min-Max
    if fit:
        scaler = MinMaxScaler()
        df[NUMERIC_COLS] = scaler.fit_transform(df[NUMERIC_COLS])
    else:
        df[NUMERIC_COLS] = scaler.transform(df[NUMERIC_COLS])

    # One-Hot Encoding (compatibilidad con sklearn >=1.2)
    if fit:
        encoder = OneHotEncoder(sparse_output=False, handle_unknown='ignore')
        encoded = encoder.fit_transform(df[CATEGORICAL_COLS])
    else:
        encoded = encoder.transform(df[CATEGORICAL_COLS])

    encoded_df = pd.DataFrame(encoded, columns=encoder.get_feature_names_out(CATEGORICAL_COLS))
    df = pd.concat([df.drop(columns=CATEGORICAL_COLS).reset_index(drop=True), encoded_df], axis=1)

    return df, encoder, scaler

def align_columns(df, reference_columns):
    for col in reference_columns:
        if col not in df.columns:
            df[col] = 0
    return df[reference_columns]

if __name__ == "__main__":
    script_dir = os.path.dirname(os.path.abspath(__file__))
    input_folder = os.path.join(script_dir, "Ton-IoT-MultiFet")     # Entrada
    output_folder = os.path.join(script_dir, "Ton-IoT-Processed")   # Salida
    os.makedirs(output_folder, exist_ok=True)

    reference_columns = None
    encoder = None
    scaler = None
    processed = 0
    skipped = 0

    for idx, file in enumerate(sorted(os.listdir(input_folder))):
        if file.endswith("_combined.csv"):
            input_path = os.path.join(input_folder, file)
            output_path = os.path.join(output_folder, file.replace("_combined.csv", "_processed.csv"))

            print(f"Procesando: {file}")
            df = pd.read_csv(input_path)

            try:
                if idx == 0:
                    df_processed, encoder, scaler = preprocess_dataframe(df, fit=True)
                    if df_processed.empty:
                        print(f"{file} vacío tras procesamiento — omitido.")
                        continue
                    reference_columns = df_processed.columns.tolist()
                else:
                    df_processed, _, _ = preprocess_dataframe(df, encoder, scaler, fit=False)
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
