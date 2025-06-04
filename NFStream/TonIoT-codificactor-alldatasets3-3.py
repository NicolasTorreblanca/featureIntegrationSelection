import os
import pandas as pd
from sklearn.preprocessing import MinMaxScaler, OneHotEncoder
import numpy as np

def preprocess_dataframe(df):
    # Columnas categóricas a codificar
    categorical_columns = ['dns-query', 'state', 'service', 'http-status-code']
    # Columnas numéricas a normalizar
    numeric_columns = [
        'dns-rejected', 'dns-RD', 'src-bytes', 'dst-ip-bytes',
        'MI-dir-L5-weight', 'HH-L3-weight', 'HH-L0.01-weight',
        'HpHp-L0.01-weight', 'HpHp-L0.01-mean', 'HpHp-L0.01-std',
        'HpHp-L0.01-magnitude', 'N-IN-Conn-P-SrcIP', 'N-IN-Conn-P-DstIP',
        'state-number', 'proto-number', 'stime', 'max', 'mean', 'min', 'stddev'
    ]

    # Verificar existencia real de las columnas en el archivo
    categorical_columns = [col for col in categorical_columns if col in df.columns]
    numeric_columns = [col for col in numeric_columns if col in df.columns]

    # Eliminar valores nulos
    df = df.dropna()

    # Normalizar columnas numéricas
    if numeric_columns:
        scaler = MinMaxScaler()
        df[numeric_columns] = scaler.fit_transform(df[numeric_columns])

    # Codificación One-Hot
    if categorical_columns:
        encoder = OneHotEncoder(sparse=False, handle_unknown='ignore')
        encoded = encoder.fit_transform(df[categorical_columns])
        encoded_df = pd.DataFrame(encoded, columns=encoder.get_feature_names_out(categorical_columns))

        # Combinar el resultado con las columnas restantes
        df = pd.concat([df.drop(columns=categorical_columns).reset_index(drop=True), encoded_df], axis=1)

    return df

if __name__ == "__main__":
    script_dir = os.path.dirname(os.path.abspath(__file__))

    # Carpeta de entrada y salida
    input_folder = os.path.join(script_dir, "Ton-IoT-MultiFet")
    output_folder = os.path.join(script_dir, "Ton-IoT-Processed")
    os.makedirs(output_folder, exist_ok=True)

    processed = 0
    skipped = 0

    for file in os.listdir(input_folder):
        if file.endswith("_combined.csv"):
            input_path = os.path.join(input_folder, file)
            output_name = file.replace("_combined.csv", "_processed.csv")
            output_path = os.path.join(output_folder, output_name)

            if os.path.exists(output_path):
                print(f"Ya existe: {output_name} — omitido.")
                skipped += 1
                continue

            print(f"\nProcesando: {file}")
            df = pd.read_csv(input_path)

            try:
                df_transformed = preprocess_dataframe(df)
                df_transformed.to_csv(output_path, index=False)
                print(f"Guardado: {output_path}")
                processed += 1
            except Exception as e:
                print(f"Error procesando {file}: {e}")

    print(f"\n{processed} archivos procesados correctamente.")
    print(f"{skipped} archivos ya existían y fueron omitidos.")
