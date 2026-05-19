# Cuarta parte del Script — NFStream-SHAP variant
# Único cambio respecto a NFStream/Part4: INPUT_FOLDER apunta a la carpeta
# de salida de Part3b en lugar de la de Part3.

import os
import pandas as pd

TARGET_SIZES = {
    "normal":     300000,
    "ddos":        20000,
    "dos":         20000,
    "backdoor":    20000,
    "injection":   20000,
    "mitm":         1043,
    "scanning":    20000,
    "ransomware":  20000,
    "password":    20000,
    "xss":         20000,
}

INPUT_FOLDER = "Ton-IoT-SHAP"
OUTPUT_FILE  = "TonIOT_Subset.csv"

class_data = {label: [] for label in TARGET_SIZES.keys()}

for file in os.listdir(INPUT_FOLDER):
    if file.endswith("_shap.csv"):
        path = os.path.join(INPUT_FOLDER, file)
        try:
            df = pd.read_csv(path)
            if 'label' not in df.columns:
                print(f"Advertencia: El archivo {file} no tiene columna 'label'. Omitido.")
                continue
            for label in TARGET_SIZES:
                df_label = df[df['label'] == label]
                if not df_label.empty:
                    class_data[label].append(df_label)
        except Exception as e:
            print(f"Error leyendo {file}: {e}")

final_frames = []
for label, target_count in TARGET_SIZES.items():
    if not class_data[label]:
        print(f"Advertencia: No se encontraron datos para la clase '{label}'.")
        continue
    df_total = pd.concat(class_data[label], ignore_index=True)
    if len(df_total) >= target_count:
        sampled = df_total.sample(n=target_count, random_state=42)
    else:
        print(f"Clase '{label}' tiene solo {len(df_total)} registros. Se completará con muestreo con reemplazo.")
        sampled = df_total.sample(n=target_count, replace=True, random_state=42)
    final_frames.append(sampled)

subset_df = pd.concat(final_frames).sample(frac=1, random_state=42).reset_index(drop=True)
subset_df.to_csv(OUTPUT_FILE, index=False)
print(f"\nSubset generado correctamente con {len(subset_df)} registros.")
print(f"Archivo guardado: {OUTPUT_FILE}")
