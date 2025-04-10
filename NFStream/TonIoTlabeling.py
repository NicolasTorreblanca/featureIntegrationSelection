import pandas as pd
import os

# Mapeo de conn-state estilo Zeek a números
conn_state_map = {
    "S0": 0,   # Solo una dirección
    "S1": 1,   # Conexión establecida
    "OTH": 2   # Otro caso
}

# Mapeo de etiquetas de clase (ajustado a tus carpetas)
label_map = {
    "Normal": 0,
    "MITM": 1,
    "NormalDdos": 2,
    "NormalDos": 3,
    "NormalScanning": 4,
    "NormalXss": 5,
    "NormalRunsomware": 6,
    "InjectionNormal": 7,
    "PasswordNormal": 8,
    "Normal_backdoor": 9
}

def etiquetar_csv(input_csv, output_csv):
    """Convierte conn-state y label de texto a números en un CSV ya existente."""
    print(f"Procesando archivo: {input_csv}")
    df = pd.read_csv(input_csv)

    # Verificar columnas requeridas
    if 'conn-state' not in df.columns or 'label' not in df.columns:
        raise ValueError("El archivo debe contener las columnas 'conn-state' y 'label'.")

    # Reemplazar valores con los mapeos definidos
    df['conn-state'] = df['conn-state'].map(conn_state_map)
    df['class'] = df['label'].map(label_map)

    # Eliminar la columna original de texto

    conteo_1 = df['label'].value_counts()

    print(conteo_1)
    df = df.drop(columns=['label'])

    # Guardar el resultado
    df.to_csv(output_csv, index=False)
    print(f"Archivo etiquetado guardado en: {output_csv}")

    # Contar los valores únicos en la columna 'class'
    conteo = df['class'].value_counts()

# Mostrar el resultado
    print(conteo)

if __name__ == '__main__':
    script_dir = os.path.dirname(os.path.abspath(__file__))

    input_csv = os.path.join(script_dir, "DATASETS", "TonIoT_labeled.csv")
    output_csv = os.path.join(script_dir, "DATASETS", "TonIoT_6fet_labeled.csv")

    etiquetar_csv(input_csv, output_csv)
