import pandas as pd
import argparse
import os

def crear_subset(ruta_csv, etiquetas, muestras_por_clase, salida):
    # Cargar el dataset
    df = pd.read_csv(ruta_csv)

    # Verificar que la columna 'label' existe
    if 'label' not in df.columns:
        raise ValueError("La columna 'label' no existe en el archivo CSV.")

    # Filtrar por las etiquetas solicitadas
    df_filtrado = df[df['label'].isin(etiquetas)]

    # Submuestreo balanceado
    df_subset = df_filtrado.groupby('label').apply(
        lambda x: x.sample(n=min(muestras_por_clase, len(x)), random_state=42)
    ).reset_index(drop=True)

    # Guardar archivo
    df_subset.to_csv(salida, index=False)
    print(f"Subconjunto creado con éxito: {salida}")
    print(df_subset['label'].value_counts())

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Crear subconjunto balanceado de Ton-IoT.")
    parser.add_argument("--csv", required=True, help="Ruta al archivo CSV de Ton-IoT.")
    parser.add_argument("--etiquetas", nargs="+", required=True, help="Etiquetas a incluir (por ejemplo: DDoS Normal Reconnaissance).")
    parser.add_argument("--muestras", type=int, default=1000, help="Número de muestras por clase.")
    parser.add_argument("--salida", default="ton_iot_subset.csv", help="Nombre del archivo de salida.")

    args = parser.parse_args()

    crear_subset(args.csv, args.etiquetas, args.muestras, args.salida)
