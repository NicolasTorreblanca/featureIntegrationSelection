# Archivo que realiza las actividades de etiquetado binario
# Para las etiquetas de los archivos se asignan etiquetas numericas para
# realizar un etiquetado binario-> Genera un CSV con 2 tipos de Categoria
# Binaria -> Benigno (0) Y Maligno (1)

import pandas as pd
import os

def categorizar_trafico(input_csv_path, output_csv_path):
    # Leer el archivo CSV
    df = pd.read_csv(input_csv_path)

    # Crear columna 'category': 0 si label es 'normal', 1 en otro caso
    df['category'] = df['label'].apply(lambda x: 0 if str(x).lower() == 'normal' else 1)

    # Eliminar columna 'label'
    df = df.drop(columns=['label'])

    # Guardar el nuevo DataFrame
    df.to_csv(output_csv_path, index=False)
    print(f"Archivo procesado guardado en: {output_csv_path}")

# Ejemplo de uso
if __name__ == "__main__":
    input_file = "TonIoT-formodels-allfets.csv"  # Reemplaza con tu ruta de entrada
    output_file = "TonIoT-formodels-allfets-binary.csv"  # Reemplaza con tu ruta de salida
    categorizar_trafico(input_file, output_file)
