# Archivo que realiza las actividades de etiquetado MultiClase
# Para las etiquetas de los archivos se asignan etiquetas numericas para
# realizar un etiquetado multiclase-> Genera un CSV con varios tipos de Categoria

import pandas as pd

def multiclase_categoria_numerica(input_csv_path, output_csv_path):
    # Leer archivo
    df = pd.read_csv(input_csv_path)

    # Diccionario de clases mapeadas a números
    clase_a_numero = {
        'normal': 0,
        'backdoor': 1,
        'dos': 2,
        'ddos': 3,
        'injection': 4,
        'mitm': 5,
        'scanning': 6,
        'ransomware': 7,
        'password': 8,
        'xss': 9
    }

    # Normaliza a minúsculas y mapea a número
    df['category'] = df['label'].str.lower().map(clase_a_numero)

    # Verifica si hay valores que no se pudieron mapear
    if df['category'].isnull().any():
        etiquetas_invalidas = df[df['category'].isnull()]['label'].unique()
        print("Advertencia: se encontraron etiquetas no reconocidas:", etiquetas_invalidas)

    # Eliminar columna 'label'
    df = df.drop(columns=['label'])

    # Guardar resultado
    df.to_csv(output_csv_path, index=False)
    print(f"Archivo multiclase numérico guardado en: {output_csv_path}")

# Ejemplo
if __name__ == "__main__":
    input_file = "TonIoT-formodels-allfets.csv"
    output_file = "TonIoT-formodels-allfets-multiclass.csv"
    multiclase_categoria_numerica(input_file, output_file)

