import pandas as pd
import os


#Cuenta cuantas instancias por archivo existen en los archivos
#Se ejecuta para verificar la integridad de los archivos Generados
# Que cumplan con la composicion deseada.


csv_file_path = "TonIoT-formodels-allfets-multiclass.csv"

def contar_por_categoria(csv_path):
    if not os.path.exists(csv_path):
        print(f"Archivo no encontrado: {csv_path}")
        return

    try:
        df = pd.read_csv(csv_path)
        
        if 'category' not in df.columns:
            print("La columna 'category' no se encuentra en el archivo.")
            return

        conteo = df['category'].value_counts()
        print("Cantidad de instancias por tipo en 'category':")
        print(conteo)

    except Exception as e:
        print(f"Ocurrió un error al procesar el archivo: {e}")

# Ejecutar función
contar_por_categoria(csv_file_path)
