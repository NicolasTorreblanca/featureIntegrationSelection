import os
import pandas as pd
from nfstream import NFStreamer

if __name__ == "__main__":
    # 📂 Obtener la ruta del script actual
    script_dir = os.path.dirname(os.path.abspath(__file__))  

    # 📁 Construir la ruta del archivo PCAP
    pcap_file = os.path.join(script_dir, "PCAP", "MITM_normal4.pcap") 

    # 🔍 Imprimir la ruta para depuración
    print(f" Buscando archivo en: {pcap_file}")

    # 🚀 Verificar si el archivo PCAP existe
    if not os.path.exists(pcap_file):
        print(f" ERROR: El archivo '{pcap_file}' no existe. Verifica su nombre y ubicación.")
    else:
        print(f" Archivo encontrado en: {pcap_file}")

        # Cargar el tráfico de red desde el archivo PCAP
        streamer = NFStreamer(source=pcap_file)

        #  Convertir a DataFrame de pandas
        df = pd.DataFrame(streamer.to_pandas())

        # Mostrar las primeras filas
        print(df.head())

        # Guardar en un archivo CSV (opcional)
        output_file = os.path.join(script_dir, "PCAP", "trafico_red.csv")
        df.to_csv(output_file, index=False)

        print(f"Archivo procesado y guardado en '{output_file}'.")
 