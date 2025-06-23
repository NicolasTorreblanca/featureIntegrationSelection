import os
import pandas as pd

def merge_processed_files(input_folder, output_file):
    merged_df = None
    reference_columns = None
    files_merged = 0
    files_skipped = 0

    for file in sorted(os.listdir(input_folder)):
        if file.endswith("_processed.csv"):
            file_path = os.path.join(input_folder, file)
            try:
                df = pd.read_csv(file_path)

                # Asegurar que las columnas coincidan con el primer archivo
                if merged_df is None:
                    merged_df = df.copy()
                    reference_columns = df.columns.tolist()
                else:
                    # Alinear columnas si falta alguna
                    for col in reference_columns:
                        if col not in df.columns:
                            df[col] = 0
                    df = df[reference_columns]
                    merged_df = pd.concat([merged_df, df], ignore_index=True)

                files_merged += 1
            except Exception as e:
                print(f"Error leyendo {file}: {e}")
                files_skipped += 1

    if merged_df is not None:
        merged_df.to_csv(output_file, index=False)
        print(f"\n Archivo final guardado: {output_file}")
        print(f"Archivos unidos: {files_merged}")
        print(f"Archivos omitidos: {files_skipped}")
    else:
        print(" No se generó el archivo final. Ningún archivo válido encontrado.")

if __name__ == "__main__":
    script_dir = os.path.dirname(os.path.abspath(__file__))
    input_folder = os.path.join(script_dir, "Ton-IoT-Processed")
    output_file = os.path.join(script_dir, "Ton-IoT-Combined-Features.csv")

    merge_processed_files(input_folder, output_file)
