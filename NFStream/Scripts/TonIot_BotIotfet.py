import os
import pandas as pd

def merge_csv_files(input_folder, output_file):
    all_dfs = []
    total_rows = 0

    for file in os.listdir(input_folder):
        if file.endswith("_flows.csv"):
            path = os.path.join(input_folder, file)
            print(f"Uniendo: {file}")
            df = pd.read_csv(path)
            all_dfs.append(df)
            total_rows += len(df)

    if not all_dfs:
        print("No se encontraron archivos CSV para unir.")
        return

    merged_df = pd.concat(all_dfs, ignore_index=True)
    merged_df.to_csv(output_file, index=False)
    print(f"\nSe han unido {len(all_dfs)} archivos con un total de {total_rows} filas.")
    print(f"Dataset combinado guardado en: {output_file}")

if __name__ == "__main__":
    input_folder = os.path.join(os.path.dirname(os.path.abspath(__file__)), "DATASETS")
    output_file = os.path.join(input_folder, "Ton-IoTwithBot-IoTfets.csv")
    merge_csv_files(input_folder, output_file)
