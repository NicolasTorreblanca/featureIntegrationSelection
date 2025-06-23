import os
import pandas as pd

def merge_combined_csvs(input_folder, output_file):
    all_dfs = []
    total_rows = 0
    total_files = 0

    for file in os.listdir(input_folder):
        if file.endswith("_combined.csv"):
            path = os.path.join(input_folder, file)
            print(f"Uniendo archivo: {file}")
            df = pd.read_csv(path)
            all_dfs.append(df)
            total_rows += len(df)
            total_files += 1

    if not all_dfs:
        print("No se encontraron archivos _combined.csv.")
        return

    merged_df = pd.concat(all_dfs, ignore_index=True)
    merged_df.to_csv(output_file, index=False)
    print(f"\n {total_files} archivos unidos.")
    print(f" Total de filas combinadas: {total_rows}")
    print(f" Dataset final guardado en: {output_file}")

if __name__ == "__main__":
    script_dir = os.path.dirname(os.path.abspath(__file__))
    input_folder = os.path.join(script_dir, "Ton-IoT-MultiFet")
    output_file = os.path.join(script_dir, "final_dataset.csv")

    merge_combined_csvs(input_folder, output_file)
