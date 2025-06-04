import pandas as pd
import os

# Parámetros
filename = "TonIot-MultiFet.csv"  # Cambia esto si tu archivo tiene otro nombre
subset_size = 0.1  # Proporción del dataset que deseas conservar (0.1 = 10%)
random_seed = 42   # Para reproducibilidad

# Ruta al archivo (misma carpeta del script)
script_dir = os.path.dirname(os.path.abspath(__file__))
file_path = os.path.join(script_dir, filename)

# Leer el dataset
print(f"Leyendo archivo: {file_path}")
df = pd.read_csv(file_path)

# Generar el subset
subset = df.sample(frac=subset_size, random_state=random_seed)
subset_filename = f"subset_{filename}"

# Guardar el nuevo archivo
subset_path = os.path.join(script_dir, subset_filename)
subset.to_csv(subset_path, index=False)

print(f"Subset generado con {len(subset)} filas.")
print(f"Guardado como: {subset_filename}")
