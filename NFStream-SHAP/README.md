# NFStream-SHAP

Variante SHAP-driven de la pipeline `NFStream/`. Genera un testbed que
contiene **solo las 10 features que SHAP identificó como más informativas
para ToN-IoT** sobre el feature space integrado (TonIoT + N-BaIoT + Bot-IoT).

Las 10 columnas vienen de `output/ToN-IoT/top10_global.csv`:
`proto_tcp, proto_udp, src_ip_bytes, src_pkts, dst_pkts, conn_state_REJ,
dst_ip_bytes, conn_state_OTH, dns_rejected_F, service_dns`.

## Prerrequisitos

1. La pipeline `NFStream/` debe estar disponible (no se modifica nunca, solo
   se referencia para entender el feature integration original).
2. `output/ToN-IoT/top10_global.csv` debe existir. Se produce con
   `shap_analysis_multidataset.py` en la raíz del proyecto.
3. PCAPs en el layout esperado:
   ```
   CololocovsLaChile01032026/PCAP/
   ├── Normal/                <- .pcap de tráfico benigno
   └── Attacks/
       ├── BackDoor/
       ├── DDos/  DoS/  Injection/  MITM/
       └── Password/  RunsomWare/  Scanning/  XSS/
   ```
4. Dependencias Python: `nfstream`, `pandas`, `numpy`, `scikit-learn`,
   `pywavelets`, `scipy`. Instalar con:
   ```bash
   pip install nfstream pandas numpy scikit-learn pywavelets scipy
   ```
5. **Windows con username con caracteres acentuados:** NFStream usa
   multiprocessing y los workers pueden fallar con paths que contienen
   tildes. El helper `smoke_test_part1.py` y `run_part1_backdoor.py`
   convierten paths a formato 8.3 (`GetShortPathNameW`) antes de pasarlos
   a NFStream. Si encuentras fallas similares al ejecutar Part1 directo
   sobre `python TonIoT-Part1-integrator-PCAP.py`, usar los runners como
   plantilla.

## Orden de ejecución

Desde `NFStream-SHAP/`:

```
python TonIoT-Part1-integrator-PCAP.py        # PCAP → DATASETS/*_base.csv
python TonIoT-Part2-integrator-of-features.py # → Ton-IoT-MultiFet/*_combined.csv
python TonIoT-Part3-codificactor.py           # → Ton-IoT-Processed/*_processed.csv
python TonIoT-Part3b-SHAPFilter.py            # → Ton-IoT-SHAP/*_shap.csv
python TonIoT-Part4-TrainTestGenerator.py     # → TonIOT_Subset.csv

# Paso manual heredado de NFStream/: renombrar la salida de Part4
cp TonIOT_Subset.csv TonIoT-formodels-allfets.csv

python TonIoT-Part4a-BinaryClassCSV.py        # → TonIoT-formodels-allfets-binary.csv
# o
python TonIoT-Part4b-MultiClassCSV.py         # → TonIoT-formodels-allfets-multiclass.csv
```

## Diferencias respecto a NFStream/

| Etapa | Cambio |
|---|---|
| Part1 | Reescrito para emitir nombres y valores estilo Zeek (`proto` como string `tcp`/`udp`/`Other`/`None`, `dns_rejected` como `F`/`T`/`-`, `src_pkts`/`dst_pkts` en lugar de `src2dst_packets`/`dst2src_packets`, todas las columnas con guión bajo). Incluye derivadores `derive_conn_state(flow)` (sintetiza S0/SF/OTH desde packet counts cuando NFStream entrega None) y `derive_service(flow)` (fallback a `application_name` de nDPI). |
| Part2 | Igual lógica de integración (wavelet/entropía/MI), pero (a) referencias de columnas con guión bajo, (b) elimina la derivación sintética de `conn_state` desde packet counts — ahora usa el `conn_state` upstream de Part1, (c) propaga `dns_rejected` (la baseline lo dropeaba). |
| Part3 | `proto` ahora es categórica (era numérica), se agrega `dns_rejected` como categórica, y el `OneHotEncoder` se pre-fitea con el vocabulario Zeek conocido (KNOWN_VOCAB) para que las columnas de salida sean estables. Incluye un guard defensivo que inyecta `'None'` si alguna columna categórica falta en el input. |
| Part3b | **NUEVO.** Filtra el `_processed.csv` para conservar solo las columnas listadas en `output/ToN-IoT/top10_global.csv`. Falla loudly si alguna columna SHAP falta en el input. |
| Part4  | Cambia el constante `INPUT_FOLDER` para leer desde `Ton-IoT-SHAP/`. |
| Part4a, Part4b | Copia textual de `NFStream/`. |

## Estado de las 10 columnas SHAP en el testbed

Tras procesar el PCAP de BackDoor (71,283 flujos), el estado real de las
columnas SHAP en el testbed:

**Vivas (7/10) — Información útil para el clasificador:**
- `proto_tcp` (36,821 flujos)
- `proto_udp` (32,788 flujos)
- `src_ip_bytes` (70,335 con valor no cero)
- `src_pkts` (50,089 con valor no cero)
- `dst_pkts` (50,838 con valor no cero)
- `dst_ip_bytes` (50,838 con valor no cero)
- `service_dns` (13,727 flujos identificados como DNS por nDPI)

**Muertas por limitación arquitectónica (2/10):**
- `conn_state_REJ`: Zeek's REJ state requires observing TCP RST in
  response to SYN. NFStream solo cuenta paquetes; no puede inferir REJ.
  La síntesis de Part1 emite solo {S0, SF, OTH}.
- `dns_rejected_F`: NFStream no parsea respuestas DNS profundamente;
  `flow.dns_rejected` retorna `None` para todos los flujos. Part1
  emite `"-"` (faltante) en lugar de `"F"` (False).

**Muerta por características del PCAP (1/10):**
- `conn_state_OTH`: Requiere flujos con `src_pkts=0`, que no aparecen
  en el PCAP de BackDoor. Puede activarse al procesar otros PCAPs.

## Checklist de validación

1. **Smoke test individual.** Cada script (Part1 → Part2 → Part3 → Part3b
   → Part4 → Part4b) tiene un comando de validación incluido en sus
   comentarios o ejecutándolo directamente. Verificar:
   - Part1 produce `_base.csv` con 17 columnas en convención Zeek.
   - Part2 produce `_combined.csv` con 26 columnas integradas.
   - Part3 produce `_processed.csv` con todas las 10 columnas SHAP
     presentes (aunque algunas sean ceros).
   - Part3b produce `_shap.csv` con exactamente 11 columnas (10 SHAP +
     label) y mantiene la cantidad de filas.
   - Part4 produce `TonIOT_Subset.csv` con muestreo balanceado por
     clase. Si solo se procesó un PCAP, solo esa clase tendrá datos.
   - Part4b produce `TonIoT-formodels-allfets-multiclass.csv` con
     columna `category` (0-9) en lugar de `label`.

2. **Contrato de vocabulario.** Tras Part3, las 10 columnas SHAP
   (`proto_tcp, proto_udp, src_ip_bytes, src_pkts, dst_pkts,
   conn_state_REJ, dst_ip_bytes, conn_state_OTH, dns_rejected_F,
   service_dns`) deben estar presentes en algún `_processed.csv`.
   Part3b verifica esto en cada corrida; si falla con
   `RuntimeError: SHAP-required columns missing...`, revisar la
   normalización de vocabulario en Part1 (helpers `proto_to_str`,
   `normalize_conn_state`, `normalize_service`,
   `dns_bool_to_zeek_str`).

3. **Comparación de referencia.** Comparar una fila aleatoria de
   `Ton-IoT-SHAP/<x>_shap.csv` contra una fila de
   `output/ToN-IoT/dataset_reducido_global.csv`. Los conjuntos de
   columnas deben ser idénticos. Las distribuciones de valores deben
   estar en rangos similares — no van a ser idénticas bit-a-bit porque
   el upstream es distinto (flujos de NFStream vs filas de Zeek) y
   MinMax es relativo al dataset.

## Limitaciones conocidas

- **MinMax es dataset-relativo.** El scaler se fitea con los PCAPs
  procesados en cada corrida, no sobre el dataset completo de ToN-IoT.
  Las accuracies absolutas no son comparables 1:1 con modelos
  entrenados sobre `Ton-IoT-Complete.csv`. Tratarlas como rankings,
  no como valores absolutos.

- **Vocabulario de NFStream vs Zeek.** NFStream 6.6.0 retorna `None`
  para `flow.connection_state` y `flow.requested_service` en todos los
  flujos extraídos de los PCAPs de ToN-IoT. Part1 mitiga esto con los
  derivadores `derive_conn_state` (síntesis desde packet counts) y
  `derive_service` (fallback a `application_name` de nDPI). Pero
  algunos valores Zeek (notablemente `conn_state_REJ` y la distinción
  `dns_rejected_F` vs `dns_rejected_-`) no pueden recuperarse sin un
  parser stateful como el de Zeek. Tres de las 10 columnas SHAP
  permanecen como ceros constantes.

- **Carpeta `RunsomWare`.** El nombre de la carpeta tiene una grafía
  particular (`Runsom-` en vez de `Ransom-`); la etiqueta canónica
  downstream es `ransomware`. Absorbido en `LABEL_MAPPING` de Part1.
  Si la carpeta se renombra, actualizar la clave allí únicamente.

- **Paso manual de renombre entre Part4 y Part4a/Part4b.** Part4 escribe
  `TonIOT_Subset.csv` pero Part4a y Part4b leen
  `TonIoT-formodels-allfets.csv`. Es necesario un `cp` manual entre
  estos pasos. Esta inconsistencia está heredada de la baseline
  `NFStream/`.

## Helpers y fixtures

- `smoke_test_part1.py`: corre Part1 sobre un solo PCAP (BackDoor) y
  valida la estructura del output. Incluye workaround Windows para
  paths con tildes.
- `run_part1_backdoor.py`: helper para regenerar
  `DATASETS/normal_backdoor_base.csv` sin correr el pipeline completo.
  Útil durante el desarrollo y debugging.

Ambos helpers están committed bajo `NFStream-SHAP/`.
