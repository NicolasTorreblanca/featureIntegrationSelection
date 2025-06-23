 Archivos usados para realizar las actividades de Preprocesamiento.

 Para ejecutar cada uno de los archivos, es necesario tener las carpetas creadas
 Por que necesitan ocupar rutas para trabajar los archivos que se utilizarán a continuacion.

# Neceista tener una carpeta PCAP, que contenga una carpeta para LOS FLUJOS de TonIot
# Aqui, almacenar todos los flujos y agrupar segun su tipo.
# Si no se cumple este paso, no va a funcionar el programa.


 Como es el orden
 TonIoT-Part1-integrator-PCAP.py
 TonIoT-Part2-integrator-of-features.py
 TonIoT-codificactor-Part3.py


 Esto genera los archivos Con casi todas las actividades
 de pre procesamiento que se buscan llevar a cabo

# A partir de los traficos de red, obtener caracteristicas
# Se usa para eso los primeros dos archivos.

# El codificator realiza actividades de preprocesamiento
# Relacionadas con modificar el archivo para que facilite la actividad de los
# Modelos de aprendizaje Automatico.

# Estas son
# - Eliminar valores Nulos
# - Codificar con One-Hot a las variables categoricas.
# - Aplicar normalizaciones con Min Max

La segunda parte consiste en generar el Dataset correspondiente con la proporción planteada, esta consiste en un :

# Aproximada mente un 65 % de trafico Benigno
# Aproximada mente un 35 % de trafico maligno

La cual es realizada por el siguiente archivo. A partir de este, el conjunto de datos se considera generado pero no finalizado, por que todavia queda asociar una etiqueta a los tipos de trafico.

TonIoT-Part4-TrainTestGenerator.py

Para asociar el trafico a un etiquetado deseado, se ocupan los archivos 

TonIoT-Part4a-BinaryClassCSV.py
TonIoT-Part4b-MultiClassCSV.py

Esto es según el etiquetado deseado , ya sea para generar el archivo en su formato Binario
O en su formato multiclase