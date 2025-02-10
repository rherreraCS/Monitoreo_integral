import os
import subprocess
import yara
import re

# Ruta al directorio del repositorio clonado
repo_path = 'C:\\Users\\Ramon\\InteGM1\\reglas_yara\\rules'

# Ruta al archivo de reglas que deseas actualizar
dest_file = 'C:\\Users\\Ramon\\InteGM1\\reglas_yara\\regla2.yar'

# Comando para actualizar el repositorio
update_command = f'cd {repo_path} && git pull origin master'

# Ejecutar el comando para actualizar el repositorio
subprocess.run(update_command, shell=True, check=True)

# Función para eliminar campos no válidos y referencias `include`
def clean_yara_rule(content):
    cleaned_content = []
    for line in content.split('\n'):
        # Eliminar líneas que contienen `include`
        if re.search(r'include', line):
            continue
        # Eliminar líneas con campos no válidos
        if re.search(r'certificate|url|service|receiver|package_name|activity|permission|network', line):
            continue
        cleaned_content.append(line)
    return '\n'.join(cleaned_content)

# Combinar todas las reglas YARA en el directorio y subdirectorios en un solo archivo de destino
with open(dest_file, 'w') as dest:
    for root, dirs, files in os.walk(repo_path):
        for filename in files:
            if filename.endswith('.yar'):
                src_file = os.path.join(root, filename)
                try:
                    # Leer el contenido del archivo
                    with open(src_file, 'r') as src:
                        content = src.read()

                    # Limpiar el contenido del archivo
                    cleaned_content = clean_yara_rule(content)

                    # Verificar la sintaxis del archivo YARA después de la limpieza
                    yara.compile(source=cleaned_content)

                    # Si la sintaxis es correcta, combinar las reglas
                    dest.write(f'// {src_file}\n')  # Comentario indicando el origen de la regla
                    dest.write(cleaned_content)
                    dest.write('\n')  # Añadir una nueva línea entre reglas para separación
                except yara.SyntaxError as e:
                    print(f'Error de sintaxis en {src_file}: {e}')
                except (OSError, IOError) as e:
                    print(f'Error al procesar {src_file}: {e}')
                    continue

print(f'Todas las reglas YARA de {repo_path} y sus subdirectorios han sido combinadas y copiadas a {dest_file}')
