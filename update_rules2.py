import os
import subprocess
import shutil

# Ruta al directorio del repositorio clonado
repo_path = 'C:\\Users\\Ramon\\InteGM1\\reglas_yara\\rules'

# Ruta al archivo de reglas que deseas actualizar
dest_file = 'C:\\Users\\Ramon\\InteGM1\\reglas_yara\\regla2.yar'

# Comando para actualizar el repositorio
update_command = f'cd {repo_path} && git pull origin master'

# Ejecutar el comando para actualizar el repositorio
subprocess.run(update_command, shell=True, check=True)

# Combinar todas las reglas YARA en el directorio y subdirectorios en un solo archivo de destino
with open(dest_file, 'w') as dest:
    for root, dirs, files in os.walk(repo_path):
        for filename in files:
            if filename.endswith('.yar'):
                src_file = os.path.join(root, filename)
                try:
                    with open(src_file, 'r') as src:
                        dest.write(f'// {src_file}\n')  # Comentario indicando el origen de la regla
                        dest.write(src.read())
                        dest.write('\n')  # Añadir una nueva línea entre reglas para separación
                except (OSError, IOError) as e:
                    print(f'Error al procesar {src_file}: {e}')
                    continue

print(f'Todas las reglas YARA de {repo_path} y sus subdirectorios han sido combinadas y copiadas a {dest_file}')

# Leer y corregir el archivo `regla2.yar` para eliminar líneas `include`
with open(dest_file, 'r') as file:
    lines = file.readlines()

with open(dest_file, 'w') as file:
    for line in lines:
        if not line.strip().startswith('include'):
            file.write(line)


