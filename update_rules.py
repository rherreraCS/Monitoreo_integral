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

# Copiar las nuevas reglas al archivo de destino
src_file = os.path.join(repo_path, 'maldocs_index.yar')
shutil.copy(src_file, dest_file)
print(f'{src_file} ha sido copiado a {dest_file}')

# Leer y corregir el archivo `regla2.yar` para eliminar líneas `include`
with open(dest_file, 'r') as file:
    lines = file.readlines()

with open(dest_file, 'w') as file:
    for line in lines:
        if not line.strip().startswith('include'):
            file.write(line)

