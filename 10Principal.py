 
import logging
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import time
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import requests
import yara
import os

# Configuración del correo electrónico
email_sender = 'rhsecure@zohomail.eu'
email_password = '0640Rhp635/'
email_receiver = 'rherrera.ciberseguridad@gmail.com'
smtp_server = 'smtp.zoho.eu'
smtp_port = 587

# Configuración de VirusTotal
api_key = '8abea6e6918845f32e21cfabb471091eec790a988d19f6dee71b05d088635984'  # Reemplaza con tu clave de API de VirusTotal

# Variable para rastrear si se ha enviado un correo
first_event_sent = False

# Función para cargar reglas YARA desde una carpeta
def load_yara_rules(rules_folder):
    rules = {}
    for filename in os.listdir(rules_folder):
        if filename.endswith(".yar"):
            rule_path = os.path.join(rules_folder, filename)
            rule_name = os.path.splitext(filename)[0]
            rules[rule_name] = rule_path
    compiled_rules = yara.compile(filepaths=rules)
    return compiled_rules

# Ruta a la carpeta con las reglas YARA
rules_folder = 'C:\\Users\\Ramon\\InteGM1\\reglas_yara'
rules = load_yara_rules(rules_folder)

def send_email(subject, body):
    global first_event_sent
    if not first_event_sent:
        msg = MIMEMultipart()
        msg['From'] = email_sender
        msg['To'] = email_receiver
        msg['Subject'] = subject

        msg.attach(MIMEText(body, 'plain'))

        try:
            server = smtplib.SMTP(smtp_server, smtp_port)
            server.starttls()
            server.login(email_sender, email_password)
            text = msg.as_string()
            server.sendmail(email_sender, email_receiver, text)
            server.quit()
            print(f'Correo enviado a {email_receiver}')
            first_event_sent = True
            time.sleep(20)  # Añade una pausa de 20 segundos entre los envíos
        except Exception as e:
            print(f'Error al enviar correo: {e}')

def scan_with_virustotal(api_key, file_path):
    url = 'https://www.virustotal.com/api/v3/files'
    headers = {
        'x-apikey': api_key,
    }
    try:
        with open(file_path, 'rb') as file:
            files = {'file': (file_path, file)}
            response = requests.post(url, headers=headers, files=files)
            response.raise_for_status()
            return response.json()
    except requests.RequestException as req_error:
        print(f'Error al escanear con VirusTotal: {req_error}')
    except Exception as e:
        print(f'Error general al escanear con VirusTotal: {e}')

def get_analysis_report(api_key, analysis_id):
    url = f'https://www.virustotal.com/api/v3/analyses/{analysis_id}'
    headers = {
        'x-apikey': api_key,
    }
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as req_error:
        print(f'Error al obtener el informe de análisis: {req_error}')
    except Exception as e:
        print(f'Error general al obtener el informe de análisis: {e}')

def scan_file_with_yara_and_virustotal(file_path):
    matches = rules.match(file_path)
    if matches:
        for match in matches:
            print(f"YARA match found: {match.rule}")
        result = scan_with_virustotal(api_key, file_path)
        analysis_id = result['data']['id']
        print(f'Análisis enviado a VirusTotal. ID: {analysis_id}')

        # Esperar a que el análisis se complete
        analysis_status = "queued"
        while analysis_status == "queued":
            report = get_analysis_report(api_key, analysis_id)
            analysis_status = report['data']['attributes']['status']
            if analysis_status == "completed":
                print('Análisis completado:')
                print(report)
            else:
                print('Esperando a que el análisis se complete...')
                time.sleep(30)  # Esperar 30 segundos antes de volver a verificar
    else:
        print("No YARA match found")

class MonitorHandler(FileSystemEventHandler):
    def on_modified(self, event):
        logging.info(f'Archivo modificado: {event.src_path}')
        print(f'Evento detectado - Modificado: {event.src_path}')
        send_email('Archivo modificado', f'Archivo modificado en: {event.src_path}')
        scan_file_with_yara_and_virustotal(event.src_path)

    def on_created(self, event):
        logging.info(f'Archivo creado: {event.src_path}')
        print(f'Evento detectado - Creado: {event.src_path}')
        send_email('Archivo creado', f'Archivo creado en: {event.src_path}')
        scan_file_with_yara_and_virustotal(event.src_path)

    def on_deleted(self, event):
        logging.info(f'Archivo eliminado: {event.src_path}')
        print(f'Evento detectado - Eliminado: {event.src_path}')
        send_email('Archivo eliminado', f'Archivo eliminado en: {event.src_path}')

if __name__ == "__main__":
    logging.basicConfig(filename='file_monitor.log', level=logging.INFO, format='%(asctime)s - %(message)s')
    print('Iniciando monitor de archivos...')

    paths = ["C:\\Users\\Ramon\\proyecto1\\personal", "C:\\Users\\Ramon\\proyecto1\\privado"]
    observers = []

    for path in paths:
        print(f'Monitoreando directorio: {path}')
        event_handler = MonitorHandler()
        observer = Observer()
        observer.schedule(event_handler, path, recursive=True)
        observer.start()
        observers.append(observer)

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        for observer in observers:
            observer.stop()
        for observer in observers:
            observer.join()
    print('Monitor detenido.')

# Usar la función con un archivo de prueba
file_path = 'C:\\Users\\Ramon\\proyecto1\\privado\\prueba3.txt'  # Especifica la ruta del archivo
scan_file_with_yara_and_virustotal(file_path)
