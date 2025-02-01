 
import logging
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import time
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import requests
import yara

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

# Compilar la regla YARA
rule = yara.compile(source="""
rule TestRule {
    strings:
        $my_text_string = "malicious_string"
        $my_hex_string = { E2 34 A1 C8 }
    condition:
        $my_text_string or $my_hex_string
}
""")

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
    files = {'file': (file_path, open(file_path, 'rb'))}
    response = requests.post(url, headers=headers, files=files)
    return response.json()

def scan_file_with_yara_and_virustotal(file_path):
    matches = rule.match(file_path)
    if matches:
        print(f"YARA match found: {matches[0].rule}")
        result = scan_with_virustotal(api_key, file_path)
        print(result)
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
file_path = 'archivo_prueba.txt'  # Especifica la ruta del archivo
scan_file_with_yara_and_virustotal(file_path)
