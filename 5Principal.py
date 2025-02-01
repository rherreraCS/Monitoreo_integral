 
import logging
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import time
import requests

# Configuración del correo electrónico
mailgun_api_key = '9c3f0c68-e6f5e16f'
mailgun_domain = 'sandboxac4cee97048342b380a07e56f6e417b2.mailgun.org'
email_sender = 'rherrera.ciberseguridad@gmail.com'
email_receiver = 'rhsecure@zohomail.eu'

def send_email(subject, body):
    print(f'Enviando correo: {subject} - {body}')
    try:
        response = requests.post(
            f"https://api.mailgun.net/v3/{mailgun_domain}/messages",
            auth=("api", mailgun_api_key),
            data={"from": email_sender,
                  "to": [email_receiver],
                  "subject": subject,
                  "text": body})
        print(f'Respuesta del correo: {response.status_code} - {response.text}')
        if response.status_code != 200:
            logging.error(f'Error al enviar correo: {response.status_code} - {response.text}')
    except Exception as e:
        logging.error(f'Error al enviar correo: {e}')
        print(f'Error al enviar correo: {e}')

class MonitorHandler(FileSystemEventHandler):
    def on_modified(self, event):
        logging.info(f'Archivo modificado: {event.src_path}')
        print(f'Evento detectado - Modificado: {event.src_path}')
        send_email('Archivo modificado', f'Archivo modificado en: {event.src_path}')

    def on_created(self, event):
        logging.info(f'Archivo creado: {event.src_path}')
        print(f'Evento detectado - Creado: {event.src_path}')
        send_email('Archivo creado', f'Archivo creado en: {event.src_path}')

    def on_deleted(self, event):
        logging.info(f'Archivo eliminado: {event.src_path}')
        print(f'Evento detectado - Eliminado: {event.src_path}')
        send_email('Archivo eliminado', f'Archivo eliminado en: {event.src_path}')

if __name__ == "__main__":
    # Configuración del registro de eventos en un archivo de log
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
