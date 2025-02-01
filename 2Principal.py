 
import logging
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import time
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Configuración del correo electrónico
email_sender = 'rhsecure@zohomail.eu'
email_password = '0640Rhp635/'
email_receiver = 'rherrera.ciberseguridad@gmail.com'
smtp_server = 'smtp.zoho.eu'
smtp_port = 587

def send_email(subject, body):
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
    except Exception as e:
        print(f'Error al enviar correo: {e}')

class MonitorHandler(FileSystemEventHandler):
    def on_modified(self, event):
        logging.info(f'Archivo modificado: {event.src_path}')
        send_email('Archivo modificado', f'Archivo modificado: {event.src_path}')

    def on_created(self, event):
        logging.info(f'Archivo creado: {event.src_path}')
        send_email('Archivo creado', f'Archivo creado: {event.src_path}')

    def on_deleted(self, event):
        logging.info(f'Archivo eliminado: {event.src_path}')
        send_email('Archivo eliminado', f'Archivo eliminado: {event.src_path}')

if __name__ == "__main__":
    # Configuración del registro de eventos en un archivo de log
    logging.basicConfig(filename='file_monitor.log', level=logging.INFO, format='%(asctime)s - %(message)s')

    path = "."  # Directorio a monitorear
    event_handler = MonitorHandler()
    observer = Observer()
    observer.schedule(event_handler, path, recursive=True)
    observer.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

