import logging
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import time

class MonitorHandler(FileSystemEventHandler):
    def on_modified(self, event):
        logging.info(f'Archivo modificado: {event.src_path}')

    def on_created(self, event):
        logging.info(f'Archivo creado: {event.src_path}')

    def on_deleted(self, event):
        logging.info(f'Archivo eliminado: {event.src_path}')

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
