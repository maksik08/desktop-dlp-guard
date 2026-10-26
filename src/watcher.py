import os
import time
from datetime import datetime
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from src.config import IGNORED_EXTENSIONS, IGNORED_PREFIXES, MAX_FILE_SIZE_BYTES
from src.extractor import TextExtractor


class AdvancedFileHandler(FileSystemEventHandler):


    def _should_ignore(self, file_path: str) -> bool:
        filename = os.path.basename(file_path)

        #  Проверка на системные/временные префиксы
        if any(filename.startswith(prefix) for prefix in IGNORED_PREFIXES):
            return True

        #  Проверка на временные расширения
        ext = os.path.splitext(filename)[1].lower()
        if ext in IGNORED_EXTENSIONS:
            return True

        #  Проверка существования файла на диске
        if not os.path.exists(file_path):
            return True

        #  Проверка размера файла
        try:
            file_size = os.path.getsize(file_path)
            if file_size > MAX_FILE_SIZE_BYTES:
                print(f"[⚠️ IGNORE] Файл слишком большой ({file_size / (1024 * 1024):.1f} МБ): {filename}")
                return True
        except OSError:
            return True

        return False

    def _process_file(self, event_type: str, file_path: str):
        if self._should_ignore(file_path):
            return

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        filename = os.path.basename(file_path)
        file_size_kb = os.path.getsize(file_path) / 1024

        print(f"\n[🔔 EVENT | {timestamp}] [{event_type.upper()}]")
        print(f" ├─ Файл: {filename}")
        print(f" ├─ Путь: {file_path}")
        print(f" └─ Размер: {file_size_kb:.2f} KB")

        print(f" [*] Запуск извлечения текста (Lab 2)...")
        extracted_text = TextExtractor.extract_text(file_path)

        if extracted_text:
            preview = extracted_text.strip().replace('\n', ' ')
            if len(preview) > 100:
                preview = preview[:100] + "..."
            print(f" [📄 EXTRACTED TEXT] -> \"{preview}\"")
        else:
            print(f" [ℹ️] Текст не найден или формат не поддерживается для чтения.")

        time.sleep(0.3)

    def on_created(self, event):
        if not event.is_directory:
            self._process_file("Created", event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            self._process_file("Modified", event.src_path)

    def on_moved(self, event):
        if not event.is_directory:
            self._process_file("Moved/Renamed", event.dest_path)


class DLPWatcher:
    "Класс управления экземплярами Observer для отслеживания директорий."

    def __init__(self, watch_paths: list):
        self.watch_paths = watch_paths
        self.observer = Observer()
        self.handler = AdvancedFileHandler()

    def start(self):
        for path in self.watch_paths:
            if os.path.exists(path):
                self.observer.schedule(self.handler, path=path, recursive=False)
                print(f"[+] Мониторинг подключен к папке: {path}")
            else:
                print(f"[!] Папка не найдена, пропускаем: {path}")

        self.observer.start()
        print("\n[*] Служба DLP Watcher успешно запущена.")
        print("[*] Нажмите Ctrl+C для завершения работы.\n" + "-" * 50)

        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            self.stop()

    def stop(self):
        print("\n[*] Остановка службы DLP Watcher...")
        self.observer.stop()
        self.observer.join()
        print("[*] Мониторинг завершен.")