import os
from datetime import datetime


class AuditLogger:
    """Модуль аудита и логирования событий DLP-системы."""

    def __init__(self, log_dir="logs", log_filename="dlp_audit.log"):
        self.log_dir = log_dir
        self.log_path = os.path.join(log_dir, log_filename)
        self._ensure_log_dir()

    def _ensure_log_dir(self):
        if not os.path.exists(self.log_dir):
            os.makedirs(self.log_dir)

    def log_event(self, event_type: str, file_path: str, file_size: float, status: str, details: str = ""):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        filename = os.path.basename(file_path)

        log_entry = (
            f"[{timestamp}] | EVENT: {event_type.upper()} | "
            f"FILE: {filename} | PATH: {file_path} | "
            f"SIZE: {file_size:.2f} KB | STATUS: {status} | DETAILS: {details}\n"
        )

        try:
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(log_entry)
        except Exception as e:
            print(f"[!] Ошибка записи в лог: {e}")