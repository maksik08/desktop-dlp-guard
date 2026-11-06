import os
import sqlite3
from datetime import datetime


class AuditLogger:

    def __init__(self, db_dir="logs", db_filename="dlp.db"):
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.db_dir = os.path.join(base_dir, db_dir)
        self.db_path = os.path.join(self.db_dir, db_filename)
        self._ensure_db_dir()
        self._init_db()

    def _ensure_db_dir(self):
        if not os.path.exists(self.db_dir):
            try:
                os.makedirs(self.db_dir)
            except Exception:
                pass

    def _init_db(self):
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS audit_logs (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TEXT,
                        event_type TEXT,
                        filename TEXT,
                        file_path TEXT,
                        file_size REAL,
                        status TEXT,
                        details TEXT
                    )
                """)
                conn.commit()
        except Exception as e:
            print(f"[!] Ошибка инициализации БД: {e}")

    def log_event(self, event_type: str, file_path: str, file_size: float, status: str, details: str = ""):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        filename = os.path.basename(file_path)

        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO audit_logs (timestamp, event_type, filename, file_path, file_size, status, details)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (timestamp, event_type.upper(), filename, file_path, file_size, status, details))
                conn.commit()
            print(f" [💾 SQLITE] Событие записано в базу данных: {self.db_path}")
        except Exception as e:
            print(f"[!] Ошибка записи в БД: {e}")