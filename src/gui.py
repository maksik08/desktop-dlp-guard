import os
import sys
import threading
import sqlite3
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext

# Добавляем корневую папку в путь поиска модулей
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(BASE_DIR)

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from src.extractor import TextExtractor
from src.analyzer import DLPAnalyzer
from src.quarantine import QuarantineManager
from src.logger import AuditLogger


class DLPApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("🛡️ Desktop Sentinel & DLP Guard")
        self.geometry("950x650")
        self.minsize(800, 500)

        # Компоненты DLP
        self.extractor = TextExtractor()
        self.analyzer = DLPAnalyzer()
        self.quarantine = QuarantineManager()
        self.logger = AuditLogger()

        # Пути
        self.watch_path = os.path.join(BASE_DIR, "test_folder")
        self.db_path = os.path.join(BASE_DIR, "logs", "dlp.db")

        self.observer = None
        self.is_running = False

        self.style = ttk.Style()
        self.style.theme_use("clam")

        self._create_widgets()
        self.refresh_logs()

    def _create_widgets(self):
        # Панель управления
        top_frame = ttk.LabelFrame(self, text=" Управление DLP-службой ")
        top_frame.pack(fill="x", padx=10, pady=5)

        self.btn_toggle = ttk.Button(top_frame, text="▶ Запустить мониторинг", command=self.toggle_monitoring)
        self.btn_toggle.pack(side="left", padx=10, pady=10)

        self.lbl_status = ttk.Label(top_frame, text="Статус: ОСТАНОВЛЕН", font=("Segoe UI", 10, "bold"),
                                    foreground="red")
        self.lbl_status.pack(side="left", padx=10)

        lbl_folder = ttk.Label(top_frame, text=f"Папка: {self.watch_path}", font=("Consolas", 9))
        lbl_folder.pack(side="right", padx=10)

        # Вкладки
        notebook = ttk.Notebook(self)
        notebook.pack(fill="both", expand=True, padx=10, pady=5)

        # Вкладка 1: Логи в реальном времени
        tab_live = ttk.Frame(notebook)
        notebook.add(tab_live, text=" 📡 Монитор событий ")

        self.log_area = scrolledtext.ScrolledText(tab_live, wrap=tk.WORD, font=("Consolas", 9), bg="#1e1e1e",
                                                  fg="#d4d4d4")
        self.log_area.pack(fill="both", expand=True, padx=5, pady=5)

        self.log_area.tag_config("HIGH", foreground="#ff5555", font=("Consolas", 9, "bold"))
        self.log_area.tag_config("CRITICAL", foreground="#ff0000", font=("Consolas", 9, "bold"))
        self.log_area.tag_config("LOW", foreground="#50fa7b")
        self.log_area.tag_config("INFO", foreground="#8be9fd")

        # Вкладка 2: База данных SQLite
        tab_db = ttk.Frame(notebook)
        notebook.add(tab_db, text=" 💾 Журнал аудита (SQLite) ")

        btn_refresh = ttk.Button(tab_db, text="🔄 Обновить базу данных", command=self.refresh_logs)
        btn_refresh.pack(anchor="ne", padx=10, pady=5)

        columns = ("id", "timestamp", "event", "file", "status")
        self.tree = ttk.Treeview(tab_db, columns=columns, show="headings")
        self.tree.heading("id", text="ID")
        self.tree.heading("timestamp", text="Дата и время")
        self.tree.heading("event", text="Событие")
        self.tree.heading("file", text="Имя файла")
        self.tree.heading("status", text="Статус угрозы")

        self.tree.column("id", width=40, anchor="center")
        self.tree.column("timestamp", width=160, anchor="center")
        self.tree.column("event", width=120, anchor="center")
        self.tree.column("file", width=260)
        self.tree.column("status", width=130, anchor="center")

        self.tree.pack(fill="both", expand=True, padx=5, pady=5)

    def log_message(self, message: str, tag: str = "INFO"):
        self.log_area.insert(tk.END, message + "\n", tag)
        self.log_area.see(tk.END)

    def toggle_monitoring(self):
        if not self.is_running:
            self.start_monitoring()
        else:
            self.stop_monitoring()

    def start_monitoring(self):
        if not os.path.exists(self.watch_path):
            os.makedirs(self.watch_path)

        event_handler = GUIWatchdogHandler(self)
        self.observer = Observer()
        self.observer.schedule(event_handler, path=self.watch_path, recursive=False)
        self.observer.start()

        self.is_running = True
        self.lbl_status.config(text="Статус: АКТИВЕН", foreground="green")
        self.btn_toggle.config(text="⏹ Остановить")
        self.log_message(f"[SYSTEM] Мониторинг запущен для каталога: {self.watch_path}", "INFO")

    def stop_monitoring(self):
        if self.observer:
            self.observer.stop()
            self.observer.join()

        self.is_running = False
        self.lbl_status.config(text="Статус: ОСТАНОВЛЕН", foreground="red")
        self.btn_toggle.config(text="▶ Запустить мониторинг")
        self.log_message("[SYSTEM] Мониторинг остановлен.", "INFO")

    def refresh_logs(self):
        for item in self.tree.get_children():
            self.tree.delete(item)

        if not os.path.exists(self.db_path):
            return

        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT id, timestamp, event_type, filename, status FROM audit_logs ORDER BY id DESC")
                for row in cursor.fetchall():
                    self.tree.insert("", tk.END, values=row)
        except Exception as e:
            messagebox.showerror("Ошибка БД", f"Не удалось прочитать базу данных: {e}")


class GUIWatchdogHandler(FileSystemEventHandler):
    def __init__(self, app: DLPApp):
        self.app = app

    def on_created(self, event):
        if not event.is_directory:
            self.process_event("CREATED", event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            self.process_event("MODIFIED", event.src_path)

    def on_moved(self, event):
        if not event.is_directory:
            self.process_event("MOVED/RENAMED", event.dest_path)

    def process_event(self, event_type: str, file_path: str):
        # Запускаем в отдельном потоке, чтобы GUI не зависал во время запроса к Ollama
        threading.Thread(target=self._analyze_file, args=(event_type, file_path), daemon=True).start()

    def _analyze_file(self, event_type: str, file_path: str):
        filename = os.path.basename(file_path)
        self.app.log_message(f"\n[🔔 EVENT | {event_type}] Файл: {filename}", "INFO")

        # 1. Извлечение текста
        text = self.app.extractor.extract_text(file_path)
        if not text:
            self.app.log_message(" [*] Пропущен (пустой или недоступный файл)", "INFO")
            return

        # 2. Анализ (Regex + Ollama)
        threat_level, regex_hits, ai_verdict = self.app.analyzer.evaluate(text)

        tag = "LOW"
        if threat_level in ["HIGH", "CRITICAL"]:
            tag = threat_level

        self.app.log_message(f" [🛡️ VERDICT] Угроза: {threat_level}", tag)
        if regex_hits:
            self.app.log_message(f"   └─ Regex совпадения: {regex_hits}", "HIGH")
        self.app.log_message(f"   └─ AI Анализ: {ai_verdict[:90]}...", tag)

        # 3. Карантин при угрозе
        if threat_level in ["HIGH", "CRITICAL"]:
            isolated_path = self.app.quarantine.isolate(file_path, threat_level)
            self.app.log_message(f" [🚨 QUARANTINE] Файл изолирован: {isolated_path}", "CRITICAL")

        # 4. Логирование в SQLite
        self.app.logger.log_event(event_type, file_path, threat_level, ai_verdict)

        # 5. Обновление таблицы в GUI
        self.app.refresh_logs()


if __name__ == "__main__":
    app = DLPApp()
    app.mainloop()