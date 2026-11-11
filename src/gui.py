import os
import sys
import threading
import sqlite3
import subprocess
import requests
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext

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
        self.geometry("980x680")
        self.minsize(850, 520)

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

        self.check_ollama_status()

        self.protocol("WM_DELETE_WINDOW", self.on_closing)

    def _create_widgets(self):
        top_frame = ttk.LabelFrame(self, text=" Управление системой и ИИ ")
        top_frame.pack(fill="x", padx=10, pady=5)

        self.btn_toggle = ttk.Button(top_frame, text="▶ Запустить мониторинг", command=self.toggle_monitoring)
        self.btn_toggle.pack(side="left", padx=8, pady=10)

        self.lbl_status = ttk.Label(top_frame, text="Статус: ОСТАНОВЛЕН", font=("Segoe UI", 9, "bold"),
                                    foreground="red")
        self.lbl_status.pack(side="left", padx=5)

        ttk.Separator(top_frame, orient="vertical").pack(side="left", fill="y", padx=10, pady=5)

        self.btn_ollama = ttk.Button(top_frame, text="🤖 Запустить Ollama", command=self.start_ollama_service)
        self.btn_ollama.pack(side="left", padx=5)

        self.lbl_ollama = ttk.Label(top_frame, text="ИИ: Проверка...", font=("Segoe UI", 9, "bold"),
                                    foreground="orange")
        self.lbl_ollama.pack(side="left", padx=5)

        lbl_folder = ttk.Label(top_frame, text=f"Папка: test_folder", font=("Consolas", 9))
        lbl_folder.pack(side="right", padx=10)

        notebook = ttk.Notebook(self)
        notebook.pack(fill="both", expand=True, padx=10, pady=5)

        tab_live = ttk.Frame(notebook)
        notebook.add(tab_live, text=" 📡 Монитор событий ")

        self.log_area = scrolledtext.ScrolledText(tab_live, wrap=tk.WORD, font=("Consolas", 9), bg="#1e1e1e",
                                                  fg="#d4d4d4")
        self.log_area.pack(fill="both", expand=True, padx=5, pady=5)

        self.log_area.tag_config("HIGH", foreground="#ff5555", font=("Consolas", 9, "bold"))
        self.log_area.tag_config("CRITICAL", foreground="#ff0000", font=("Consolas", 9, "bold"))
        self.log_area.tag_config("LOW", foreground="#50fa7b")
        self.log_area.tag_config("INFO", foreground="#8be9fd")

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

    def check_ollama_status(self):
        """Проверяет, запущен ли локальный сервер Ollama."""

        def _ping():
            try:
                res = requests.get("http://localhost:11434/", timeout=2)
                if res.status_code == 200:
                    self.after(0, lambda: self.lbl_ollama.config(text="ИИ: АКТИВЕН", foreground="green"))
                else:
                    self.after(0, lambda: self.lbl_ollama.config(text="ИИ: ОТКЛЮЧЕН", foreground="red"))
            except:
                self.after(0, lambda: self.lbl_ollama.config(text="ИИ: ОТКЛЮЧЕН", foreground="red"))

        threading.Thread(target=_ping, daemon=True).start()

    def start_ollama_service(self):
        """Запускает Ollama в фоновом режиме прямо из приложения."""

        def _run():
            try:
                self.log_message("[SYSTEM] Запуск локального сервера Ollama...", "INFO")
                creation_flags = subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
                subprocess.Popen(["ollama", "serve"], creationflags=creation_flags)

                import time
                time.sleep(3)
                self.check_ollama_status()
                self.log_message("[SYSTEM] Сервер Ollama успешно инициирован.", "INFO")
            except Exception as e:
                self.after(0, lambda: messagebox.showerror("Ошибка", f"Не удалось запустить Ollama:\n{e}"))

        threading.Thread(target=_run, daemon=True).start()

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
            self.check_ollama_status()
        except Exception as e:
            messagebox.showerror("Ошибка БД", f"Не удалось прочитать базу данных: {e}")

    def on_closing(self):
        """Срабатывает при закрытии приложения (нажатии на крестик)."""
        if self.is_running:
            self.stop_monitoring()

        if messagebox.askyesno("Выход", "Остановить также фоновый сервер Ollama для экономии памяти?"):
            try:
                if os.name == 'nt':
                    os.system("taskkill /f /im ollama.exe >nul 2>&1")
                    os.system("taskkill /f /im ollama_llama_server.exe >nul 2>&1")
                else:
                    os.system("pkill ollama")
            except Exception:
                pass

        self.destroy()


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
        threading.Thread(target=self._analyze_file, args=(event_type, file_path), daemon=True).start()

    def _analyze_file(self, event_type: str, file_path: str):
        filename = os.path.basename(file_path)
        self.app.log_message(f"\n[🔔 EVENT | {event_type}] Файл: {filename}", "INFO")

        text = self.app.extractor.extract_text(file_path)
        if not text:
            self.app.log_message(" [*] Пропущен (пустой или недоступный файл)", "INFO")
            return

        threat_level, regex_hits, ai_verdict = self.app.analyzer.evaluate(text)

        tag = "LOW"
        if threat_level in ["HIGH", "CRITICAL"]:
            tag = threat_level

        self.app.log_message(f" [🛡️ VERDICT] Угроза: {threat_level}", tag)
        if regex_hits:
            self.app.log_message(f"   └─ Regex совпадения: {regex_hits}", "HIGH")
        self.app.log_message(f"   └─ AI Анализ: {ai_verdict[:90]}...", tag)

        if threat_level in ["HIGH", "CRITICAL"]:
            isolated_path = self.app.quarantine.isolate(file_path, threat_level)
            self.app.log_message(f" [🚨 QUARANTINE] Файл изолирован: {isolated_path}", "CRITICAL")

        self.app.logger.log_event(event_type, file_path, threat_level, ai_verdict)


        self.app.after(0, self.app.refresh_logs)


if __name__ == "__main__":
    app = DLPApp()
    app.mainloop()