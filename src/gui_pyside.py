import os
import sys
import time
import sqlite3
import subprocess
import requests

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.append(BASE_DIR)

from PySide6.QtCore import Qt, QThread, Signal, QTimer
from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import (
    QApplication,
    QMainWindow,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QPushButton,
    QLabel,
    QTabWidget,
    QTextEdit,
    QTableWidget,
    QTableWidgetItem,
    QHeaderView,
    QMessageBox,
    QGroupBox,
)

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from src.extractor import TextExtractor
from src.analyzer import DLPAnalyzer
from src.quarantine import QuarantineManager
from src.logger import AuditLogger


class FileAnalysisWorker(QThread):
    """Асинхронный анализ файла вне главного UI-потока."""
    log_ready = Signal(str, str)       # (message, level_tag)
    audit_updated = Signal()

    def __init__(self, event_type: str, file_path: str, extractor, analyzer, quarantine, logger):
        super().__init__()
        self.event_type = event_type
        self.file_path = file_path
        self.extractor = extractor
        self.analyzer = analyzer
        self.quarantine = quarantine
        self.logger = logger

    def run(self):
        time.sleep(0.3)
        if not os.path.exists(self.file_path):
            return

        filename = os.path.basename(self.file_path)
        self.log_ready.emit(f"\n[🔔 EVENT | {self.event_type}] Файл: {filename}", "INFO")

        text = self.extractor.extract_text(self.file_path)
        if not text:
            self.log_ready.emit(" [*] Пропущен (пустой или недоступный файл)", "INFO")
            return

        threat_level, regex_hits, ai_verdict = self.analyzer.evaluate(text)
        tag = threat_level if threat_level in ("HIGH", "CRITICAL") else "LOW"

        self.log_ready.emit(f" [🛡️ VERDICT] Угроза: {threat_level}", tag)
        if regex_hits:
            self.log_ready.emit(f"   └─ Regex совпадения: {regex_hits}", "HIGH")
        self.log_ready.emit(f"   └─ AI Анализ: {ai_verdict[:110]}...", tag)

        audit_details = ai_verdict

        if threat_level in ("HIGH", "CRITICAL"):
            enc_path = self.quarantine.isolate(self.file_path, threat_level)
            shredded = not os.path.exists(self.file_path)
            shred_status = "SHREDDED" if shredded else "SHRED_FAILED_OR_LOCKED"

            self.log_ready.emit(f" [🔐 AES-256] Зашифровано в карантин: {enc_path}", "CRITICAL")
            self.log_ready.emit(f" [🔥 SHRED] Статус уничтожения оригинала: {shred_status}", "CRITICAL")
            audit_details = f"{ai_verdict} | AES-256: {enc_path} | Orig: {shred_status}"

        self.logger.log_event(self.event_type, self.file_path, threat_level, audit_details)
        self.audit_updated.emit()


class OllamaStatusWorker(QThread):
    """Асинхронная проверка доступности локального сервера Ollama."""
    status_checked = Signal(bool)

    def run(self):
        try:
            res = requests.get("http://localhost:11434/", timeout=2)
            self.status_checked.emit(res.status_code == 200)
        except Exception:
            self.status_checked.emit(False)


class QtWatchdogHandler(FileSystemEventHandler):
    """Обработчик событий watchdog, передающий задачи в сигналы Qt."""
    def __init__(self, window: "DLPMainWindow"):
        super().__init__()
        self.window = window
        self._last_processed = {}

    def on_created(self, event):
        if not event.is_directory:
            self._dispatch("CREATED", event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            self._dispatch("MODIFIED", event.src_path)

    def on_moved(self, event):
        if not event.is_directory:
            self._dispatch("MOVED/RENAMED", event.dest_path)

    def _dispatch(self, event_type: str, file_path: str):
        now = time.time()
        if now - self._last_processed.get(file_path, 0) < 1.5:
            return
        self._last_processed[file_path] = now
        self.window.file_event_detected.emit(event_type, file_path)


class DLPMainWindow(QMainWindow):
    file_event_detected = Signal(str, str)

    def __init__(self):
        super().__init__()
        self.setWindowTitle("🛡️ Desktop Sentinel & DLP Guard (PySide6)")
        self.resize(1040, 720)
        self.setMinimumSize(880, 560)

        self.extractor = TextExtractor()
        self.analyzer = DLPAnalyzer()
        self.quarantine = QuarantineManager()
        self.logger = AuditLogger()

        self.watch_path = os.path.join(BASE_DIR, "test_folder")
        self.db_path = os.path.join(BASE_DIR, "logs", "dlp.db")

        self.observer = None
        self.is_running = False
        self._workers: list[QThread] = []

        self._init_ui()
        self.file_event_detected.connect(self._on_file_event)

        self.refresh_logs()
        self.check_ollama_status()

        # Периодическая проверка статуса Ollama каждые 10 секунд
        self.ollama_timer = QTimer(self)
        self.ollama_timer.timeout.connect(self.check_ollama_status)
        self.ollama_timer.start(10000)

    def _init_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        root_layout = QVBoxLayout(central)

        # Верхняя панель управления
        top_group = QGroupBox("Управление системой и ИИ")
        top_layout = QHBoxLayout(top_group)

        self.btn_toggle = QPushButton("▶ Запустить мониторинг")
        self.btn_toggle.clicked.connect(self.toggle_monitoring)
        top_layout.addWidget(self.btn_toggle)

        self.lbl_status = QLabel("Статус: ОСТАНОВЛЕН")
        self.lbl_status.setStyleSheet("color: #d32f2f; font-weight: bold;")
        top_layout.addWidget(self.lbl_status)

        self.btn_ollama = QPushButton("🤖 Запустить Ollama")
        self.btn_ollama.clicked.connect(self.start_ollama_service)
        top_layout.addWidget(self.btn_ollama)

        self.lbl_ollama = QLabel("ИИ: Проверка...")
        self.lbl_ollama.setStyleSheet("color: #ef6c00; font-weight: bold;")
        top_layout.addWidget(self.lbl_ollama)

        top_layout.addStretch()

        lbl_folder = QLabel(f"Папка: {os.path.basename(self.watch_path)}")
        lbl_folder.setFont(QFont("Consolas", 9))
        top_layout.addWidget(lbl_folder)

        root_layout.addWidget(top_group)

        # Вкладки
        self.tabs = QTabWidget()
        root_layout.addWidget(self.tabs)

        # Вкладка 1: Монитор событий
        tab_live = QWidget()
        live_layout = QVBoxLayout(tab_live)

        self.log_area = QTextEdit()
        self.log_area.setReadOnly(True)
        self.log_area.setFont(QFont("Consolas", 9))
        self.log_area.setStyleSheet("background-color: #1e1e1e; color: #d4d4d4;")
        live_layout.addWidget(self.log_area)

        self.tabs.addTab(tab_live, "📡 Монитор событий")

        # Вкладка 2: Журнал аудита (SQLite)
        tab_db = QWidget()
        db_layout = QVBoxLayout(tab_db)

        db_top = QHBoxLayout()
        db_top.addStretch()
        btn_refresh = QPushButton("🔄 Обновить базу данных")
        btn_refresh.clicked.connect(self.refresh_logs)
        db_top.addWidget(btn_refresh)
        db_layout.addLayout(db_top)

        self.table = QTableWidget()
        self.table.setColumnCount(6)
        self.table.setHorizontalHeaderLabels(["ID", "Дата и время", "Событие", "Имя файла", "Угроза", "Детали / AES-256"])
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        db_layout.addWidget(self.table)

        self.tabs.addTab(tab_db, "💾 Журнал аудита (SQLite)")

    def append_log(self, message: str, tag: str = "INFO"):
        color_map = {
            "INFO": QColor("#8be9fd"),
            "LOW": QColor("#50fa7b"),
            "HIGH": QColor("#ff79c6"),
            "CRITICAL": QColor("#ff5555"),
        }
        cursor = self.log_area.textCursor()
        cursor.movePosition(cursor.MoveOperation.End)

        fmt = cursor.charFormat()
        fmt.setForeground(color_map.get(tag, QColor("#d4d4d4")))
        fmt.setFontWeight(QFont.Weight.Bold if tag in ("HIGH", "CRITICAL") else QFont.Weight.Normal)
        cursor.setCharFormat(fmt)
        cursor.insertText(message + "\n")

        self.log_area.setTextCursor(cursor)
        self.log_area.ensureCursorVisible()

    def check_ollama_status(self):
        worker = OllamaStatusWorker(self)
        worker.status_checked.connect(self._on_ollama_status)
        worker.finished.connect(lambda w=worker: self._cleanup_worker(w))
        self._workers.append(worker)
        worker.start()

    def _on_ollama_status(self, active: bool):
        if active:
            self.lbl_ollama.setText("ИИ: АКТИВЕН")
            self.lbl_ollama.setStyleSheet("color: #2e7d32; font-weight: bold;")
        else:
            self.lbl_ollama.setText("ИИ: ОТКЛЮЧЕН")
            self.lbl_ollama.setStyleSheet("color: #d32f2f; font-weight: bold;")

    def start_ollama_service(self):
        try:
            self.append_log("[SYSTEM] Запуск локального сервера Ollama...", "INFO")
            creation_flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
            subprocess.Popen(["ollama", "serve"], creationflags=creation_flags)
            QTimer.singleShot(3000, self.check_ollama_status)
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось запустить Ollama:\n{e}")

    def toggle_monitoring(self):
        if not self.is_running:
            self.start_monitoring()
        else:
            self.stop_monitoring()

    def start_monitoring(self):
        os.makedirs(self.watch_path, exist_ok=True)
        handler = QtWatchdogHandler(self)
        self.observer = Observer()
        self.observer.schedule(handler, path=self.watch_path, recursive=False)
        self.observer.start()

        self.is_running = True
        self.btn_toggle.setText("⏹ Остановить")
        self.lbl_status.setText("Статус: АКТИВЕН")
        self.lbl_status.setStyleSheet("color: #2e7d32; font-weight: bold;")
        self.append_log(f"[SYSTEM] Мониторинг запущен для каталога: {self.watch_path}", "INFO")

    def stop_monitoring(self):
        if self.observer:
            self.observer.stop()
            self.observer.join()
            self.observer = None

        self.is_running = False
        self.btn_toggle.setText("▶ Запустить мониторинг")
        self.lbl_status.setText("Статус: ОСТАНОВЛЕН")
        self.lbl_status.setStyleSheet("color: #d32f2f; font-weight: bold;")
        self.append_log("[SYSTEM] Мониторинг остановлен.", "INFO")

    def _on_file_event(self, event_type: str, file_path: str):
        worker = FileAnalysisWorker(
            event_type=event_type,
            file_path=file_path,
            extractor=self.extractor,
            analyzer=self.analyzer,
            quarantine=self.quarantine,
            logger=self.logger,
        )
        worker.log_ready.connect(self.append_log)
        worker.audit_updated.connect(self.refresh_logs)
        worker.finished.connect(lambda w=worker: self._cleanup_worker(w))
        self._workers.append(worker)
        worker.start()

    def _cleanup_worker(self, worker: QThread):
        if worker in self._workers:
            self._workers.remove(worker)
        worker.deleteLater()

    def refresh_logs(self):
        self.table.setRowCount(0)
        if not os.path.exists(self.db_path):
            return

        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT id, timestamp, event_type, filename, status, details FROM audit_logs ORDER BY id DESC"
                )
                rows = cursor.fetchall()

            self.table.setRowCount(len(rows))
            for r_idx, row in enumerate(rows):
                for c_idx, val in enumerate(row):
                    item = QTableWidgetItem("" if val is None else str(val))
                    if c_idx in (0, 2, 4):
                        item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                    self.table.setItem(r_idx, c_idx, item)
        except Exception as e:
            QMessageBox.critical(self, "Ошибка БД", f"Не удалось прочитать базу данных:\n{e}")

    def closeEvent(self, event):
        if self.is_running:
            self.stop_monitoring()

        reply = QMessageBox.question(
            self,
            "Выход",
            "Остановить также фоновый сервер Ollama для экономии памяти?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if reply == QMessageBox.StandardButton.Yes:
            try:
                if os.name == "nt":
                    os.system("taskkill /f /im ollama.exe >nul 2>&1")
                    os.system("taskkill /f /im ollama_llama_server.exe >nul 2>&1")
                else:
                    os.system("pkill ollama")
            except Exception:
                pass

        event.accept()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    win = DLPMainWindow()
    win.show()
    sys.exit(app.exec())