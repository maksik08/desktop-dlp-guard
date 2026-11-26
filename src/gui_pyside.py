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
    QLineEdit,
    QTableWidget,
    QTableWidgetItem,
    QHeaderView,
    QMessageBox,
    QGroupBox,
    QListWidget,
)

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from src.extractor import TextExtractor
from src.analyzer import DLPAnalyzer
from src.quarantine import QuarantineManager
from src.logger import AuditLogger


class FileAnalysisWorker(QThread):
    """Асинхронный анализ файла вне главного UI-потока."""
    log_ready = Signal(str, str)
    audit_updated = Signal()
    quarantine_updated = Signal()

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
            self.quarantine_updated.emit()

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


class ChatWorker(QThread):
    """Асинхронный запрос к локальному чату Ollama (Human-in-the-Loop)."""
    reply_ready = Signal(str)
    reply_error = Signal(str)

    def __init__(self, messages: list[dict], model: str = "llama3.2"):
        super().__init__()
        self.messages = messages
        self.model = model

    def run(self):
        try:
            payload = {
                "model": self.model,
                "messages": self.messages,
                "stream": False,
            }
            res = requests.post("http://localhost:11434/api/chat", json=payload, timeout=60)
            res.raise_for_status()
            data = res.json()
            content = data.get("message", {}).get("content", "").strip()
            if not content:
                self.reply_error.emit("Модель вернула пустой ответ.")
                return
            self.reply_ready.emit(content)
        except requests.ConnectionError:
            self.reply_error.emit("Сервер Ollama недоступен. Запустите его кнопкой «🤖 Запустить Ollama».")
        except Exception as e:
            self.reply_error.emit(f"Ошибка при обращении к модели: {e}")


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
        self.resize(1100, 760)
        self.setMinimumSize(900, 600)

        self.extractor = TextExtractor()
        self.analyzer = DLPAnalyzer()
        self.quarantine = QuarantineManager()
        self.logger = AuditLogger()

        self.watch_path = os.path.join(BASE_DIR, "test_folder")
        self.db_path = os.path.join(BASE_DIR, "logs", "dlp.db")

        self.observer = None
        self.is_running = False
        self._workers: list[QThread] = []
        self._chat_history: list[dict] = [
            {
                "role": "system",
                "content": (
                    "Ты ассистент безопасности системы DLP Guard. Помогай оператору анализировать "
                    "инциденты утечки данных, объяснять решения по уровню риска (LOW, HIGH, CRITICAL), "
                    "шифрование AES-256-GCM и безопасное уничтожение файлов (Secure Shredding). "
                    "Отвечай кратко, чётко и по делу на русском языке."
                ),
            }
        ]

        self._init_ui()
        self.file_event_detected.connect(self._on_file_event)

        self.refresh_logs()
        self.refresh_quarantine_list()
        self.check_ollama_status()

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

        # Вкладка 3: Ассистент безопасности (Human-in-the-Loop) + Карантин
        tab_hitl = QWidget()
        hitl_layout = QHBoxLayout(tab_hitl)

        # Левая часть: асинхронный чат с моделью
        chat_group = QGroupBox("Асинхронный AI-чат (Human-in-the-Loop)")
        chat_layout = QVBoxLayout(chat_group)

        quick_row = QHBoxLayout()
        btn_q1 = QPushButton("Сводка последних инцидентов")
        btn_q1.clicked.connect(lambda: self._send_preset_prompt(
            "Сделай краткую сводку по последним инцидентам безопасности из журнала и подскажи, какие действия требуются оператору."
        ))
        btn_q2 = QPushButton("Пояснить AES-256 и шредирование")
        btn_q2.clicked.connect(lambda: self._send_preset_prompt(
            "Кратко объясни, как защищены файлы в карантине с помощью AES-256-GCM и почему перед удалением применяется шредирование."
        ))
        quick_row.addWidget(btn_q1)
        quick_row.addWidget(btn_q2)
        chat_layout.addLayout(quick_row)

        self.chat_display = QTextEdit()
        self.chat_display.setReadOnly(True)
        self.chat_display.setFont(QFont("Segoe UI", 9))
        self.chat_display.append(
            "<i>Ассистент готов. Задайте вопрос по инцидентам или выберите файл справа для подтверждённого действия.</i>\n"
        )
        chat_layout.addWidget(self.chat_display)

        input_row = QHBoxLayout()
        self.chat_input = QLineEdit()
        self.chat_input.setPlaceholderText("Введите вопрос для AI-ассистента...")
        self.chat_input.returnPressed.connect(self.send_chat_message)
        input_row.addWidget(self.chat_input)

        self.btn_send_chat = QPushButton("Отправить")
        self.btn_send_chat.clicked.connect(self.send_chat_message)
        input_row.addWidget(self.btn_send_chat)
        chat_layout.addLayout(input_row)

        hitl_layout.addWidget(chat_group, stretch=3)

        # Правая часть: действия над карантином с подтверждением человека
        q_group = QGroupBox("Карантин (.enc) — подтверждение действий")
        q_layout = QVBoxLayout(q_group)

        btn_refresh_q = QPushButton("🔄 Обновить список карантина")
        btn_refresh_q.clicked.connect(self.refresh_quarantine_list)
        q_layout.addWidget(btn_refresh_q)

        self.quarantine_list = QListWidget()
        self.quarantine_list.setFont(QFont("Consolas", 8))
        q_layout.addWidget(self.quarantine_list)

        self.btn_decrypt = QPushButton("🔓 Расшифровать выбранный файл")
        self.btn_decrypt.clicked.connect(self.confirm_and_decrypt)
        q_layout.addWidget(self.btn_decrypt)

        self.btn_shred_enc = QPushButton("🔥 Безвозвратно уничтожить (.enc)")
        self.btn_shred_enc.setStyleSheet("color: #b71c1c; font-weight: bold;")
        self.btn_shred_enc.clicked.connect(self.confirm_and_shred)
        q_layout.addWidget(self.btn_shred_enc)

        hitl_layout.addWidget(q_group, stretch=2)

        self.tabs.addTab(tab_hitl, "🤖 AI-чат и карантин (HITL)")

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
        worker.quarantine_updated.connect(self.refresh_quarantine_list)
        worker.finished.connect(lambda w=worker: self._cleanup_worker(w))
        self._workers.append(worker)
        worker.start()

    def _cleanup_worker(self, worker: QThread):
        if worker in self._workers:
            self._workers.remove(worker)
        worker.deleteLater()

    def _get_recent_audit_context(self, limit: int = 5) -> str:
        if not os.path.exists(self.db_path):
            return "Журнал аудита пуст."
        try:
            with sqlite3.connect(self.db_path) as conn:
                cur = conn.cursor()
                cur.execute(
                    "SELECT timestamp, event_type, filename, status, details FROM audit_logs ORDER BY id DESC LIMIT ?",
                    (limit,),
                )
                rows = cur.fetchall()
            if not rows:
                return "Записей в журнале пока нет."
            return "\n".join(
                f"- [{r[0]}] {r[1]} | {r[2]} | {r[3]} | {r[4]}" for r in rows
            )
        except Exception as e:
            return f"Ошибка чтения журнала: {e}"

    def _send_preset_prompt(self, prompt: str):
        self.chat_input.setText(prompt)
        self.send_chat_message()

    def send_chat_message(self):
        user_text = self.chat_input.text().strip()
        if not user_text:
            return

        self.chat_input.clear()
        self.btn_send_chat.setEnabled(False)
        self.chat_display.append(f"<b>Оператор:</b> {user_text}")

        audit_ctx = self._get_recent_audit_context(limit=5)
        augmented_prompt = (
            f"Контекст последних записей аудита:\n{audit_ctx}\n\n"
            f"Вопрос оператора: {user_text}"
        )

        self._chat_history.append({"role": "user", "content": augmented_prompt})

        worker = ChatWorker(list(self._chat_history), model="llama3.2")
        worker.reply_ready.connect(self._on_chat_reply)
        worker.reply_error.connect(self._on_chat_error)
        worker.finished.connect(lambda: self.btn_send_chat.setEnabled(True))
        worker.finished.connect(lambda w=worker: self._cleanup_worker(w))
        self._workers.append(worker)
        worker.start()

    def _on_chat_reply(self, reply: str):
        self._chat_history.append({"role": "assistant", "content": reply})
        safe_reply = reply.replace("\n", "<br>")
        self.chat_display.append(f"<b>AI-ассистент:</b> {safe_reply}<br>")
        self.chat_display.ensureCursorVisible()

    def _on_chat_error(self, err: str):
        if self._chat_history and self._chat_history[-1]["role"] == "user":
            self._chat_history.pop()
        self.chat_display.append(f"<span style='color:#d32f2f;'><b>Ошибка:</b> {err}</span><br>")
        self.chat_display.ensureCursorVisible()

    def refresh_quarantine_list(self):
        self.quarantine_list.clear()
        q_dir = getattr(self.quarantine, "quarantine_dir", os.path.join(BASE_DIR, "quarantine"))

        if hasattr(self.quarantine, "list_quarantined"):
            enc_files = self.quarantine.list_quarantined()
        else:
            if not os.path.exists(q_dir):
                return
            enc_files = [
                os.path.join(q_dir, name)
                for name in sorted(os.listdir(q_dir))
                if os.path.isfile(os.path.join(q_dir, name)) and name.endswith(".enc")
            ]

        for enc_path in enc_files:
            self.quarantine_list.addItem(os.path.basename(enc_path))

    def _selected_enc_path(self) -> str | None:
        item = self.quarantine_list.currentItem()
        if not item:
            QMessageBox.information(self, "Выбор файла", "Выберите файл (.enc) в списке карантина.")
            return None
        return os.path.join(self.quarantine.quarantine_dir, item.text())

    def confirm_and_decrypt(self):
        enc_path = self._selected_enc_path()
        if not enc_path:
            return

        reply = QMessageBox.question(
            self,
            "Подтверждение оператора (Human-in-the-Loop)",
            f"Расшифровать файл из карантина?\n\n{os.path.basename(enc_path)}",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return

        try:
            restored = self.quarantine.decrypt_file(enc_path)
            self.append_log(f" [🔓 DECRYPT] Восстановлен файл: {restored}", "INFO")
            self.logger.log_event(
                "HITL_DECRYPT",
                restored,
                "INFO",
                f"Оператор подтвердил расшифровку контейнера {os.path.basename(enc_path)} -> {restored}",
            )
            self.refresh_logs()
            QMessageBox.information(self, "Готово", f"Файл расшифрован:\n{restored}")
        except Exception as e:
            QMessageBox.critical(self, "Ошибка расшифровки", f"Не удалось расшифровать файл:\n{e}")

    def confirm_and_shred(self):
        enc_path = self._selected_enc_path()
        if not enc_path:
            return

        reply = QMessageBox.warning(
            self,
            "Подтверждение уничтожения (Human-in-the-Loop)",
            f"Безвозвратно перезаписать и удалить файл из карантина?\n\n{os.path.basename(enc_path)}",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return

        ok = self.quarantine.shred_quarantined(enc_path)
        if ok:
            self.append_log(f" [🔥 SHRED_ENC] Безвозвратно уничтожен: {enc_path}", "CRITICAL")
            self.logger.log_event(
                "HITL_SHRED",
                enc_path,
                "CRITICAL",
                f"Оператор подтвердил безвозвратное уничтожение {os.path.basename(enc_path)}",
            )
            self.refresh_quarantine_list()
            self.refresh_logs()
            QMessageBox.information(self, "Готово", "Контейнер карантина безвозвратно уничтожен.")
        else:
            QMessageBox.critical(self, "Ошибка", "Не удалось уничтожить выбранный файл.")

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