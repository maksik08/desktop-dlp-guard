import os
import re
import sys
import json
import time
import sqlite3
import subprocess
from datetime import datetime
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
    QFrame,
    QPushButton,
    QLabel,
    QTabWidget,
    QTextEdit,
    QLineEdit,
    QComboBox,
    QFileDialog,
    QTableWidget,
    QTableWidgetItem,
    QHeaderView,
    QMessageBox,
    QGroupBox,
    QListWidget,
    QListWidgetItem,
    QSplitter,
    QDialog,
)

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from src.extractor import TextExtractor
from src.analyzer import DLPAnalyzer
from src.quarantine import QuarantineManager
from src.logger import AuditLogger


APP_QSS = """
QMainWindow, QWidget {
    background-color: #f4f6f9;
    color: #1f2937;
    font-family: "Segoe UI", sans-serif;
    font-size: 10pt;
}

QGroupBox {
    background-color: #ffffff;
    border: 1px solid #e2e8f0;
    border-radius: 10px;
    margin-top: 10px;
    padding: 12px;
    font-weight: 600;
}

QGroupBox::title {
    subcontrol-origin: margin;
    left: 12px;
    padding: 0 6px;
    color: #334155;
}

QFrame#MetricCard {
    background-color: #ffffff;
    border: 1px solid #e2e8f0;
    border-radius: 10px;
    padding: 10px 14px;
}

QLabel#MetricTitle {
    color: #64748b;
    font-size: 8.5pt;
    font-weight: 600;
}

QLabel#MetricValue {
    color: #0f172a;
    font-size: 16pt;
    font-weight: 700;
}

QLabel#MetricValueDanger {
    color: #dc2626;
    font-size: 16pt;
    font-weight: 700;
}

QLabel#MetricValueAccent {
    color: #1d4ed8;
    font-size: 16pt;
    font-weight: 700;
}

QPushButton {
    background-color: #2563eb;
    color: #ffffff;
    border: none;
    border-radius: 7px;
    padding: 7px 13px;
    font-weight: 600;
}

QPushButton:hover {
    background-color: #1d4ed8;
}

QPushButton:pressed {
    background-color: #1e40af;
}

QPushButton:disabled {
    background-color: #94a3b8;
}

QPushButton:checked {
    background-color: #1e3a8a;
    border: 1px solid #93c5fd;
}

QPushButton#SecondaryBtn {
    background-color: #e2e8f0;
    color: #1e293b;
}

QPushButton#SecondaryBtn:hover {
    background-color: #cbd5e1;
}

QPushButton#SecondaryBtn:checked {
    background-color: #dbeafe;
    color: #1d4ed8;
    border: 1px solid #93c5fd;
}

QPushButton#DangerBtn {
    background-color: #dc2626;
    color: #ffffff;
}

QPushButton#DangerBtn:hover {
    background-color: #b91c1c;
}

QLineEdit, QComboBox, QListWidget {
    background-color: #ffffff;
    border: 1px solid #cbd5e1;
    border-radius: 7px;
    padding: 6px 10px;
}

QLineEdit:focus, QComboBox:focus, QListWidget:focus {
    border: 1px solid #2563eb;
}

QTabWidget::pane {
    background-color: #ffffff;
    border: 1px solid #e2e8f0;
    border-radius: 10px;
    top: -1px;
}

QTabBar::tab {
    background-color: #e2e8f0;
    color: #475569;
    border-top-left-radius: 8px;
    border-top-right-radius: 8px;
    padding: 8px 16px;
    margin-right: 4px;
    font-weight: 600;
}

QTabBar::tab:selected {
    background-color: #ffffff;
    color: #2563eb;
    border: 1px solid #e2e8f0;
    border-bottom-color: #ffffff;
}

QTableWidget {
    background-color: #ffffff;
    border: 1px solid #e2e8f0;
    border-radius: 8px;
    gridline-color: #e2e8f0;
}

QHeaderView::section {
    background-color: #f8fafc;
    color: #334155;
    padding: 6px;
    border: none;
    border-bottom: 1px solid #cbd5e1;
    font-weight: 600;
}
"""

SKIP_DIRS = {".git", "__pycache__", ".venv", "venv", "node_modules", "quarantine", ".keys"}
ASCII_PRINTABLE_RE = re.compile(rb"[ -~]{4,}")
UTF16_PRINTABLE_RE = re.compile(b"(?:[ -~]\x00){4,}")
HEAVY_OR_BINARY_EXTS = {
    ".dll", ".exe", ".bin", ".msi", ".sys", ".so", ".dylib",
    ".zip", ".7z", ".rar", ".iso", ".img", ".cab", ".dmp"
}
TEMP_EXTS = {".tmp", ".temp", ".log", ".bak", ".old", ".chk", ".dmp", ".cache", ".etl"}
INSTALLER_HINTS = ("setup", "installer", "redist", "vcredist", "chainer", "patch", "update", "uninstall")


def _format_size(num_bytes: int) -> str:
    if num_bytes < 1024:
        return f"{num_bytes} Б"
    if num_bytes < 1024 * 1024:
        return f"{num_bytes / 1024:.1f} КБ"
    return f"{num_bytes / (1024 * 1024):.1f} МБ"


def _parse_ignore_rules(raw_rules: str) -> tuple[set[str], set[str]]:
    """
    Разбирает строку исключений вида '.mp4, .avi, backup, temp_dir'
    на множество расширений (с точкой) и множество имён папок/файлов.
    """
    ignore_exts: set[str] = set()
    ignore_names: set[str] = set()
    for token in (raw_rules or "").split(","):
        cleaned = token.strip().lower()
        if not cleaned:
            continue
        if cleaned.startswith("*."):
            cleaned = cleaned[1:]
        if cleaned.startswith(".") and len(cleaned) > 1:
            ignore_exts.add(cleaned)
        else:
            ignore_names.add(cleaned)
    return ignore_exts, ignore_names


class ScanCacheDB:
    """Кэш результатов сканирования в SQLite по ключу (file_path, size, mtime_ns)."""

    def __init__(self, db_path: str):
        self.db_path = db_path
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self._init_table()

    def _init_table(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS scan_cache (
                    file_path TEXT PRIMARY KEY,
                    size INTEGER NOT NULL,
                    mtime_ns INTEGER NOT NULL,
                    threat_level TEXT NOT NULL,
                    regex_hits TEXT NOT NULL,
                    snippet TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )
            conn.commit()

    def load_all(self) -> dict[str, tuple[int, int, str, list[str], str]]:
        if not os.path.exists(self.db_path):
            return {}
        cache: dict[str, tuple[int, int, str, list[str], str]] = {}
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute(
                    "SELECT file_path, size, mtime_ns, threat_level, regex_hits, snippet FROM scan_cache"
                )
                for path, size, mtime_ns, threat, hits_json, snippet in cursor.fetchall():
                    try:
                        hits = json.loads(hits_json) if hits_json else []
                    except Exception:
                        hits = []
                    cache[path] = (int(size), int(mtime_ns), str(threat), hits, str(snippet))
        except Exception:
            return {}
        return cache

    def save_batch(self, entries: list[tuple[str, int, int, str, list[str], str]]):
        if not entries:
            return
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        rows = [
            (path, size, mtime_ns, threat, json.dumps(hits, ensure_ascii=False), snippet, now_str)
            for path, size, mtime_ns, threat, hits, snippet in entries
        ]
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.executemany(
                    """
                    INSERT OR REPLACE INTO scan_cache
                    (file_path, size, mtime_ns, threat_level, regex_hits, snippet, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    rows,
                )
                conn.commit()
        except Exception:
            pass

    def invalidate_paths(self, paths: list[str] | set[str]):
        if not paths or not os.path.exists(self.db_path):
            return
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.executemany("DELETE FROM scan_cache WHERE file_path = ?", [(p,) for p in paths])
                conn.commit()
        except Exception:
            pass

    def clear_all(self):
        if not os.path.exists(self.db_path):
            return
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("DELETE FROM scan_cache")
                conn.commit()
        except Exception:
            pass


def _evaluate_file_review(
    rel_name: str,
    size_bytes: int,
    threat_level: str,
    regex_hits: list | None = None,
) -> tuple[bool, str, str]:
    """
    Определяет, нужно ли предложить файл пользователю к удалению или карантину
    (угроза HIGH/CRITICAL или кандидат на очистку), без автоматического удаления.
    Возвращает (should_prompt, purpose_desc, reason_desc).
    """
    low_name = rel_name.lower()
    _, ext = os.path.splitext(low_name)
    threat_upper = (threat_level or "LOW").upper()

    if threat_upper in ("HIGH", "CRITICAL"):
        hits_info = f" ({', '.join(str(x) for x in regex_hits)})" if regex_hits else ""
        return (
            True,
            "Файл содержит чувствительные данные (например, пароль, ключ или секрет) либо помечен как риск.",
            f"Обнаружена угроза [{threat_upper}]{hits_info}",
        )

    if any(hint in low_name for hint in INSTALLER_HINTS):
        return (
            True,
            "Компонент или ресурс установщика/обновления ПО (часто остаётся после установки или сбоя мастера).",
            "Имя содержит признаки установщика/обновления (setup/installer/chainer/redist)",
        )

    if ext in TEMP_EXTS or "cache" in low_name or "temp" in low_name:
        return (
            True,
            "Временный файл, журнал, дамп или кэш программы.",
            f"Расширение ({ext or 'без расширения'}) или имя указывает на временные/кэш-данные",
        )

    if low_name == "thumbs.db" or low_name == ".ds_store" or low_name.endswith("~"):
        return (
            True,
            "Служебный кэш эскизов или резервная копия редактора.",
            "Служебный/резервный файл окружения",
        )

    if ext in {".zip", ".7z", ".rar", ".iso", ".cab"} and size_bytes > 50 * 1024 * 1024:
        return (
            True,
            "Крупный архив или образ диска (может быть скачанным дистрибутивом или дубликатом).",
            f"Крупный архив/образ ({_format_size(size_bytes)})",
        )

    if ext in {".dll", ".exe", ".msi"}:
        return (
            False,
            "Исполняемый файл или библиотека (может использоваться программой или быть остатком дистрибутива).",
            "Требует осторожной проверки перед удалением",
        )

    return (
        False,
        "Обычный файл данных/документ/конфигурация (удалять только если вы уверены, что он не нужен).",
        "Явных признаков риска или остаточного файла нет",
    )


def _iter_files_recursive(
    root_dir: str,
    max_files: int = 1000,
    thread: QThread | None = None,
    ignore_exts: set[str] | None = None,
    ignore_names: set[str] | None = None,
) -> tuple[list[str], int]:
    found: list[str] = []
    skipped_count = 0
    extra_dirs = ignore_names or set()
    blocked_exts = ignore_exts or set()
    all_skip_dirs = SKIP_DIRS | extra_dirs

    for current_root, dirnames, filenames in os.walk(root_dir):
        if thread is not None and thread.isInterruptionRequested():
            return found, skipped_count
        kept_dirs = []
        for d in dirnames:
            if d.lower() in all_skip_dirs:
                skipped_count += 1
            else:
                kept_dirs.append(d)
        dirnames[:] = kept_dirs

        for fname in sorted(filenames):
            if thread is not None and thread.isInterruptionRequested():
                return found, skipped_count
            low_fname = fname.lower()
            _, ext = os.path.splitext(low_fname)
            if low_fname in extra_dirs or (ext and ext in blocked_exts):
                skipped_count += 1
                continue
            full_path = os.path.join(current_root, fname)
            if os.path.isfile(full_path):
                found.append(full_path)
                if len(found) >= max_files:
                    return found, skipped_count
    return found, skipped_count


def _read_any_file_content(file_path: str, extractor: TextExtractor, max_chars: int = 600) -> tuple[str, bool]:
    """
    Безопасно читает текст или строки из файла без зависаний на больших бинарниках.
    Возвращает (snippet, has_analyzable_text).
    """
    try:
        file_size = os.path.getsize(file_path)
    except OSError as e:
        return f"[ошибка размера файла: {e}]", False

    if file_size == 0:
        return "[пустой файл]", False

    _, ext = os.path.splitext(file_path.lower())

    if ext not in HEAVY_OR_BINARY_EXTS and file_size <= 2 * 1024 * 1024:
        try:
            extracted = extractor.extract_text(file_path)
            if extracted and extracted.strip():
                cleaned = re.sub(r"\s+", " ", extracted.strip())
                return cleaned[:max_chars], True
        except Exception:
            pass

    try:
        with open(file_path, "rb") as f:
            raw = f.read(65536)
    except PermissionError:
        return "[нет доступа к чтению файла]", False
    except OSError as e:
        return f"[ошибка чтения: {e}]", False

    for enc in ("utf-8", "cp1251", "cp866", "latin-1"):
        try:
            decoded = raw.decode(enc)
            printable = sum(1 for ch in decoded if ch.isprintable() or ch in "\r\n\t")
            if len(decoded) > 0 and (printable / len(decoded)) > 0.85:
                cleaned = re.sub(r"\s+", " ", decoded.strip())
                return cleaned[:max_chars], bool(cleaned)
        except Exception:
            continue

    ascii_hits = [chunk.decode("ascii", errors="ignore") for chunk in ASCII_PRINTABLE_RE.findall(raw)]
    utf16_hits = [
        chunk.decode("utf-16-le", errors="ignore") for chunk in UTF16_PRINTABLE_RE.findall(raw)
    ]
    strings = (ascii_hits + utf16_hits)[:20]
    if strings:
        joined = re.sub(r"\s+", " ", " | ".join(strings))
        return f"[строки из файла ({_format_size(file_size)})]: {joined[:max_chars]}", True

    return f"[бинарный файл ({_format_size(file_size)}) без читаемых строк]", False


class CleanupCandidatesDialog(QDialog):
    """Окно выбора файлов с галочками перед отправкой в карантин или удалением."""

    def __init__(self, candidates: list[dict], parent=None):
        super().__init__(parent)
        self.setWindowTitle("Выбор файлов (угрозы и кандидаты)")
        self.resize(780, 500)
        self._candidates = candidates
        self.selected_candidates: list[dict] = []
        self.action_mode: str = "delete"

        layout = QVBoxLayout(self)
        layout.setSpacing(10)

        lbl_info = QLabel(
            "Программа не изменяет и не удаляет файлы автоматически. Отметьте галочками нужные файлы "
            "и выберите действие: поместить в зашифрованный карантин (.enc) или удалить:"
        )
        lbl_info.setWordWrap(True)
        layout.addWidget(lbl_info)

        ctrl_row = QHBoxLayout()
        btn_select_all = QPushButton("☑ Выбрать все")
        btn_select_all.setObjectName("SecondaryBtn")
        btn_select_all.clicked.connect(lambda: self._set_all_checked(True))
        ctrl_row.addWidget(btn_select_all)

        btn_deselect_all = QPushButton("☐ Снять выбор")
        btn_deselect_all.setObjectName("SecondaryBtn")
        btn_deselect_all.clicked.connect(lambda: self._set_all_checked(False))
        ctrl_row.addWidget(btn_deselect_all)

        ctrl_row.addStretch()

        self.lbl_selected_count = QLabel("")
        self.lbl_selected_count.setStyleSheet("color: #334155; font-weight: 600;")
        ctrl_row.addWidget(self.lbl_selected_count)
        layout.addLayout(ctrl_row)

        self.list_widget = QListWidget()
        self.list_widget.setFont(QFont("Segoe UI", 9))
        self.list_widget.itemChanged.connect(self._update_selected_counter)
        layout.addWidget(self.list_widget)

        for idx, c in enumerate(candidates):
            text = (
                f"{c['rel_name']}  ({c['size_text']}, {c['mtime']})\n"
                f"Причина: {c['reason']} | Назначение: {c['purpose']}"
            )
            item = QListWidgetItem(text)
            item.setFlags(item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
            item.setCheckState(Qt.CheckState.Checked)
            item.setData(Qt.ItemDataRole.UserRole, idx)
            self.list_widget.addItem(item)

        btn_row = QHBoxLayout()
        btn_row.addStretch()

        btn_cancel = QPushButton("Отмена")
        btn_cancel.setObjectName("SecondaryBtn")
        btn_cancel.clicked.connect(self.reject)
        btn_row.addWidget(btn_cancel)

        self.btn_quarantine = QPushButton("🔐 В карантин")
        self.btn_quarantine.setObjectName("SecondaryBtn")
        self.btn_quarantine.clicked.connect(self._on_quarantine_clicked)
        btn_row.addWidget(self.btn_quarantine)

        self.btn_delete = QPushButton("🗑️ Удалить выбранные")
        self.btn_delete.setObjectName("DangerBtn")
        self.btn_delete.clicked.connect(self._on_delete_clicked)
        btn_row.addWidget(self.btn_delete)

        layout.addLayout(btn_row)

        self._update_selected_counter()

    def _set_all_checked(self, checked: bool):
        state = Qt.CheckState.Checked if checked else Qt.CheckState.Unchecked
        self.list_widget.blockSignals(True)
        for i in range(self.list_widget.count()):
            self.list_widget.item(i).setCheckState(state)
        self.list_widget.blockSignals(False)
        self._update_selected_counter()

    def _update_selected_counter(self):
        count = 0
        for i in range(self.list_widget.count()):
            if self.list_widget.item(i).checkState() == Qt.CheckState.Checked:
                count += 1
        self.lbl_selected_count.setText(f"Выбрано файлов: {count} из {self.list_widget.count()}")
        has_any = count > 0
        self.btn_quarantine.setEnabled(has_any)
        self.btn_delete.setEnabled(has_any)

    def _collect_checked_candidates(self) -> list[dict]:
        chosen: list[dict] = []
        for i in range(self.list_widget.count()):
            item = self.list_widget.item(i)
            if item.checkState() == Qt.CheckState.Checked:
                idx = item.data(Qt.ItemDataRole.UserRole)
                if isinstance(idx, int) and 0 <= idx < len(self._candidates):
                    chosen.append(self._candidates[idx])
        return chosen

    def _on_quarantine_clicked(self):
        chosen = self._collect_checked_candidates()
        if not chosen:
            QMessageBox.information(self, "Ничего не выбрано", "Отметьте хотя бы один файл галочкой.")
            return
        self.selected_candidates = chosen
        self.action_mode = "quarantine"
        self.accept()

    def _on_delete_clicked(self):
        chosen = self._collect_checked_candidates()
        if not chosen:
            QMessageBox.information(self, "Ничего не выбрано", "Отметьте хотя бы один файл галочкой.")
            return
        self.selected_candidates = chosen
        self.action_mode = "delete"
        self.accept()


class FolderContextScanWorker(QThread):
    """Сканирует папку с кэшированием в SQLite, быстрым предфильтром и масками исключений."""
    progress = Signal(str)
    log_line = Signal(str, str)
    scan_complete = Signal(str, list, list, bool, dict)

    def __init__(
        self,
        folder_path: str,
        extractor: TextExtractor,
        analyzer: DLPAnalyzer,
        db_path: str,
        ignore_rules: str = "",
        max_files: int = 400,
    ):
        super().__init__()
        self.folder_path = folder_path
        self.extractor = extractor
        self.analyzer = analyzer
        self.db_path = db_path
        self.ignore_rules = ignore_rules
        self.max_files = max_files

    def run(self):
        stats = {"cache_hits": 0, "fast_skipped": 0, "analyzed": 0, "ignored": 0}
        if not os.path.exists(self.folder_path):
            self.scan_complete.emit("Папка не существует.", [], [], False, stats)
            return

        t0 = time.perf_counter()
        self.progress.emit("Поиск файлов во всех вложенных папках...")
        ignore_exts, ignore_names = _parse_ignore_rules(self.ignore_rules)
        files, skipped_count = _iter_files_recursive(
            self.folder_path,
            max_files=self.max_files,
            thread=self,
            ignore_exts=ignore_exts,
            ignore_names=ignore_names,
        )
        stats["ignored"] = skipped_count

        if self.isInterruptionRequested():
            self.scan_complete.emit("", [], [], True, stats)
            return

        total = len(files)
        if total == 0:
            self.scan_complete.emit(
                f"Папка: {self.folder_path}\nФайлов для проверки не найдено (исключено по фильтрам: {skipped_count}).",
                [],
                [],
                False,
                stats,
            )
            return

        cache_db = ScanCacheDB(self.db_path)
        cached_map = cache_db.load_all()
        new_cache_entries: list[tuple[str, int, int, str, list[str], str]] = []

        self.log_line.emit(
            f"\n[🔍 SCAN] Начат анализ папки: {self.folder_path} (файлов: {total}, исключено: {skipped_count})",
            "INFO",
        )
        summary_lines: list[str] = [f"Папка: {self.folder_path} | Найдено файлов: {total}"]
        records: list[dict] = []
        candidates: list[dict] = []

        for idx, path in enumerate(files, start=1):
            if self.isInterruptionRequested():
                cache_db.save_batch(new_cache_entries)
                self.scan_complete.emit("", records, candidates, True, stats)
                return

            rel_name = os.path.relpath(path, self.folder_path)
            try:
                st = os.stat(path)
                size = st.st_size
                mtime_ns = st.st_mtime_ns
                mtime_str = datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M")
            except OSError:
                size = 0
                mtime_ns = 0
                mtime_str = "-"

            cached = cached_map.get(path)
            source_tag = ""
            if cached is not None and cached[0] == size and cached[1] == mtime_ns and mtime_ns > 0:
                _, _, threat_level, regex_hits, content_snippet = cached
                stats["cache_hits"] += 1
                source_tag = " [кэш]"
            else:
                content_snippet, has_text = _read_any_file_content(path, self.extractor, max_chars=2000)
                if self.isInterruptionRequested():
                    cache_db.save_batch(new_cache_entries)
                    self.scan_complete.emit("", records, candidates, True, stats)
                    return

                regex_hits = []
                if not has_text:
                    threat_level = "LOW"
                    stats["fast_skipped"] += 1
                    source_tag = " [предфильтр]"
                else:
                    try:
                        threat_level, regex_hits, _ = self.analyzer.evaluate(content_snippet)
                    except Exception:
                        threat_level = "LOW"
                    stats["analyzed"] += 1

                if mtime_ns > 0:
                    new_cache_entries.append(
                        (path, size, mtime_ns, threat_level, list(regex_hits or []), content_snippet[:350])
                    )

            should_prompt, purpose_desc, reason_desc = _evaluate_file_review(
                rel_name, size, threat_level, regex_hits
            )
            rec = {
                "path": path,
                "rel_name": rel_name,
                "size": size,
                "size_text": _format_size(size),
                "mtime": mtime_str,
                "threat": threat_level,
                "snippet": content_snippet[:350],
                "is_candidate": should_prompt,
                "purpose": purpose_desc,
                "reason": reason_desc,
            }
            records.append(rec)
            if should_prompt:
                candidates.append(rec)

            tag = "CRITICAL" if threat_level == "CRITICAL" else ("HIGH" if threat_level == "HIGH" else "LOW")
            cand_mark = f" [{reason_desc}]" if should_prompt else ""
            self.log_line.emit(
                f"  • {rel_name} ({_format_size(size)}, {mtime_str}) -> [{threat_level}]{source_tag}{cand_mark}",
                tag,
            )

            summary_lines.append(
                f"{idx}. Имя: {rel_name} | Размер: {_format_size(size)} | Дата: {mtime_str} | "
                f"Метка: {threat_level} | Предложен к проверке: {'да' if should_prompt else 'нет'} | "
                f"Причина: {reason_desc} | Назначение: {purpose_desc}"
            )

            if idx == 1 or idx % 25 == 0 or idx == total:
                self.progress.emit(f"Обработано {idx} из {total} файлов (кэш: {stats['cache_hits']})...")

        cache_db.save_batch(new_cache_entries)
        stats["elapsed_sec"] = round(time.perf_counter() - t0, 2)
        full_report = "\n".join(summary_lines)[:10000]
        self.scan_complete.emit(full_report, records, candidates, False, stats)


class FileAnalysisWorker(QThread):
    """Асинхронный анализ одного файла при событиях watchdog без автоудаления."""
    log_ready = Signal(str, str)
    audit_updated = Signal()
    review_item_ready = Signal(dict)

    def __init__(self, event_type: str, file_path: str, watch_root: str, db_path: str, extractor, analyzer, logger):
        super().__init__()
        self.event_type = event_type
        self.file_path = file_path
        self.watch_root = watch_root
        self.db_path = db_path
        self.extractor = extractor
        self.analyzer = analyzer
        self.logger = logger

    def run(self):
        time.sleep(0.15)
        if not os.path.exists(self.file_path):
            return

        filename = os.path.basename(self.file_path)
        try:
            rel_name = os.path.relpath(self.file_path, self.watch_root)
        except ValueError:
            rel_name = filename

        try:
            st = os.stat(self.file_path)
            size = st.st_size
            mtime_ns = st.st_mtime_ns
            mtime_str = datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M")
        except OSError:
            size = 0
            mtime_ns = 0
            mtime_str = "-"

        self.log_ready.emit(f"\n[🔔 EVENT | {self.event_type}] Файл: {rel_name}", "INFO")

        text, has_text = _read_any_file_content(self.file_path, self.extractor, max_chars=2000)
        if not text:
            self.log_ready.emit(" [*] Пропущен (пустой или недоступный файл)", "INFO")
            return

        if not has_text:
            threat_level, regex_hits, ai_verdict = "LOW", [], "Предфильтр: пустой или бинарный файл без текста"
        else:
            threat_level, regex_hits, ai_verdict = self.analyzer.evaluate(text)

        if mtime_ns > 0:
            ScanCacheDB(self.db_path).save_batch(
                [(self.file_path, size, mtime_ns, threat_level, list(regex_hits or []), text[:350])]
            )

        tag = threat_level if threat_level in ("HIGH", "CRITICAL") else "LOW"

        self.log_ready.emit(f" [🛡️ VERDICT] Угроза: {threat_level}", tag)
        if regex_hits:
            self.log_ready.emit(f"   └─ Regex совпадения: {regex_hits}", "HIGH")
        self.log_ready.emit(f"   └─ AI Анализ: {ai_verdict[:110]}...", tag)

        should_prompt, purpose_desc, reason_desc = _evaluate_file_review(
            rel_name, size, threat_level, regex_hits
        )
        audit_details = f"{ai_verdict} | {reason_desc} (ожидает решения пользователя)"

        self.logger.log_event(self.event_type, self.file_path, threat_level, audit_details)
        self.audit_updated.emit()

        if should_prompt:
            self.log_ready.emit(f" [⚠️ REVIEW] Добавлено в список на проверку (без автоудаления): {rel_name}", "HIGH")
            self.review_item_ready.emit({
                "path": self.file_path,
                "rel_name": rel_name,
                "size": size,
                "size_text": _format_size(size),
                "mtime": mtime_str,
                "threat": threat_level,
                "snippet": text[:350],
                "is_candidate": True,
                "purpose": purpose_desc,
                "reason": reason_desc,
            })


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
    """Асинхронный запрос к локальному чату Ollama с учётом просканированной папки."""
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
                "options": {
                    "temperature": 0.1,
                    "num_predict": 350,
                },
            }
            res = requests.post("http://localhost:11434/api/chat", json=payload, timeout=90)
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
        self.resize(1180, 780)
        self.setMinimumSize(960, 620)
        self.setStyleSheet(APP_QSS)

        self.extractor = TextExtractor()
        self.analyzer = DLPAnalyzer()
        self.quarantine = QuarantineManager()
        self.logger = AuditLogger()

        self.watch_path = os.path.join(BASE_DIR, "test_folder")
        self.db_path = os.path.join(BASE_DIR, "logs", "dlp.db")
        self.cache_db = ScanCacheDB(self.db_path)

        self.observer = None
        self.is_running = False
        self._active_scan_worker: FolderContextScanWorker | None = None
        self._workers: list[QThread] = []
        self._all_audit_rows: list[tuple] = []
        self._last_folder_report: str = ""
        self._last_scan_records: list[dict] = []
        self._pending_review_items: list[dict] = []
        self._review_dialog_open: bool = False
        self._chat_history: list[dict] = [
            {
                "role": "system",
                "content": (
                    "Ты строгий аналитик файлов на диске. Отвечай ТОЛЬКО на русском языке. "
                    "Используй ТОЛЬКО те файлы, которые явно перечислены в переданном списке сканирования. "
                    "ЗАПРЕЩЕНО придумывать файлы, которых нет в списке (например, example.txt, image.jpg, .DS_Store, unknown.exe). "
                    "Если в списке только 1 файл — анализируй только этот 1 файл. "
                    "Помогай понять, что за файлы и для чего они могут быть, но не принимай решение об удалении за пользователя."
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

    def _create_metric_card(self, title: str, value_object_name: str = "MetricValue") -> tuple[QFrame, QLabel]:
        card = QFrame()
        card.setObjectName("MetricCard")
        layout = QVBoxLayout(card)
        layout.setContentsMargins(6, 4, 6, 4)
        layout.setSpacing(2)

        lbl_title = QLabel(title)
        lbl_title.setObjectName("MetricTitle")

        lbl_value = QLabel("0")
        lbl_value.setObjectName(value_object_name)

        layout.addWidget(lbl_title)
        layout.addWidget(lbl_value)
        return card, lbl_value

    def _init_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        root_layout = QVBoxLayout(central)
        root_layout.setSpacing(10)

        top_group = QGroupBox("Управление системой и ИИ")
        top_layout = QHBoxLayout(top_group)

        self.btn_scan_and_watch = QPushButton("🔍 Сканирование")
        self.btn_scan_and_watch.setToolTip("Запустить сканирование и мониторинг выбранной папки; повторное нажатие остановит оба режима")
        self.btn_scan_and_watch.clicked.connect(self.toggle_scan_and_monitoring)
        top_layout.addWidget(self.btn_scan_and_watch)

        self.lbl_status = QLabel("Статус: ОСТАНОВЛЕН")
        self.lbl_status.setStyleSheet("color: #dc2626; font-weight: 700;")
        top_layout.addWidget(self.lbl_status)

        self.btn_ollama = QPushButton("🤖 Запустить Ollama")
        self.btn_ollama.setObjectName("SecondaryBtn")
        self.btn_ollama.clicked.connect(self.start_ollama_service)
        top_layout.addWidget(self.btn_ollama)

        self.lbl_ollama = QLabel("ИИ: Проверка...")
        self.lbl_ollama.setStyleSheet("color: #d97706; font-weight: 700;")
        top_layout.addWidget(self.lbl_ollama)

        top_layout.addStretch()

        self.btn_stats_toggle = QPushButton("📊 Статистика")
        self.btn_stats_toggle.setObjectName("SecondaryBtn")
        self.btn_stats_toggle.setCheckable(True)
        self.btn_stats_toggle.setChecked(False)
        self.btn_stats_toggle.clicked.connect(self.toggle_stats_panel)
        top_layout.addWidget(self.btn_stats_toggle)

        self.lbl_folder = QLabel(f"Папка: {os.path.basename(self.watch_path)}")
        self.lbl_folder.setFont(QFont("Consolas", 9))
        self.lbl_folder.setToolTip(self.watch_path)
        top_layout.addWidget(self.lbl_folder)

        self.btn_choose_folder = QPushButton("📁 Выбрать папку")
        self.btn_choose_folder.setObjectName("SecondaryBtn")
        self.btn_choose_folder.setToolTip("Выбрать папку в Windows для сканирования и мониторинга")
        self.btn_choose_folder.clicked.connect(self.choose_watch_folder)
        top_layout.addWidget(self.btn_choose_folder)

        root_layout.addWidget(top_group)

        self.stats_widget = QWidget()
        metrics_layout = QHBoxLayout(self.stats_widget)
        metrics_layout.setContentsMargins(0, 0, 0, 0)
        metrics_layout.setSpacing(10)

        card_total, self.lbl_metric_total = self._create_metric_card("ВСЕГО СОБЫТИЙ", "MetricValue")
        card_threats, self.lbl_metric_threats = self._create_metric_card("УГРОЗ HIGH / CRITICAL", "MetricValueDanger")
        card_quarantine, self.lbl_metric_quarantine = self._create_metric_card("В КАРАНТИНЕ (.ENC)", "MetricValueAccent")

        metrics_layout.addWidget(card_total)
        metrics_layout.addWidget(card_threats)
        metrics_layout.addWidget(card_quarantine)
        self.stats_widget.setVisible(False)
        root_layout.addWidget(self.stats_widget)

        self.tabs = QTabWidget()
        root_layout.addWidget(self.tabs)

        tab_live = QWidget()
        live_outer = QVBoxLayout(tab_live)

        live_toolbar = QHBoxLayout()
        self.btn_review_list = QPushButton("🗑️ Удалить выбранные (0)")
        self.btn_review_list.setObjectName("DangerBtn")
        self.btn_review_list.setEnabled(False)
        self.btn_review_list.clicked.connect(self.open_review_dialog_manual)
        live_toolbar.addWidget(self.btn_review_list)

        self.lbl_scan_status = QLabel("")
        self.lbl_scan_status.setStyleSheet("color: #64748b; font-size: 9pt;")
        live_toolbar.addWidget(self.lbl_scan_status)

        self.btn_clear_log = QPushButton("Очистить лог")
        self.btn_clear_log.setObjectName("SecondaryBtn")
        self.btn_clear_log.clicked.connect(self.log_area_clear)
        live_toolbar.addWidget(self.btn_clear_log)

        self.btn_clear_cache = QPushButton("⚡ Сбросить кэш")
        self.btn_clear_cache.setObjectName("SecondaryBtn")
        self.btn_clear_cache.setToolTip("Очистить кэш сканирования в SQLite, чтобы перепроверить все файлы заново")
        self.btn_clear_cache.clicked.connect(self.clear_scan_cache)
        live_toolbar.addWidget(self.btn_clear_cache)

        live_toolbar.addStretch()

        self.btn_toggle_side_chat = QPushButton("🤖 Чат с ИИ")
        self.btn_toggle_side_chat.setObjectName("SecondaryBtn")
        self.btn_toggle_side_chat.setCheckable(True)
        self.btn_toggle_side_chat.setChecked(False)
        self.btn_toggle_side_chat.clicked.connect(self.toggle_side_chat)
        live_toolbar.addWidget(self.btn_toggle_side_chat)

        live_outer.addLayout(live_toolbar)

        filter_toolbar = QHBoxLayout()
        lbl_ignore = QLabel("Исключить (расширения/папки):")
        lbl_ignore.setStyleSheet("color: #475569; font-size: 9pt;")
        filter_toolbar.addWidget(lbl_ignore)

        self.ignore_rules_input = QLineEdit()
        self.ignore_rules_input.setPlaceholderText("Например: .mp4, .avi, .iso, backup")
        self.ignore_rules_input.setClearButtonEnabled(True)
        filter_toolbar.addWidget(self.ignore_rules_input)
        live_outer.addLayout(filter_toolbar)

        self.live_splitter = QSplitter(Qt.Orientation.Horizontal)

        self.log_area = QTextEdit()
        self.log_area.setReadOnly(True)
        self.log_area.setFont(QFont("Consolas", 9))
        self.log_area.setStyleSheet("background-color: #0f172a; color: #e2e8f0; border-radius: 8px; padding: 8px;")
        self.live_splitter.addWidget(self.log_area)

        self.side_chat_panel = QGroupBox("Чат с ИИ — что за файлы и что лишнее")
        side_chat_layout = QVBoxLayout(self.side_chat_panel)

        self.side_chat_display = QTextEdit()
        self.side_chat_display.setReadOnly(True)
        self.side_chat_display.setFont(QFont("Segoe UI", 9))
        self.side_chat_display.append(
            "<i>Нажмите «Сканирование» — запустится анализ папки и мониторинг. "
            "Неизменённые файлы берутся из кэша SQLite, а найденные угрозы или кандидаты "
            "предлагаются в окне выбора с галочками (можно отправить в карантин или удалить).</i>\n"
        )
        side_chat_layout.addWidget(self.side_chat_display)

        side_input_row = QHBoxLayout()
        self.side_chat_input = QLineEdit()
        self.side_chat_input.setPlaceholderText("Например: для чего эти файлы и что лишнее?")
        self.side_chat_input.returnPressed.connect(self.send_side_chat_message)
        side_input_row.addWidget(self.side_chat_input)

        self.btn_side_send = QPushButton("Спросить")
        self.btn_side_send.clicked.connect(self.send_side_chat_message)
        side_input_row.addWidget(self.btn_side_send)
        side_chat_layout.addLayout(side_input_row)

        self.side_chat_panel.setVisible(False)
        self.live_splitter.addWidget(self.side_chat_panel)
        self.live_splitter.setSizes([740, 420])

        live_outer.addWidget(self.live_splitter)
        self.tabs.addTab(tab_live, "📡 Сканер и монитор")

        tab_db = QWidget()
        db_layout = QVBoxLayout(tab_db)

        db_top = QHBoxLayout()
        db_top.addWidget(QLabel("Угроза:"))

        self.combo_threat_filter = QComboBox()
        self.combo_threat_filter.addItems(["ALL", "CRITICAL", "HIGH", "LOW", "INFO"])
        self.combo_threat_filter.currentTextChanged.connect(self._apply_audit_filters)
        db_top.addWidget(self.combo_threat_filter)

        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Поиск по файлу, событию или деталям...")
        self.search_input.setClearButtonEnabled(True)
        self.search_input.textChanged.connect(self._apply_audit_filters)
        db_top.addWidget(self.search_input, stretch=1)

        btn_reset_filters = QPushButton("Сбросить")
        btn_reset_filters.setObjectName("SecondaryBtn")
        btn_reset_filters.clicked.connect(self._reset_audit_filters)
        db_top.addWidget(btn_reset_filters)

        btn_refresh = QPushButton("🔄 Обновить базу данных")
        btn_refresh.clicked.connect(self.refresh_logs)
        db_top.addWidget(btn_refresh)
        db_layout.addLayout(db_top)

        self.lbl_audit_count = QLabel("Показано записей: 0")
        self.lbl_audit_count.setStyleSheet("color: #64748b; font-size: 9pt;")
        db_layout.addWidget(self.lbl_audit_count)

        self.table = QTableWidget()
        self.table.setColumnCount(6)
        self.table.setHorizontalHeaderLabels(["ID", "Дата и время", "Событие", "Имя файла", "Угроза", "Детали / AES-256"])
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        db_layout.addWidget(self.table)

        self.tabs.addTab(tab_db, "💾 Журнал аудита (SQLite)")

        tab_hitl = QWidget()
        hitl_layout = QHBoxLayout(tab_hitl)

        q_group = QGroupBox("Карантин (.enc) — подтверждение действий")
        q_layout = QVBoxLayout(q_group)

        q_top_row = QHBoxLayout()
        btn_refresh_q = QPushButton("🔄 Обновить список карантина")
        btn_refresh_q.setObjectName("SecondaryBtn")
        btn_refresh_q.clicked.connect(self.refresh_quarantine_list)
        q_top_row.addWidget(btn_refresh_q)
        q_top_row.addStretch()
        q_layout.addLayout(q_top_row)

        self.quarantine_list = QListWidget()
        self.quarantine_list.setFont(QFont("Consolas", 9))
        q_layout.addWidget(self.quarantine_list)

        q_actions_row = QHBoxLayout()
        self.btn_decrypt = QPushButton("🔓 Расшифровать выбранный файл")
        self.btn_decrypt.clicked.connect(self.confirm_and_decrypt)
        q_actions_row.addWidget(self.btn_decrypt)

        self.btn_shred_enc = QPushButton("🔥 Безвозвратно уничтожить (.enc)")
        self.btn_shred_enc.setObjectName("DangerBtn")
        self.btn_shred_enc.clicked.connect(self.confirm_and_shred)
        q_actions_row.addWidget(self.btn_shred_enc)

        q_layout.addLayout(q_actions_row)
        hitl_layout.addWidget(q_group)

        self.tabs.addTab(tab_hitl, "🔐 Карантин (HITL)")

    def _is_scan_or_watch_active(self) -> bool:
        scan_running = self._active_scan_worker is not None and self._active_scan_worker.isRunning()
        return self.is_running or scan_running

    def _sync_scan_watch_button(self):
        active = self._is_scan_or_watch_active()
        if active:
            self.btn_scan_and_watch.setText("⏹ Остановить сканирование")
            self.btn_scan_and_watch.setObjectName("DangerBtn")
            self.lbl_status.setText("Статус: АКТИВЕН")
            self.lbl_status.setStyleSheet("color: #16a34a; font-weight: 700;")
        else:
            self.btn_scan_and_watch.setText("🔍 Сканирование")
            self.btn_scan_and_watch.setObjectName("")
            self.lbl_status.setText("Статус: ОСТАНОВЛЕН")
            self.lbl_status.setStyleSheet("color: #dc2626; font-weight: 700;")

        self.btn_scan_and_watch.style().unpolish(self.btn_scan_and_watch)
        self.btn_scan_and_watch.style().polish(self.btn_scan_and_watch)

    def _sync_review_button(self):
        count = len(self._pending_review_items)
        self.btn_review_list.setText(f"🗑️ Удалить выбранные ({count})")
        self.btn_review_list.setEnabled(count > 0)

    def toggle_stats_panel(self, checked: bool):
        self.stats_widget.setVisible(checked)

    def toggle_side_chat(self, checked: bool):
        self.side_chat_panel.setVisible(checked)
        if checked:
            self.live_splitter.setSizes([720, 440])
            self.side_chat_input.setFocus()

    def log_area_clear(self):
        self.log_area.clear()

    def clear_scan_cache(self):
        self.cache_db.clear_all()
        self.append_log("[⚡ CACHE] Кэш сканирования в SQLite очищен. Следующий запуск проверит все файлы заново.", "INFO")
        QMessageBox.information(self, "Кэш очищен", "Кэш результатов сканирования успешно очищен.")

    def toggle_scan_and_monitoring(self):
        if self._is_scan_or_watch_active():
            self.stop_scan_and_monitoring()
        else:
            self.start_scan_and_monitoring()

    def start_scan_and_monitoring(self):
        os.makedirs(self.watch_path, exist_ok=True)
        self._start_watcher_only()

        if self._active_scan_worker is None or not self._active_scan_worker.isRunning():
            self.lbl_scan_status.setText("Сканирование и мониторинг...")
            worker = FolderContextScanWorker(
                folder_path=self.watch_path,
                extractor=self.extractor,
                analyzer=self.analyzer,
                db_path=self.db_path,
                ignore_rules=self.ignore_rules_input.text(),
                max_files=400,
            )
            self._active_scan_worker = worker
            worker.progress.connect(self.lbl_scan_status.setText)
            worker.log_line.connect(self.append_log)
            worker.scan_complete.connect(self._on_folder_scan_complete)
            worker.finished.connect(self._on_scan_worker_finished)
            worker.finished.connect(lambda w=worker: self._cleanup_worker(w))
            self._workers.append(worker)
            worker.start()

        self._sync_scan_watch_button()

    def stop_scan_and_monitoring(self):
        if self._active_scan_worker is not None and self._active_scan_worker.isRunning():
            self._active_scan_worker.requestInterruption()
            self.lbl_scan_status.setText("Остановка сканирования и мониторинга...")
            self.append_log("[⏹ SCAN] Запрошена остановка сканирования и мониторинга...", "INFO")

        self._stop_watcher_only()
        self._sync_scan_watch_button()

    def _on_scan_worker_finished(self):
        self._active_scan_worker = None
        self._sync_scan_watch_button()

    def _add_pending_review_items(self, items: list[dict], open_dialog: bool = False):
        existing_paths = {x["path"] for x in self._pending_review_items}
        added = False
        for item in items:
            if item["path"] not in existing_paths:
                self._pending_review_items.append(item)
                existing_paths.add(item["path"])
                added = True

        self._sync_review_button()
        if added and open_dialog and not self._review_dialog_open:
            self._prompt_delete_candidates(self._pending_review_items)

    def open_review_dialog_manual(self):
        self._review_dialog_open = False
        if not self._pending_review_items:
            QMessageBox.information(
                self,
                "Нет файлов на удаление",
                "В списке пока нет файлов с угрозами или кандидатов на удаление.",
            )
            return
        self._prompt_delete_candidates(self._pending_review_items)

    def _build_review_report_text(self, records: list[dict], candidates: list[dict]) -> str:
        lines = [
            f"=== ОТЧЁТ ПО ПАПКЕ: {self.watch_path} ===",
            f"Всего файлов проверено: {len(records)} | Предложено к проверке: {len(candidates)}",
            "",
            "--- ЧТО ЗА ФАЙЛЫ И ДЛЯ ЧЕГО МОГУТ БЫТЬ ---",
        ]
        for idx, r in enumerate(records, start=1):
            lines.append(
                f"{idx}. {r['rel_name']} ({r['size_text']}, изменён {r['mtime']}) — {r['purpose']}"
            )

        if candidates:
            lines.append("")
            lines.append("--- ФАЙЛЫ С УГРОЗАМИ / КАНДИДАТЫ (ТРЕБУЮТ ВАШЕГО ПОДТВЕРЖДЕНИЯ) ---")
            for idx, c in enumerate(candidates, start=1):
                lines.append(
                    f"{idx}. {c['rel_name']} ({c['size_text']}) — {c['reason']}. Назначение: {c['purpose']}"
                )
        else:
            lines.append("")
            lines.append("Файлов с угрозами или кандидатов не найдено.")

        return "\n".join(lines)

    def _on_folder_scan_complete(
        self,
        full_report: str,
        records: list[dict],
        candidates: list[dict],
        cancelled: bool,
        stats: dict,
    ):
        if cancelled:
            self.lbl_scan_status.setText(f"Остановлено (обработано файлов: {len(records)})")
            self.append_log(f"[⏹ SCAN] Сканирование остановлено (обработано файлов: {len(records)}).", "INFO")
            return

        self._last_folder_report = full_report
        self._last_scan_records = records
        watch_state = "мониторинг активен" if self.is_running else "мониторинг остановлен"
        elapsed = stats.get("elapsed_sec", 0.0)
        cache_hits = stats.get("cache_hits", 0)
        fast_skipped = stats.get("fast_skipped", 0)
        ignored = stats.get("ignored", 0)

        self.lbl_scan_status.setText(
            f"Готово за {elapsed} с: файлов — {len(records)}, из кэша — {cache_hits}, "
            f"на проверку — {len(candidates)} ({watch_state})"
        )
        self.append_log(
            f"[✅ SCAN] Анализ завершён за {elapsed} с (всего: {len(records)}, "
            f"из кэша: {cache_hits}, предфильтр: {fast_skipped}, исключено: {ignored}).",
            "INFO",
        )

        report_text = self._build_review_report_text(records, candidates)
        self.append_log("\n" + report_text, "INFO")

        if not self.btn_toggle_side_chat.isChecked():
            self.btn_toggle_side_chat.setChecked(True)
            self.toggle_side_chat(True)

        self.side_chat_display.append(
            "<b>Отчёт по папке сформирован:</b><br>" + report_text.replace("\n", "<br>") + "<br>"
        )
        self.side_chat_display.ensureCursorVisible()

        if candidates:
            self._add_pending_review_items(candidates, open_dialog=False)
            self.append_log(
                f"[ℹ️ HITL] Найдено файлов на проверку: {len(candidates)}. "
                f"Нажмите кнопку «Удалить выбранные ({len(candidates)})», чтобы отметить файлы и отправить в карантин или удалить.",
                "INFO",
            )

    def _prompt_delete_candidates(self, candidates: list[dict]):
        if self._review_dialog_open:
            return
        self._review_dialog_open = True
        try:
            dialog = CleanupCandidatesDialog(candidates, parent=self)
            if dialog.exec() != QDialog.DialogCode.Accepted:
                self.append_log("[🛡️ HITL] Действие отменено пользователем. Файлы не тронуты.", "INFO")
                return

            chosen = dialog.selected_candidates

            if dialog.action_mode == "quarantine":
                quarantined_count = 0
                failed_q: list[str] = []
                moved_paths: set[str] = set()

                for c in chosen:
                    target_path = c["path"]
                    if not os.path.exists(target_path):
                        moved_paths.add(target_path)
                        continue
                    try:
                        enc_path = self.quarantine.isolate(target_path, c.get("threat", "HIGH"))
                        quarantined_count += 1
                        moved_paths.add(target_path)
                        self.append_log(f" [🔐 AES-256] Помещено в карантин: {enc_path}", "CRITICAL")
                        self.logger.log_event(
                            "HITL_QUARANTINE",
                            target_path,
                            c.get("threat", "HIGH"),
                            f"Оператор отправил в карантин: {enc_path} ({c['reason']})",
                        )
                    except Exception as e:
                        failed_q.append(f"{c['rel_name']} ({e})")

                if moved_paths:
                    self.cache_db.invalidate_paths(moved_paths)
                    self._pending_review_items = [
                        x for x in self._pending_review_items if x["path"] not in moved_paths
                    ]
                    self._sync_review_button()

                self.refresh_quarantine_list()
                self.refresh_logs()
                if failed_q:
                    QMessageBox.warning(
                        self,
                        "Частичное перемещение в карантин",
                        f"В карантин помещено файлов: {quarantined_count}.\nОшибки:\n" + "\n".join(failed_q[:10]),
                    )
                else:
                    QMessageBox.information(
                        self,
                        "Готово",
                        f"Файлов помещено в карантин (.enc): {quarantined_count}.",
                    )
                return

            confirm_msg = (
                f"Вы выбрали файлов для удаления: {len(chosen)}.\n"
                f"Безвозвратно удалить отмеченные файлы?"
            )
            reply = QMessageBox.warning(
                self,
                "Подтверждение удаления выбранных файлов",
                confirm_msg,
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            if reply != QMessageBox.StandardButton.Yes:
                self.append_log("[🛡️ HITL] Финальное подтверждение удаления отклонено. Файлы не тронуты.", "INFO")
                return

            deleted_count = 0
            failed_items: list[str] = []
            deleted_paths: set[str] = set()

            for c in chosen:
                target_path = c["path"]
                if not os.path.exists(target_path):
                    deleted_paths.add(target_path)
                    continue
                try:
                    ok = False
                    if hasattr(self.quarantine, "shred_file"):
                        ok = bool(self.quarantine.shred_file(target_path))
                    if not ok and os.path.exists(target_path):
                        os.remove(target_path)
                        ok = not os.path.exists(target_path)

                    if ok and not os.path.exists(target_path):
                        deleted_count += 1
                        deleted_paths.add(target_path)
                        self.logger.log_event(
                            "USER_APPROVED_DELETE",
                            target_path,
                            "INFO",
                            f"Удалено по выбору пользователя ({c['reason']})",
                        )
                    else:
                        failed_items.append(f"{c['rel_name']} (файл занят или нет прав)")
                except Exception as e:
                    failed_items.append(f"{c['rel_name']} ({e})")

            if deleted_paths:
                self.cache_db.invalidate_paths(deleted_paths)
                self._pending_review_items = [
                    x for x in self._pending_review_items if x["path"] not in deleted_paths
                ]
                self._sync_review_button()

            self.refresh_logs()
            self.refresh_quarantine_list()
            self.append_log(
                f"[🗑️ CLEANUP] Удалено файлов: {deleted_count}"
                + (f", ошибок/заблокировано: {len(failed_items)}" if failed_items else ""),
                "INFO",
            )
            if failed_items:
                QMessageBox.warning(
                    self,
                    "Частичное удаление",
                    f"Удалено файлов: {deleted_count}.\nНе удалось удалить:\n" + "\n".join(failed_items[:10]),
                )
            else:
                QMessageBox.information(self, "Готово", f"Удалено файлов: {deleted_count}.")
        finally:
            self._review_dialog_open = False

    def _update_metrics(self):
        total_events = len(self._all_audit_rows)
        threats_count = sum(
            1 for r in self._all_audit_rows if str(r[4] or "").upper() in ("HIGH", "CRITICAL")
        )
        quarantine_count = self.quarantine_list.count()

        self.lbl_metric_total.setText(str(total_events))
        self.lbl_metric_threats.setText(str(threats_count))
        self.lbl_metric_quarantine.setText(str(quarantine_count))

    def choose_watch_folder(self):
        selected_dir = QFileDialog.getExistingDirectory(
            self,
            "Выберите папку в Windows для сканирования и мониторинга",
            self.watch_path if os.path.exists(self.watch_path) else BASE_DIR,
        )
        if not selected_dir:
            return

        abs_selected = os.path.abspath(selected_dir)
        if abs_selected == os.path.abspath(self.watch_path):
            return

        was_active = self._is_scan_or_watch_active()
        if was_active:
            self.stop_scan_and_monitoring()

        self.watch_path = abs_selected
        self._pending_review_items = []
        self._sync_review_button()
        self.lbl_folder.setText(f"Папка: {os.path.basename(self.watch_path) or self.watch_path}")
        self.lbl_folder.setToolTip(self.watch_path)
        self.append_log(f"[SYSTEM] Выбрана папка: {self.watch_path}", "INFO")

        if was_active:
            self.start_scan_and_monitoring()

    def append_log(self, message: str, tag: str = "INFO"):
        color_map = {
            "INFO": QColor("#38bdf8"),
            "LOW": QColor("#4ade80"),
            "HIGH": QColor("#f472b6"),
            "CRITICAL": QColor("#f87171"),
        }
        cursor = self.log_area.textCursor()
        cursor.movePosition(cursor.MoveOperation.End)

        fmt = cursor.charFormat()
        fmt.setForeground(color_map.get(tag, QColor("#e2e8f0")))
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
            self.lbl_ollama.setStyleSheet("color: #16a34a; font-weight: 700;")
        else:
            self.lbl_ollama.setText("ИИ: ОТКЛЮЧЕН")
            self.lbl_ollama.setStyleSheet("color: #dc2626; font-weight: 700;")

    def start_ollama_service(self):
        try:
            self.append_log("[SYSTEM] Запуск локального сервера Ollama...", "INFO")
            creation_flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
            subprocess.Popen(["ollama", "serve"], creationflags=creation_flags)
            QTimer.singleShot(3000, self.check_ollama_status)
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось запустить Ollama:\n{e}")

    def _start_watcher_only(self):
        if self.is_running:
            return
        os.makedirs(self.watch_path, exist_ok=True)
        handler = QtWatchdogHandler(self)
        self.observer = Observer()
        self.observer.schedule(handler, path=self.watch_path, recursive=True)
        self.observer.start()

        self.is_running = True
        self.append_log(f"[SYSTEM] Мониторинг запущен для каталога: {self.watch_path}", "INFO")

    def _stop_watcher_only(self):
        if self.observer:
            self.observer.stop()
            self.observer.join()
            self.observer = None

        if self.is_running:
            self.is_running = False
            self.append_log("[SYSTEM] Мониторинг остановлен.", "INFO")

    def _on_file_event(self, event_type: str, file_path: str):
        if not self.is_running:
            return

        ignore_exts, ignore_names = _parse_ignore_rules(self.ignore_rules_input.text())
        low_path = file_path.lower()
        low_name = os.path.basename(low_path)
        _, ext = os.path.splitext(low_name)
        if low_name in ignore_names or (ext and ext in ignore_exts):
            return
        try:
            rel_parts = {p.lower() for p in os.path.relpath(file_path, self.watch_path).split(os.sep)}
            if rel_parts & (SKIP_DIRS | ignore_names):
                return
        except ValueError:
            pass

        worker = FileAnalysisWorker(
            event_type=event_type,
            file_path=file_path,
            watch_root=self.watch_path,
            db_path=self.db_path,
            extractor=self.extractor,
            analyzer=self.analyzer,
            logger=self.logger,
        )
        worker.log_ready.connect(self.append_log)
        worker.audit_updated.connect(self.refresh_logs)
        worker.review_item_ready.connect(lambda item: self._add_pending_review_items([item], open_dialog=False))
        worker.finished.connect(lambda w=worker: self._cleanup_worker(w))
        self._workers.append(worker)
        worker.start()

    def _cleanup_worker(self, worker: QThread):
        if worker in self._workers:
            self._workers.remove(worker)
        worker.deleteLater()

    def send_side_chat_message(self):
        user_text = self.side_chat_input.text().strip()
        if not user_text:
            return

        self.side_chat_input.clear()
        self.btn_side_send.setEnabled(False)
        self.side_chat_display.append(f"<b>Вы:</b> {user_text}")

        folder_ctx = self._last_folder_report if self._last_folder_report else (
            f"Сканирование ещё не запускалось. Выбранная папка: {self.watch_path}"
        )
        augmented_prompt = (
            f"РЕАЛЬНЫЕ ДАННЫЕ СКАНИРОВАНИЯ (только эти файлы существуют в папке):\n{folder_ctx}\n\n"
            f"Вопрос пользователя: {user_text}\n"
            f"Напоминание: упоминай ТОЛЬКО файлы из списка выше и не придумывай других."
        )

        messages_to_send = [self._chat_history[0], {"role": "user", "content": augmented_prompt}]
        self._chat_history.append({"role": "user", "content": user_text})

        worker = ChatWorker(messages_to_send, model="llama3.2")
        worker.reply_ready.connect(self._on_side_chat_reply)
        worker.reply_error.connect(self._on_side_chat_error)
        worker.finished.connect(lambda: self.btn_side_send.setEnabled(True))
        worker.finished.connect(lambda w=worker: self._cleanup_worker(w))
        self._workers.append(worker)
        worker.start()

    def _on_side_chat_reply(self, reply: str):
        self._chat_history.append({"role": "assistant", "content": reply})
        safe_reply = reply.replace("\n", "<br>")
        self.side_chat_display.append(f"<b>ИИ:</b> {safe_reply}<br>")
        self.side_chat_display.ensureCursorVisible()

    def _on_side_chat_error(self, err: str):
        if self._chat_history and self._chat_history[-1]["role"] == "user":
            self._chat_history.pop()
        self.side_chat_display.append(f"<span style='color:#dc2626;'><b>Ошибка:</b> {err}</span><br>")
        self.side_chat_display.ensureCursorVisible()

    def refresh_quarantine_list(self):
        self.quarantine_list.clear()
        q_dir = getattr(self.quarantine, "quarantine_dir", os.path.join(BASE_DIR, "quarantine"))

        if hasattr(self.quarantine, "list_quarantined"):
            enc_files = self.quarantine.list_quarantined()
        else:
            if not os.path.exists(q_dir):
                self._update_metrics()
                return
            enc_files = [
                os.path.join(q_dir, name)
                for name in sorted(os.listdir(q_dir))
                if os.path.isfile(os.path.join(q_dir, name)) and name.endswith(".enc")
            ]

        for enc_path in enc_files:
            self.quarantine_list.addItem(os.path.basename(enc_path))

        self._update_metrics()

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

        if hasattr(self.quarantine, "shred_quarantined"):
            ok = self.quarantine.shred_quarantined(enc_path)
        else:
            ok = self.quarantine.shred_file(enc_path)

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

    def _reset_audit_filters(self):
        self.combo_threat_filter.setCurrentText("ALL")
        self.search_input.clear()
        self._apply_audit_filters()

    def _apply_audit_filters(self):
        threat_filter = self.combo_threat_filter.currentText().strip().upper()
        query = self.search_input.text().strip().lower()

        filtered = []
        for row in self._all_audit_rows:
            status_val = str(row[4] or "").upper()
            if threat_filter != "ALL" and status_val != threat_filter:
                continue

            if query:
                haystack = f"{row[2] or ''} {row[3] or ''} {row[4] or ''} {row[5] or ''}".lower()
                if query not in haystack:
                    continue

            filtered.append(row)

        self.table.setRowCount(len(filtered))
        for r_idx, row in enumerate(filtered):
            for c_idx, val in enumerate(row):
                item = QTableWidgetItem("" if val is None else str(val))
                if c_idx in (0, 2, 4):
                    item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                self.table.setItem(r_idx, c_idx, item)

        self.lbl_audit_count.setText(f"Показано записей: {len(filtered)} из {len(self._all_audit_rows)}")

    def refresh_logs(self):
        self._all_audit_rows = []
        if not os.path.exists(self.db_path):
            self._apply_audit_filters()
            self._update_metrics()
            return

        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT id, timestamp, event_type, filename, status, details FROM audit_logs ORDER BY id DESC"
                )
                self._all_audit_rows = cursor.fetchall()
            self._apply_audit_filters()
            self._update_metrics()
        except Exception as e:
            QMessageBox.critical(self, "Ошибка БД", f"Не удалось прочитать базу данных:\n{e}")

    def closeEvent(self, event):
        if self._active_scan_worker is not None and self._active_scan_worker.isRunning():
            self._active_scan_worker.requestInterruption()
            self._active_scan_worker.wait(2000)

        self._stop_watcher_only()

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