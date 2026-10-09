import os
from pathlib import Path

# Базовый путь к проекту
BASE_DIR = Path(__file__).resolve().parent.parent

# Отслеживаемые директории по умолчанию
WATCH_DIRECTORIES = [
    os.path.join(BASE_DIR, "test_folder"),
    # Можно добавить путь к папке Загрузки пользователя:
    # os.path.join(Path.home(), "Downloads")
]

# Игнорируемые расширения (временные файлы Word, системные файлы, кэш)
IGNORED_EXTENSIONS = {
    ".tmp", ".crdownload", ".part", ".swp", ".lock", ".ds_store"
}

# Игнорируемые префиксы имен (например, временные файлы Office ~$doc.docx)
IGNORED_PREFIXES = ("~$", ".~", ".")

# Максимальный размер файла для сканирования (например, до 50 МБ)
MAX_FILE_SIZE_BYTES = 50 * 1024 * 1024