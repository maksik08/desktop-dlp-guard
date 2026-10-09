import os
from src.config import WATCH_DIRECTORIES
from src.watcher import DLPWatcher


def init_environment():
    """Проверка и подготовка рабочих директорий."""
    for folder in WATCH_DIRECTORIES:
        os.makedirs(folder, exist_ok=True)


if __name__ == "__main__":
    print("=" * 50)
    print(" AI Desktop Sentinel & DLP Guard — Core System (Lab 1)")
    print("=" * 50)

    init_environment()

    watcher_service = DLPWatcher(watch_paths=WATCH_DIRECTORIES)
    watcher_service.start()