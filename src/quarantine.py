import os
import shutil
from datetime import datetime


class QuarantineManager:

    def __init__(self, quarantine_dir="quarantine"):
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.quarantine_dir = os.path.join(base_dir, quarantine_dir)
        self._ensure_dir()

    def _ensure_dir(self):
        if not os.path.exists(self.quarantine_dir):
            try:
                os.makedirs(self.quarantine_dir)
            except Exception:
                pass

    def isolate_file(self, file_path: str, threat_level: str) -> str:
        if threat_level not in ["HIGH", "CRITICAL"]:
            return ""

        if not os.path.exists(file_path):
            return ""

        filename = os.path.basename(file_path)
        name, ext = os.path.splitext(filename)
        timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
        quarantine_filename = f"{name}_{timestamp_str}_{threat_level}{ext}"
        destination_path = os.path.join(self.quarantine_dir, quarantine_filename)

        try:
            shutil.move(file_path, destination_path)
            print(f" [🚨 QUARANTINE] Файл изолирован в карантин: {destination_path}")
            return destination_path
        except Exception as e:
            print(f"[!] Ошибка перемещения файла в карантин: {e}")
            return ""