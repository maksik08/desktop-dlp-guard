import os


class TextExtractor:

    @staticmethod
    def extract_text(file_path: str) -> str:

        if not os.path.exists(file_path):
            return ""

        ext = os.path.splitext(file_path)[1].lower()

        # 1. Текстовые форматы
        if ext in [".txt", ".log", ".csv", ".json", ".md"]:
            return TextExtractor._extract_from_text(file_path)

        return ""

    @staticmethod
    def _extract_from_text(file_path: str) -> str:
        "Чтение обычных текстовых файлов с защитой от кодировок."
        for encoding in ["utf-8", "cp1251", "latin-1"]:
            try:
                with open(file_path, "r", encoding=encoding) as f:
                    return f.read()
            except UnicodeDecodeError:
                continue
        return ""