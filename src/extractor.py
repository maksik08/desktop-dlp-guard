import os
import fitz  # PyMuPDF для работы с PDF
from docx import Document  # python-docx для работы с Word


class TextExtractor:

    @staticmethod
    def extract_text(file_path: str) -> str:

        if not os.path.exists(file_path):
            return ""

        ext = os.path.splitext(file_path)[1].lower()

        # 1. Текстовые форматы
        if ext in [".txt", ".log", ".csv", ".json", ".md"]:
            return TextExtractor._extract_from_text(file_path)

        # 2. Документы Word
        elif ext == ".docx":
            return TextExtractor._extract_from_docx(file_path)

        # 3. Документы PDF
        elif ext == ".pdf":
            return TextExtractor._extract_from_pdf(file_path)

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

    @staticmethod
    def _extract_from_docx(file_path: str) -> str:

        try:
            doc = Document(file_path)
            full_text = [paragraph.text for paragraph in doc.paragraphs]
            return "\n".join(full_text)
        except Exception as e:
            print(f"[!] Ошибка чтения DOCX файла {file_path}: {e}")
            return ""

    @staticmethod
    def _extract_from_pdf(file_path: str) -> str:

        try:
            text = ""
            with fitz.open(file_path) as doc:
                for page in doc:
                    text += page.get_text() + "\n"
            return text
        except Exception as e:
            print(f"[!] Ошибка чтения PDF файла {file_path}: {e}")
            return ""