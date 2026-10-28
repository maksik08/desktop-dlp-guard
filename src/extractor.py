import os
import time
import pymupdf
from docx import Document
import easyocr


class TextExtractor:
    """Универсальный класс для извлечения текста из файлов различных форматов."""

    _ocr_reader = None

    @classmethod
    def _get_ocr_reader(cls):
        if cls._ocr_reader is None:
            print("[*] Инициализация OCR-модуля (EasyOCR)...")
            cls._ocr_reader = easyocr.Reader(['ru', 'en'], gpu=False)
        return cls._ocr_reader

    @staticmethod
    def extract_text(file_path: str) -> str:
        if not os.path.exists(file_path):
            return ""

        ext = os.path.splitext(file_path)[1].lower()

        if ext in [".txt", ".log", ".csv", ".json", ".md"]:
            return TextExtractor._extract_from_text(file_path)
        elif ext == ".docx":
            return TextExtractor._extract_from_docx(file_path)
        elif ext == ".pdf":
            return TextExtractor._extract_from_pdf(file_path)
        elif ext in [".png", ".jpg", ".jpeg", ".bmp", ".tiff"]:
            return TextExtractor._extract_from_image(file_path)

        return ""

    @staticmethod
    def _extract_from_text(file_path: str) -> str:
        """Чтение текстовых файлов с защитой от блокировок ОС и кодировок."""
        # Делаем до 3 попыток на случай, если файл еще занят процессом записи
        for attempt in range(3):
            for encoding in ["utf-8", "cp1251", "latin-1"]:
                try:
                    with open(file_path, "r", encoding=encoding) as f:
                        return f.read()
                except UnicodeDecodeError:
                    continue
                except PermissionError:
                    # Файл заблокирован ОС/редактором, ждем 0.2 сек и пробуем снова
                    time.sleep(0.2)
                    break
        return ""

    @staticmethod
    def _extract_from_docx(file_path: str) -> str:
        try:
            doc = Document(file_path)
            return "\n".join([p.text for p in doc.paragraphs])
        except Exception as e:
            print(f"[!] Ошибка чтения DOCX: {e}")
            return ""

    @staticmethod
    def _extract_from_pdf(file_path: str) -> str:
        try:
            text = ""
            with pymupdf.open(file_path) as doc:
                for page in doc:
                    text += page.get_text() + "\n"
            return text
        except Exception as e:
            print(f"[!] Ошибка чтения PDF: {e}")
            return ""

    @staticmethod
    def _extract_from_image(file_path: str) -> str:
        try:
            reader = TextExtractor._get_ocr_reader()
            results = reader.readtext(file_path, detail=0)
            return "\n".join(results)
        except Exception as e:
            print(f"[!] Ошибка OCR: {e}")
            return ""