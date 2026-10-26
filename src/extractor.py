import os
import fitz
from docx import Document
import easyocr


class TextExtractor:

    _ocr_reader = None

    @classmethod
    def _get_ocr_reader(cls):
        if cls._ocr_reader is None:
            print("[*] Инициализация OCR-модуля (EasyOCR)... Это может занять пару секунд.")
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

    @staticmethod
    def _extract_from_image(file_path: str) -> str:
        try:
            reader = TextExtractor._get_ocr_reader()
            # detail=0 возвращает только список распознанных строк текста
            results = reader.readtext(file_path, detail=0)
            return "\n".join(results)
        except Exception as e:
            print(f"[!] Ошибка OCR-распознавания для файла {file_path}: {e}")
            return ""