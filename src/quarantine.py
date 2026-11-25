import os
import json
import time
import base64
import shutil
from datetime import datetime
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class QuarantineManager:
    """Менеджер карантина с шифрованием AES-256 и безопасным уничтожением (Secure Shredding)."""

    def __init__(self, quarantine_dir: str = "quarantine", shred_passes: int = 3):
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.quarantine_dir = os.path.join(base_dir, quarantine_dir)
        self.keys_dir = os.path.join(self.quarantine_dir, ".keys")
        self.shred_passes = max(1, shred_passes)

        os.makedirs(self.quarantine_dir, exist_ok=True)
        os.makedirs(self.keys_dir, exist_ok=True)

        self.key_path = os.path.join(self.keys_dir, "aes256.key")
        self.key = self._load_or_create_key()

    def _load_or_create_key(self) -> bytes:
        """Загружает существующий 256-битный ключ или генерирует новый."""
        if os.path.exists(self.key_path):
            with open(self.key_path, "rb") as f:
                raw = f.read().strip()
                # Поддерживаем как raw 32 байта, так и base64
                try:
                    key = base64.urlsafe_b64decode(raw)
                    if len(key) == 32:
                        return key
                except Exception:
                    pass
                if len(raw) == 32:
                    return raw

        key = AESGCM.generate_key(bit_length=256)
        with open(self.key_path, "wb") as f:
            f.write(base64.urlsafe_b64encode(key))
        return key

    def shred_file(self, file_path: str) -> bool:
        """
        Безвозвратное уничтожение файла (Secure Shredding):
        перезаписывает содержимое случайными байтами и нулями в N проходов,
        очищает размер, переименовывает и удаляет.
        """
        if not os.path.exists(file_path) or not os.path.isfile(file_path):
            return False

        try:
            file_size = os.path.getsize(file_path)
            with open(file_path, "r+b") as f:
                for pass_num in range(self.shred_passes):
                    f.seek(0)
                    remaining = file_size
                    chunk_size = 65536
                    while remaining > 0:
                        write_len = min(chunk_size, remaining)
                        if pass_num == self.shred_passes - 1:
                            # Последний проход — нули
                            f.write(b"\x00" * write_len)
                        else:
                            f.write(os.urandom(write_len))
                        remaining -= write_len
                    f.flush()
                    os.fsync(f.fileno())

                # Обрезаем файл до 0 байт перед удалением
                f.truncate(0)
                f.flush()
                os.fsync(f.fileno())

            # Переименовываем перед удалением, чтобы скрыть исходное имя в каталоге
            parent_dir = os.path.dirname(file_path)
            temp_name = os.path.join(parent_dir, f".shred_{os.getpid()}_{int(time.time() * 1000)}")
            os.replace(file_path, temp_name)
            os.remove(temp_name)
            return True
        except Exception as e:
            print(f"[!] Ошибка при шредировании файла {file_path}: {e}")
            return False

    def isolate(self, file_path: str, threat_level: str = "HIGH") -> str:
        """
        Шифрует файл алгоритмом AES-256-GCM, сохраняет в карантин (.enc)
        и безвозвратно уничтожает исходный файл.
        """
        if not os.path.exists(file_path):
            return ""

        original_name = os.path.basename(file_path)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        enc_filename = f"{ts}_{threat_level}_{original_name}.enc"
        enc_path = os.path.join(self.quarantine_dir, enc_filename)

        with open(file_path, "rb") as f:
            plaintext = f.read()

        nonce = os.urandom(12)  # Рекомендуемый размер nonce для AES-GCM — 96 бит (12 байт)
        metadata = {
            "original_filename": original_name,
            "original_path": file_path,
            "threat_level": threat_level,
            "isolated_at": datetime.now().isoformat(),
            "original_size": len(plaintext),
        }
        aad = json.dumps(metadata, ensure_ascii=False).encode("utf-8")

        aesgcm = AESGCM(self.key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, aad)

        # Формат контейнера:
        # [4 байта длина AAD][AAD JSON][12 байт nonce][ciphertext + GCM tag]
        aad_len_bytes = len(aad).to_bytes(4, byteorder="big")
        with open(enc_path, "wb") as out:
            out.write(aad_len_bytes)
            out.write(aad)
            out.write(nonce)
            out.write(ciphertext)

        # Безвозвратно затираем и удаляем исходный файл
        self.shred_file(file_path)
        return enc_path

    def decrypt_file(self, enc_path: str, output_dir: str | None = None) -> str:
        """Расшифровывает .enc файл из карантина (например, при проверке ложного срабатывания)."""
        if not os.path.exists(enc_path):
            raise FileNotFoundError(f"Зашифрованный файл не найден: {enc_path}")

        with open(enc_path, "rb") as f:
            aad_len = int.from_bytes(f.read(4), byteorder="big")
            aad = f.read(aad_len)
            nonce = f.read(12)
            ciphertext = f.read()

        metadata = json.loads(aad.decode("utf-8"))
        aesgcm = AESGCM(self.key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, aad)

        target_dir = output_dir or self.quarantine_dir
        os.makedirs(target_dir, exist_ok=True)
        restored_path = os.path.join(target_dir, f"restored_{metadata['original_filename']}")

        with open(restored_path, "wb") as out:
            out.write(plaintext)

        return restored_path