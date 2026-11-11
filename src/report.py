import sqlite3
import os


def show_audit_logs():
    # Путь к базе данных в папке logs
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    db_path = os.path.join(base_dir, "logs", "dlp.db")

    if not os.path.exists(db_path):
        print(f"[!] База данных еще не найдена по пути: {db_path}")
        print("[!] Сначала выполните хотя бы одно тестирование с файлом-угрозой.")
        return

    print("=" * 95)
    print(f" 🛡️  ОТЧЕТ ПО ИНЦИДЕНТАМ И АУДИТУ DLP-СИСТЕМЫ")
    print(f" 📂  База данных: {db_path}")
    print("=" * 95)

    try:
        with sqlite3.connect(db_path) as conn:
            cursor = conn.cursor()
            # Проверяем структуру таблицы и выводим данные
            cursor.execute("SELECT id, timestamp, event_type, filename, status FROM audit_logs ORDER BY id DESC")
            rows = cursor.fetchall()

            if not rows:
                print("📭 В базе данных пока нет записей об инцидентах.")
                return

            print(f"{'ID':<4} | {'Дата и время':<20} | {'Событие':<14} | {'Имя файла':<22} | {'Статус угрозы':<15}")
            print("-" * 95)
            for row in rows:
                print(f"{row[0]:<4} | {row[1]:<20} | {row[2]:<14} | {row[3]:<22} | {row[4]:<15}")

            print("=" * 95)
            print(f"Всего зафиксировано инцидентов: {len(rows)}")
    except Exception as e:
        print(f"[!] Ошибка при чтении базы данных: {e}")
    print("=" * 95)


if __name__ == "__main__":
    show_audit_logs()