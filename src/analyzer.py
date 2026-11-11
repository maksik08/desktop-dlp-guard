import re
import requests


class DLPAnalyzer:

    def __init__(self, model_name="llama3.2"):
        self.model_name = model_name
        self.url = "http://localhost:11434/api/generate"

        # Расширенные сигнатуры (включая русские ключевые слова и ключи)
        self.patterns = {
            "API_KEY": r"(?:api[_-]?key|access[_-]?token)['\"\\s]*[:=]['\"\\s]*([a-zA-Z0-9_\\-]{16,})",
            "PASSWORD": r"(?:password|passwd|pwd|пароль)['\"\\s]*[:=]['\"\\s]*([^\s'\"]{4,})",
            "AWS_KEY": r"AKIA[0-9A-Z]{16}"
        }

    def _regex_check(self, text: str) -> dict:
        found = {}
        for name, pattern in self.patterns.items():
            matches = re.findall(pattern, text, re.IGNORECASE)
            if matches:
                found[name] = matches
        return found

    def _ai_check(self, text: str) -> str:
        # Нейтральный промпт для классификации, который не вызывает отказ системы безопасности ИИ
        prompt = (
            "Task: Data classification for system compliance audit. "
            "Analyze the text snippet below and determine if it contains sensitive technical data, credentials, or keys. "
            "Output format requirement: Start with risk level (LOW, HIGH, or CRITICAL) followed by a short reason.\n\n"
            f"Text: {text}"
        )

        payload = {
            "model": self.model_name,
            "prompt": prompt,
            "stream": False,
            "options": {
                "num_predict": 40,
                "temperature": 0.1
            }
        }

        try:
            response = requests.post(self.url, json=payload, timeout=20)
            if response.status_code == 200:
                data = response.json()
                res_text = data.get("response", "").strip()
                # Если модель все же попыталась выдать отказ, подменяем на нейтральный ответ
                if "I cannot" in res_text or "I can't" in res_text:
                    return "HIGH: Potential sensitive credential detected."
                return res_text
            else:
                return f"AI_ERROR: HTTP status {response.status_code}"
        except Exception as e:
            return f"AI_ERROR: {str(e)}"

    def evaluate(self, text: str):
        # 1. Первичная проверка регулярными выражениями
        regex_results = self._regex_check(text)

        threat_level = "LOW"
        if regex_results:
            threat_level = "HIGH"

        # 2. Семантический анализ через ИИ
        ai_verdict = self._ai_check(text)

        # 3. Синтез общего вердикта угрозы
        ai_upper = ai_verdict.upper()
        if "CRITICAL" in ai_upper:
            threat_level = "CRITICAL"
        elif "HIGH" in ai_upper and threat_level != "CRITICAL":
            threat_level = "HIGH"

        return threat_level, regex_results, ai_verdict