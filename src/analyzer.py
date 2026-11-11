import re
import requests


class DLPAnalyzer:

    def __init__(self, model_name="llama3.2"):
        self.model_name = model_name
        self.url = "http://localhost:11434/api/generate"

        # Сигнатуры для быстрого regex-анализа (API-ключи, пароли, AWS ключи)
        self.patterns = {
            "API_KEY": r"(?:api[_-]?key|access[_-]?token)['\"\\s]*[:=]['\"\\s]*([a-zA-Z0-9_\\-]{16,})",
            "PASSWORD": r"(?:password|passwd|pwd)['\"\\s]*[:=]['\"\\s]*([^\s'\"]{6,})",
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
        prompt = (
            "Analyze the following text for sensitive data (API keys, passwords, PII, confidential records). "
            "Return threat level (LOW, HIGH, CRITICAL) and a brief reason:\n\n"
            f"{text}"
        )

        payload = {
            "model": self.model_name,
            "prompt": prompt,
            "stream": False,
            "options": {
                "num_predict": 50,  # Жестко ограничиваем длину ответа для мгновенной работы
                "temperature": 0.1  # Строгий и детерминированный ответ
            }
        }

        try:
            # Запрос к локальному серверу Ollama с тайм-аутом 15 секунд
            response = requests.post(self.url, json=payload, timeout=15)
            if response.status_code == 200:
                data = response.json()
                return data.get("response", "").strip()
            else:
                return f"AI_ERROR: HTTP status {response.status_code}"
        except requests.exceptions.ConnectionError:
            return "AI_OFFLINE: Ollama service is not running locally."
        except requests.exceptions.Timeout:
            return "AI_ERROR: Read timed out."
        except Exception as e:
            return f"AI_ERROR: {str(e)}"

    def evaluate(self, text: str):
        # 1. Первичная проверка регулярными выражениями
        regex_results = self._regex_check(text)

        threat_level = "LOW"
        if regex_results:
            threat_level = "HIGH"

        # 2. Семантический анализ через легкую локальную модель llama3.2
        ai_verdict = self._ai_check(text)

        # 3. Синтез общего вердикта угрозы
        ai_upper = ai_verdict.upper()
        if "CRITICAL" in ai_upper:
            threat_level = "CRITICAL"
        elif "HIGH" in ai_upper and threat_level != "CRITICAL":
            threat_level = "HIGH"

        return threat_level, regex_results, ai_verdict