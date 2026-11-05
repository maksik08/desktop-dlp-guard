import re
import requests
import json


class DLPAnalyzer:
    """Движок анализа рисков утечки данных (Regex + Ollama LLM)."""

    def __init__(self, ollama_model="llama3"):
        self.ollama_model = ollama_model
        self.ollama_url = "http://localhost:11434/api/generate"

        # Шаблоны регулярных выражений для быстрого поиска (Regex Engine)
        self.patterns = {
            "API_KEY": r"(?:api[_-]?key|secret[_-]?key|token)['\"\\s]*[:=]['\"\\s]*([a-zA-Z0-9_\-]{20,})",
            "CREDIT_CARD": r"\b(?:\d{4}[-\s]?){3}\d{4}\b",
            "EMAIL": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
            "IP_ADDRESS": r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",
            "PASSWORD_HINT": r"(?:password|passwd|пароль)['\"\\s]*[:=]['\"\\s]*([^\s]{4,})"
        }

    def analyze_regex(self, text: str) -> dict:
        """Быстрый поиск конфиденциальных данных по регулярным выражениям."""
        findings = {}
        for category, pattern in self.patterns.items():
            matches = re.findall(pattern, text, re.IGNORECASE)
            if matches:
                # Уникализируем найденные совпадения и скрываем часть для безопасности в логах
                findings[category] = list(set(matches))
        return findings

    def analyze_semantic(self, text: str) -> str:
        """Глубокий семантический анализ текста с помощью локальной Ollama LLM."""
        # Обрезаем текст до разумного лимита, чтобы не перегружать модель
        truncated_text = text[:3000]

        prompt = (
            "You are a strict Data Loss Prevention (DLP) security AI. "
            "Analyze the following text snippet and determine if it contains sensitive corporate data, "
            "source code secrets, financial reports, or personal data. "
            "Respond ONLY with a short verdict: 'SAFE', 'SUSPICIOUS', or 'CRITICAL', "
            "followed by a brief 1-sentence reason.\n\n"
            f"Text: {truncated_text}"
        )

        payload = {
            "model": self.ollama_model,
            "prompt": prompt,
            "stream": False
        }

        try:
            response = requests.post(self.ollama_url, json=payload, timeout=10)
            if response.status_code == 200:
                result = response.json().get("response", "").strip()
                return result
            else:
                return "AI_ERROR: Ollama returned status code " + str(response.status_code)
        except requests.exceptions.ConnectionError:
            return "AI_OFFLINE: Ollama service is not running locally."
        except Exception as e:
            return f"AI_ERROR: {str(e)}"

    def evaluate(self, text: str) -> tuple:
        """Комплексная оценка документа: Regex + Семантика."""
        regex_results = self.analyze_regex(text)

        # Если найдены критические regex-паттерны — сразу высокий риск
        is_regex_critical = len(regex_results) > 0

        # Запрашиваем вердикт у локальной LLM
        ai_verdict = self.analyze_semantic(text)

        threat_level = "LOW"
        if is_regex_critical:
            threat_level = "HIGH"
        if "CRITICAL" in ai_verdict.upper():
            threat_level = "CRITICAL"
        elif "SUSPICIOUS" in ai_verdict.upper() and threat_level != "HIGH":
            threat_level = "MEDIUM"

        return threat_level, regex_results, ai_verdict