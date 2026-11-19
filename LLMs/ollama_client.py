"""
LLMs/ollama_client.py
Minimal HTTP client for a locally-running Ollama server
(https://ollama.com). Used to generate natural-language explanations
of detected threats without sending any data to a third-party cloud API.
"""

import requests
from config import Config


class OllamaClient:
    def __init__(self, host: str = None, model: str = None, timeout: int = None):
        self.host = (host or Config.OLLAMA_HOST).rstrip("/")
        self.model = model or Config.OLLAMA_MODEL
        self.timeout = timeout or Config.OLLAMA_TIMEOUT

    def is_available(self) -> bool:
        try:
            resp = requests.get(f"{self.host}/api/tags", timeout=3)
            return resp.status_code == 200
        except requests.RequestException:
            return False

    def generate(self, prompt: str) -> str:
        """
        Sends a prompt to the local Ollama /api/generate endpoint.
        Raises RuntimeError on failure so callers can fall back gracefully.
        """
        try:
            resp = requests.post(
                f"{self.host}/api/generate",
                json={"model": self.model, "prompt": prompt, "stream": False},
                timeout=self.timeout,
            )
            resp.raise_for_status()
            data = resp.json()
            return data.get("response", "").strip()
        except requests.RequestException as exc:
            raise RuntimeError(f"Ollama request failed: {exc}") from exc
