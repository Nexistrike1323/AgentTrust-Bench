from __future__ import annotations

import json
from urllib.error import URLError, HTTPError
from urllib.request import Request, urlopen


class ProviderError(RuntimeError):
    pass


class OllamaProvider:
    """Minimal Ollama chat adapter. Talks only to the local Ollama endpoint."""

    name = "ollama"

    def __init__(self, model: str, base_url: str = "http://127.0.0.1:11434", timeout: int = 120):
        if not model or not model.strip():
            raise ValueError("A local Ollama model name is required")
        if not base_url.startswith("http://127.0.0.1") and not base_url.startswith("http://localhost"):
            raise ValueError("For this release, Ollama must use a localhost URL")
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def generate(self, messages: list[dict[str, str]]) -> str:
        payload = {
            "model": self.model,
            "messages": messages,
            "stream": False,
            "options": {"temperature": 0},
        }
        request = Request(
            self.base_url + "/api/chat",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urlopen(request, timeout=self.timeout) as response:
                body = json.loads(response.read().decode("utf-8"))
        except (HTTPError, URLError, TimeoutError, OSError, json.JSONDecodeError) as exc:
            raise ProviderError(
                f"Could not query local Ollama at {self.base_url}: {exc}. "
                "Check that Ollama is running and the model is installed."
            ) from exc

        try:
            content = body["message"]["content"]
        except (KeyError, TypeError) as exc:
            raise ProviderError("Ollama returned an unexpected chat response") from exc
        if not isinstance(content, str) or not content.strip():
            raise ProviderError("Ollama returned an empty model response")
        return content.strip()
