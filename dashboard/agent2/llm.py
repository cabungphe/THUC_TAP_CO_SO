from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Protocol

from .security import redact_secrets


class LLMError(RuntimeError):
    pass


class LLMClient(Protocol):
    def complete(self, messages: list[dict[str, str]]) -> str:
        ...


@dataclass
class OpenAICompatibleClient:
    """Minimal client for OpenAI-compatible /chat/completions endpoints."""

    api_key: str = field(repr=False)
    base_url: str
    model: str
    temperature: float = 0.1
    timeout_seconds: int = 90

    @classmethod
    def from_env(cls) -> "OpenAICompatibleClient":
        api_key = os.getenv("AGENT2_API_KEY", "").strip()
        base_url = os.getenv("AGENT2_BASE_URL", "https://api.cerebras.ai/v1").strip().rstrip("/")
        model = os.getenv("AGENT2_MODEL", "qwen-3.8-27b").strip()
        missing = [
            name
            for name, value in (
                ("AGENT2_API_KEY", api_key),
                ("AGENT2_BASE_URL", base_url),
                ("AGENT2_MODEL", model),
            )
            if not value
        ]
        if missing:
            raise LLMError(f"Missing environment variables: {', '.join(missing)}")
        return cls(api_key=api_key, base_url=base_url, model=model)

    def complete(self, messages: list[dict[str, str]]) -> str:
        url = f"{self.base_url}/chat/completions"
        payload = json.dumps(
            {
                "model": self.model,
                "messages": messages,
                "temperature": self.temperature,
            }
        ).encode("utf-8")
        request = urllib.request.Request(
            url,
            data=payload,
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
                "Accept": "application/json",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Agent2/1.0",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout_seconds) as response:
                body = response.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            detail = exc.read(16000).decode("utf-8", errors="replace")
            is_html = "text/html" in (exc.headers.get("Content-Type", "").lower()) or "<html" in detail.lower()
            if exc.code == 403 and is_html and "cloudflare" in detail.lower():
                ray = redact_secrets(exc.headers.get("CF-Ray", "unknown"), (self.api_key,))
                raise LLMError(
                    f"LLM HTTP 403: Cloudflare blocked the request before a model response. "
                    f"CF-Ray: {ray}. Test the API connection in the sidebar. If that succeeds "
                    "but finding analysis fails, request content may be triggering the gateway. "
                    "This is not a finding-schema error or a completed security analysis."
                ) from None
            detail = redact_secrets(detail, (self.api_key,))[:1000]
            raise LLMError(f"LLM HTTP {exc.code}: {detail}") from None
        except (urllib.error.URLError, TimeoutError, ValueError, OSError) as exc:
            detail = redact_secrets(exc, (self.api_key,))[:1000]
            raise LLMError(f"LLM request failed: {detail}") from None

        try:
            data = json.loads(body)
            return data["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError, json.JSONDecodeError) as exc:
            raise LLMError("Unexpected LLM response format") from exc
