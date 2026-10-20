"""Keep credentials out of child processes and user-visible diagnostics."""
from __future__ import annotations

import json
import os
import re
from collections.abc import Mapping, Iterable
from urllib.parse import quote, quote_plus


_SENSITIVE_ENV_PARTS = (
    "API_KEY", "ACCESS_KEY", "SECRET", "PASSWORD", "PASSWD", "TOKEN",
    "CREDENTIAL", "PRIVATE_KEY", "AUTH", "COOKIE", "SESSION",
    "DATABASE_URL", "CONNECTION_STRING", "DSN",
)
_ASSIGNMENT = re.compile(
    r"(?i)((?<![\w-])['\"]?(?:[\w-]*(?:api[_-]?key|access[_-]?key|secret|"
    r"token|password|passwd|credential|private[_-]?key|authorization|cookie)[\w-]*|"
    r"key)['\"]?\s*[:=]\s*['\"]?)"
    r"([^\s'\"&,;}]+)"
)
_BEARER = re.compile(r"(?i)\b(Bearer|Basic)\s+([A-Za-z0-9._~+/=-]+)")
_URL_USERINFO = re.compile(r"(?i)(https?://)[^\s/@]+@")
_KNOWN_TOKEN = re.compile(
    r"\b(?:sk-[A-Za-z0-9_-]{8,}|AIza[A-Za-z0-9_-]{20,}|"
    r"gh[pousr]_[A-Za-z0-9_]{20,}|AKIA[A-Z0-9]{16}|xox[baprs]-[A-Za-z0-9-]{16,})\b"
)


def sensitive_env_name(name: str) -> bool:
    """Identify variables that could hold credentials, regardless of provider."""
    upper = name.upper()
    return upper == "KEY" or any(part in upper for part in _SENSITIVE_ENV_PARTS)


def secret_values_from_env(env: Mapping[str, str] | None = None) -> tuple[str, ...]:
    values = os.environ if env is None else env
    return tuple(value for name, value in values.items()
                 if sensitive_env_name(name) and len(value) >= 4)


def child_process_env(env: Mapping[str, str] | None = None) -> dict[str, str]:
    """Run the Google-login CLI and project checks without inherited API credentials."""
    source = os.environ if env is None else env
    return {name: value for name, value in source.items()
            if not sensitive_env_name(name)}


def redact_secrets(value: object, secrets: Iterable[str] = ()) -> str:
    """Sanitize diagnostics before sending them to a browser or writing a log."""
    text = str(value)
    known = set(secret_values_from_env())
    known.update(secret for secret in secrets if secret)
    for secret in sorted(known, key=len, reverse=True):
        # APIs sometimes echo URL-encoded or JSON-escaped credentials.
        variants = (secret, quote(secret, safe=""), quote_plus(secret),
                    json.dumps(secret, ensure_ascii=True)[1:-1])
        for variant in variants:
            if variant:
                text = text.replace(variant, "[REDACTED]")
    text = _URL_USERINFO.sub(r"\1[REDACTED]@", text)
    text = _BEARER.sub(r"\1 [REDACTED]", text)
    text = _ASSIGNMENT.sub(r"\1[REDACTED]", text)
    return _KNOWN_TOKEN.sub("[REDACTED]", text)


def redact_data(value: object, secrets: Iterable[str] = ()) -> object:
    """Preserve JSON-like structure while cleaning text supplied to the UI."""
    if isinstance(value, str):
        return redact_secrets(value, secrets)
    if isinstance(value, dict):
        return {redact_secrets(key, secrets) if isinstance(key, str) else key:
                ("[REDACTED]" if isinstance(key, str) and
                 sensitive_env_name(key) and isinstance(item, str)
                 else redact_data(item, secrets))
                for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact_data(item, secrets) for item in value]
    return value
