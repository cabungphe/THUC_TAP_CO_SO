from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Agent2Config:
    """Hard limits for one isolated finding analysis run."""

    max_steps: int = 14
    max_tool_calls: int = 10
    max_search_results: int = 20
    max_read_lines: int = 220
    max_file_bytes: int = 512_000
    max_json_retries: int = 2

    allowed_extensions: tuple[str, ...] = (
        ".php",
        ".js",
        ".cjs",
        ".mjs",
        ".ts",
        ".tsx",
        ".jsx",
        ".json",
        ".html",
        ".ejs",
        ".hbs",
        ".pug",
        ".sql",
        ".yaml",
        ".yml",
    )

    excluded_dirs: tuple[str, ...] = (
        ".git",
        "node_modules",
        "dist",
        "build",
        "coverage",
        ".next",
        ".cache",
        "vendor",
    )

    blocked_file_names: tuple[str, ...] = (
        ".env",
        ".env.local",
        ".env.production",
        ".npmrc",
        "id_rsa",
        "id_ed25519",
    )

    blocked_suffixes: tuple[str, ...] = (
        ".pem",
        ".key",
        ".p12",
        ".pfx",
    )
