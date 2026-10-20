from __future__ import annotations

from pathlib import Path
from typing import Any

from .config import Agent2Config
from .security import redact_secrets


class ToolError(RuntimeError):
    pass


class ReadOnlySourceTools:
    """Read-only, source-root confined tools exposed to Agent 2."""

    def __init__(self, source_root: str | Path, config: Agent2Config | None = None):
        self.root = Path(source_root).expanduser().resolve()
        self.config = config or Agent2Config()
        if not self.root.exists() or not self.root.is_dir():
            raise ToolError(f"source_root is not a directory: {self.root}")

    def _resolve_safe(self, relative_path: str | None) -> Path:
        if not relative_path or relative_path in {".", "./"}:
            path = self.root
        else:
            raw = Path(relative_path)
            path = raw.resolve() if raw.is_absolute() else (self.root / raw).resolve()

        try:
            path.relative_to(self.root)
        except ValueError as exc:
            raise ToolError("Path escapes source_root") from exc

        rel_parts = path.relative_to(self.root).parts
        if any(part in self.config.excluded_dirs for part in rel_parts):
            raise ToolError("Path is inside an excluded directory")
        return path

    def _is_blocked_file(self, path: Path) -> bool:
        if path.name in self.config.blocked_file_names or path.name.startswith(".env."):
            return True
        if path.suffix.lower() in self.config.blocked_suffixes:
            return True
        try:
            rel_parts = path.relative_to(self.root).parts
        except ValueError:
            return True
        return any(part in self.config.excluded_dirs for part in rel_parts)

    def _is_searchable_file(self, path: Path) -> bool:
        return (
            path.is_file()
            and not self._is_blocked_file(path)
            and path.suffix.lower() in self.config.allowed_extensions
        )

    def search_code(
        self,
        query: str,
        path: str | None = None,
        max_results: int | None = None,
    ) -> dict[str, Any]:
        """Literal, case-insensitive source search with bounded output."""
        query = (query or "").strip()
        if not query:
            raise ToolError("search_code.query must not be empty")
        if len(query) > 300:
            raise ToolError("search_code.query is too long")

        base = self._resolve_safe(path)
        if not base.exists():
            raise ToolError(f"Search path does not exist: {path}")

        limit = min(max_results or self.config.max_search_results, self.config.max_search_results)
        needle = query.casefold()
        results: list[dict[str, Any]] = []
        scanned_files = 0

        candidates = [base] if base.is_file() else base.rglob("*")
        for file_path in candidates:
            if len(results) >= limit:
                break
            if not self._is_searchable_file(file_path):
                continue
            try:
                if file_path.stat().st_size > self.config.max_file_bytes:
                    continue
                text = file_path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            scanned_files += 1
            for line_no, line in enumerate(text.splitlines(), start=1):
                if needle in line.casefold():
                    results.append(
                        {
                            "path": file_path.relative_to(self.root).as_posix(),
                            "line": line_no,
                            "text": redact_secrets(line[:500]),
                        }
                    )
                    if len(results) >= limit:
                        break

        return {
            "query": redact_secrets(query),
            "search_path": "." if base == self.root else base.relative_to(self.root).as_posix(),
            "count": len(results),
            "scanned_files": scanned_files,
            "results": results,
            "truncated": len(results) >= limit,
        }

    def read_file(
        self,
        path: str,
        start_line: int = 1,
        end_line: int | None = None,
    ) -> dict[str, Any]:
        file_path = self._resolve_safe(path)
        if not file_path.exists() or not file_path.is_file():
            raise ToolError(f"File does not exist: {path}")
        if self._is_blocked_file(file_path):
            raise ToolError("Reading this file is blocked by policy")
        if file_path.suffix.lower() not in self.config.allowed_extensions:
            raise ToolError(f"Unsupported file extension: {file_path.suffix}")
        if file_path.stat().st_size > self.config.max_file_bytes:
            raise ToolError("File exceeds max_file_bytes")

        start = max(int(start_line or 1), 1)
        requested_end = int(end_line) if end_line is not None else start + self.config.max_read_lines - 1
        end = min(requested_end, start + self.config.max_read_lines - 1)
        if end < start:
            raise ToolError("end_line must be >= start_line")

        text = file_path.read_text(encoding="utf-8", errors="replace")
        lines = text.splitlines()
        selected = lines[start - 1 : end]
        numbered = [f"{line_no:>5}: {line}" for line_no, line in enumerate(selected, start=start)]

        return {
            "path": file_path.relative_to(self.root).as_posix(),
            "start_line": start,
            "end_line": start + max(len(selected) - 1, 0),
            "total_lines": len(lines),
            "content": redact_secrets("\n".join(numbered)),
            "truncated": end < len(lines),
        }
