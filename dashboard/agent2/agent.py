from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import Any

from .config import Agent2Config
from .llm import LLMClient, LLMError
from .prompts import SYSTEM_PROMPT, finding_prompt
from .schemas import Finding, FindingBatch, SchemaError, validate_finish_result
from .tools import ReadOnlySourceTools, ToolError


class AgentProtocolError(RuntimeError):
    pass


def _parse_json_object(text: str) -> dict[str, Any]:
    raw = (text or "").strip()
    if raw.startswith("```"):
        lines = raw.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        raw = "\n".join(lines).strip()
    data = json.loads(raw)
    if not isinstance(data, dict):
        raise ValueError("LLM response must be a JSON object")
    return data


@dataclass
class _Metrics:
    llm_calls: int = 0
    tool_calls: int = 0
    search_calls: int = 0
    read_calls: int = 0
    files_read: set[str] | None = None

    def __post_init__(self) -> None:
        if self.files_read is None:
            self.files_read = set()

    def to_dict(self, elapsed_ms: int) -> dict[str, Any]:
        return {
            "llm_calls": self.llm_calls,
            "tool_calls": self.tool_calls,
            "search_calls": self.search_calls,
            "read_calls": self.read_calls,
            "files_read": sorted(self.files_read or set()),
            "elapsed_ms": elapsed_ms,
        }


class Agent2Runner:
    """Batch runner. Each finding gets an isolated conversation/state."""

    def __init__(
        self,
        llm: LLMClient,
        tools: ReadOnlySourceTools,
        config: Agent2Config | None = None,
    ):
        self.llm = llm
        self.tools = tools
        self.config = config or Agent2Config()

    def analyze_batch(self, batch: FindingBatch) -> dict[str, Any]:
        started = time.perf_counter()
        results = [self.analyze_finding(finding, batch.source_revision) for finding in batch.findings]
        elapsed_ms = int((time.perf_counter() - started) * 1000)
        return {
            "batch_id": batch.batch_id,
            "source_revision": batch.source_revision,
            "status": "completed",
            "finding_count": len(batch.findings),
            "results": results,
            "elapsed_ms": elapsed_ms,
        }

    def analyze_finding(self, finding: Finding, source_revision: str) -> dict[str, Any]:
        started = time.perf_counter()
        metrics = _Metrics()
        messages: list[dict[str, str]] = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": finding_prompt(finding, source_revision)},
        ]
        json_failures = 0

        for _step in range(1, self.config.max_steps + 1):
            if metrics.tool_calls >= self.config.max_tool_calls:
                return self._limit_result(finding, metrics, started)

            try:
                metrics.llm_calls += 1
                raw = self.llm.complete(messages)
            except LLMError as exc:
                return self._failed_result(finding, f"Lỗi mô hình ngôn ngữ: {exc}", metrics, started)

            try:
                command = _parse_json_object(raw)
            except (ValueError, json.JSONDecodeError) as exc:
                json_failures += 1
                if json_failures > self.config.max_json_retries:
                    return self._failed_result(
                        finding,
                        f"Mô hình liên tục trả về JSON không hợp lệ: {exc}",
                        metrics,
                        started,
                    )
                messages.append({"role": "assistant", "content": raw})
                messages.append(
                    {
                        "role": "user",
                        "content": "Protocol error: return exactly one valid JSON object matching the action schema.",
                    }
                )
                continue

            action = str(command.get("action", "")).strip()
            if action == "finish":
                try:
                    result = validate_finish_result(command.get("result"), finding)
                except SchemaError as exc:
                    json_failures += 1
                    if json_failures > self.config.max_json_retries:
                        return self._failed_result(
                            finding,
                            f"Cấu trúc kết quả phân tích không hợp lệ: {exc}",
                            metrics,
                            started,
                        )
                    messages.append({"role": "assistant", "content": raw})
                    messages.append(
                        {
                            "role": "user",
                            "content": f"Finish schema error: {exc}. Correct it without inventing evidence.",
                        }
                    )
                    continue

                # Defense against unsupported confirmed claims. Every cited code file
                # must have been successfully read in this isolated run.
                if result["analysis_status"] == "confirmed":
                    cited_paths = {
                        str(item.get("path", "")).strip()
                        for item in result.get("code_locations", [])
                        if isinstance(item, dict) and item.get("path")
                    }
                    unread_paths = cited_paths - (metrics.files_read or set())
                    if not metrics.files_read or unread_paths:
                        messages.append({"role": "assistant", "content": raw})
                        messages.append(
                            {
                                "role": "user",
                                "content": (
                                    "A confirmed result requires successful read_file evidence for every "
                                    f"cited code location. Unread paths: {sorted(unread_paths)}. "
                                    "Read the relevant files, or finish unresolved."
                                ),
                            }
                        )
                        continue

                elapsed_ms = int((time.perf_counter() - started) * 1000)
                result["metrics"] = metrics.to_dict(elapsed_ms)
                result["source_revision"] = source_revision
                return result

            if action not in {"search_code", "read_file"}:
                json_failures += 1
                if json_failures > self.config.max_json_retries:
                    return self._failed_result(
                        finding,
                        f"Thao tác không được hỗ trợ: {action!r}",
                        metrics,
                        started,
                    )
                messages.append({"role": "assistant", "content": raw})
                messages.append(
                    {
                        "role": "user",
                        "content": "Unsupported action. Use only search_code, read_file, or finish.",
                    }
                )
                continue

            args = command.get("args") or {}
            if not isinstance(args, dict):
                args = {}

            try:
                metrics.tool_calls += 1
                if action == "search_code":
                    metrics.search_calls += 1
                    observation = self.tools.search_code(
                        query=str(args.get("query", "")),
                        path=args.get("path"),
                        max_results=args.get("max_results"),
                    )
                else:
                    metrics.read_calls += 1
                    observation = self.tools.read_file(
                        path=str(args.get("path", "")),
                        start_line=int(args.get("start_line", 1)),
                        end_line=(int(args["end_line"]) if args.get("end_line") is not None else None),
                    )
                    metrics.files_read.add(observation["path"])
            except (ToolError, ValueError, TypeError) as exc:
                observation = {"tool_error": str(exc)}

            messages.append({"role": "assistant", "content": raw})
            messages.append(
                {
                    "role": "user",
                    "content": "TOOL_OBSERVATION\n" + json.dumps(observation, ensure_ascii=False),
                }
            )

        return self._limit_result(finding, metrics, started)

    def _limit_result(
        self, finding: Finding, metrics: _Metrics, started: float
    ) -> dict[str, Any]:
        elapsed_ms = int((time.perf_counter() - started) * 1000)
        return {
            "finding_id": finding.finding_id,
            "vulnerability_type": finding.vulnerability_type,
            "analysis_status": "analysis_limit_reached",
            "confidence": "low",
            "reason": "Phân tích phát hiện này đã đạt giới hạn số bước hoặc số lần gọi công cụ được cấu hình.",
            "code_locations": [],
            "root_cause": {},
            "remediation": {},
            "metrics": metrics.to_dict(elapsed_ms),
        }

    def _failed_result(
        self,
        finding: Finding,
        reason: str,
        metrics: _Metrics,
        started: float,
    ) -> dict[str, Any]:
        elapsed_ms = int((time.perf_counter() - started) * 1000)
        return {
            "finding_id": finding.finding_id,
            "vulnerability_type": finding.vulnerability_type,
            "analysis_status": "failed",
            "confidence": "low",
            "reason": reason,
            "code_locations": [],
            "root_cause": {},
            "remediation": {},
            "metrics": metrics.to_dict(elapsed_ms),
        }
