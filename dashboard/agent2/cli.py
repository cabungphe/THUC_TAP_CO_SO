from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

from .agent import Agent2Runner
from .config import Agent2Config
from .llm import OpenAICompatibleClient
from .schemas import FindingBatch, SchemaError
from .tools import ReadOnlySourceTools, ToolError
from .adapter import convert_agent1_to_batch


def _escape_prose_dollars(markdown: str) -> str:
    """Keep PHP variables out of math mode while preserving backtick code spans/blocks."""
    return re.sub(
        r"(?P<ticks>`+).*?(?P=ticks)|(?<!\\)\$",
        lambda match: match.group(0) if match.group("ticks") else r"\$",
        markdown,
        flags=re.DOTALL,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Agent 2 Root Cause Analysis MVP")
    parser.add_argument("--batch", required=True, help="Path to finalized finding batch JSON (or Agent 1 log)")
    parser.add_argument("--source-root", required=True, help="Read-only source root to analyze")
    parser.add_argument("--out", required=True, help="Output JSON path")
    return parser

def build_user_report(result: dict) -> str:
    """Build a rich, human-readable Markdown report for display in the UI."""
    md = "# Báo cáo phân tích nguyên nhân gốc rễ\n\n"
    md += f"**Mã đợt phân tích**: `{result.get('batch_id', 'N/A')}`  \n"
    md += f"**Phiên bản mã nguồn**: `{result.get('source_revision', 'N/A')}`  \n"
    md += f"**Số phát hiện**: {result.get('finding_count', 0)}  \n"
    md += f"**Thời gian xử lý**: {result.get('elapsed_ms', 0) / 1000:.1f}s\n\n"
    md += "---\n\n"

    for i, item in enumerate(result.get('results', []), 1):
        vuln = item.get('vulnerability_type', 'unknown').upper().replace('_', ' ')
        status = item.get('analysis_status', 'unknown')
        confidence = {"high": "Cao", "medium": "Trung bình", "low": "Thấp"}.get(
            item.get('confidence'), 'Không xác định'
        )

        status_label = {
            "confirmed": "Đã xác nhận",
            "unresolved": "Chưa xác nhận được",
            "analysis_limit_reached": "Vượt giới hạn phân tích",
            "failed": "Lỗi phân tích",
        }.get(status, status)

        md += f"## {i}. [{vuln}] {item.get('finding_id', '')}\n\n"
        md += f"| Thuộc tính | Giá trị |\n|---|---|\n"
        md += f"| Trạng thái | **{status_label}** |\n"
        md += f"| Độ tin cậy | {confidence} |\n"

        if status == "confirmed":
            root_cause = item.get("root_cause", {})
            remediation = item.get("remediation", {})

            md += f"\n### Nguyên nhân gốc rễ\n\n"
            md += f"{root_cause.get('summary', 'Không có thông tin.')}\n\n"

            if root_cause.get("source") or root_cause.get("sink"):
                md += f"- **Nguồn dữ liệu đầu vào**: {root_cause.get('source', 'Không có thông tin.')}\n"
                md += f"- **Điểm thực thi nhạy cảm**: {root_cause.get('sink', 'Không có thông tin.')}\n\n"

            data_flow = root_cause.get("data_flow", [])
            if data_flow:
                md += "**Luồng dữ liệu:**\n\n"
                for step_idx, step in enumerate(data_flow, 1):
                    md += f"{step_idx}. {step}\n"
                md += "\n"

            locations = item.get("code_locations", [])
            if locations:
                md += "### Vị trí mã nguồn liên quan\n\n"
                md += "| Tệp | Dòng | Vai trò |\n|---|---|---|\n"
                for loc in locations:
                    role = {
                        "source": "Nguồn dữ liệu đầu vào",
                        "processing": "Xử lý dữ liệu",
                        "sink": "Điểm thực thi nhạy cảm",
                        "vulnerable_handler": "Hàm xử lý có lỗ hổng",
                        "related": "Mã nguồn liên quan",
                    }.get(loc.get('role'), 'Không xác định')
                    md += f"| `{loc.get('path', '')}` | {loc.get('start_line', '?')}-{loc.get('end_line', '?')} | {role} |\n"
                md += "\n"

            md += "### Đề xuất khắc phục\n\n"
            md += f"**Chiến lược**: {remediation.get('recommended_strategy', 'Không có thông tin.')}\n\n"
            if remediation.get("rationale"):
                md += f"**Lý do**: {remediation['rationale']}\n\n"
            constraints = remediation.get("constraints", [])
            if constraints:
                md += "**Ràng buộc:**\n"
                for c in constraints:
                    md += f"- {c}\n"
                md += "\n"
            alternatives = remediation.get("alternatives", [])
            if alternatives:
                md += "**Phương án thay thế:**\n"
                for a in alternatives:
                    md += f"- {a}\n"
                md += "\n"
        else:
            reason = item.get('reason', 'Không có lý do cụ thể.')
            md += f"\n**Lý do**: {reason}\n\n"

        notes = item.get("notes", [])
        if notes:
            md += "**Ghi chú:**\n"
            for n in notes:
                md += f"- {n}\n"
            md += "\n"

        md += "---\n\n"

    return _escape_prose_dollars(md)


def _fix_anchors(item: dict) -> tuple[str, tuple]:
    """Ignore related/source locations; identify the actual sink when available."""
    locations = item.get("code_locations", [])
    for role in ("sink", "vulnerable_handler"):
        anchors = set()
        for loc in locations:
            if loc.get("role") != role or not loc.get("path"):
                continue
            start, end = loc.get("start_line"), loc.get("end_line")
            if not isinstance(start, int) or not isinstance(end, int) or start < 1 or end < start:
                continue
            path = loc["path"].replace("\\", "/").removeprefix("./")
            anchors.add((path, start, end))
        if anchors:
            return role, tuple(sorted(anchors))
    return "", ()


def group_fix_plans(result: dict) -> list[dict]:
    """Group confirmed fixes by code evidence, retaining all distinct requirements."""
    groups = []
    for item in result.get("results", []):
        if item.get("analysis_status") != "confirmed":
            continue
        remediation = item.get("remediation", {})
        strategy = remediation.get("recommended_strategy", "Đọc vị trí bên dưới để xác định cách sửa.")
        constraints = list(dict.fromkeys(remediation.get("constraints", [])))
        locations = list(dict.fromkeys(
            (loc.get("path", ""), loc.get("start_line", "?"), loc.get("end_line", "?"))
            for loc in item.get("code_locations", []) if loc.get("path")
        ))
        role, anchors = _fix_anchors(item)
        identity = (item.get("vulnerability_type", "unknown"), item.get("source_revision"))
        group = None
        for existing in groups:
            if existing["identity"] != identity or existing["role"] != role:
                continue
            prior = existing["anchors"]
            # Sink ranges may differ slightly between model runs. Broad handler
            # ranges must match exactly so unrelated sinks in a file stay separate.
            same_code = bool(anchors) and len(anchors) == len(prior) and all(
                a[0] == b[0] and (a == b or (role == "sink" and
                                           max(a[1], b[1]) <= min(a[2], b[2])))
                for a, b in zip(anchors, prior)
            )
            if not anchors:
                same_code = (existing["locations"] == locations and
                             existing["strategies"] == [strategy] and
                             existing["constraints"] == constraints)
            if same_code:
                group = existing
                break
        if group is None:
            group = {"identity": identity, "role": role, "anchors": anchors,
                     "ids": [], "locations": [], "strategies": [], "constraints": []}
            groups.append(group)
        group["ids"] = list(dict.fromkeys(group["ids"] + [item.get("finding_id", "")]))
        group["locations"] = list(dict.fromkeys(group["locations"] + locations))
        group["strategies"] = list(dict.fromkeys(group["strategies"] + [strategy]))
        group["constraints"] = list(dict.fromkeys(group["constraints"] + constraints))
    return groups


def build_agent3_payload(result: dict, source_root: str = "") -> str:
    """Compact handoff: locations, one strategy, and required constraints."""
    lines = [
        "# Hướng dẫn sửa lỗi cho Agent 3",
        f"Source: `{source_root}`",
        "",
        "Đọc source hiện tại trước khi sửa; dòng tham chiếu có thể đã thay đổi. "
        "Chỉ sửa các lỗi dưới đây, dùng thay đổi nhỏ nhất phù hợp với phiên bản đang chạy. "
        "Các finding cùng nguyên nhân chỉ cần vá một lần; phần đã vá đúng chỉ kiểm tra lại. "
        "Giữ chức năng hợp lệ, không refactor lan rộng hoặc tự deploy.",
        "",
    ]
    confirmed = [item for item in result.get("results", [])
                 if item.get("analysis_status") == "confirmed"]
    if not confirmed:
        return "\n".join(lines + ["Không có finding nào được xác nhận. Không cần tạo bản vá."])

    for index, group in enumerate(group_fix_plans(result), 1):
        vuln = group["identity"][0]
        label = vuln.upper().replace("_", " ")
        ids = ", ".join(dict.fromkeys(group["ids"]))
        lines.extend([f"## Bản sửa #{index}: {label} — {ids}"])
        paths = {}
        for path, start, end in group["locations"]:
            paths.setdefault(path, []).append(f"{start}-{end}")
        for path, ranges in paths.items():
            lines.append(f"- File: `{path}` (dòng {', '.join(ranges)}).")
        lines.extend(f"- Sửa: {strategy}" for strategy in group["strategies"])
        lines.extend(f"- Yêu cầu: {constraint}" for constraint in group["constraints"])
        lines.append("")

    lines.extend([
        "Chế độ chỉ sửa code: bỏ qua yêu cầu tạo/chạy test, lint, build và retest, "
        "kể cả nếu có trong các mục trên. Kết thúc ngay sau khi sửa mã nguồn.",
        "Báo lại ngắn gọn: file đã sửa, thay đổi chính; ghi rõ chưa chạy kiểm thử.",
    ])
    return "\n".join(lines)


def main() -> int:
    args = build_parser().parse_args()
    batch_path = Path(args.batch)
    out_path = Path(args.out)

    try:
        batch_data = json.loads(batch_path.read_text(encoding="utf-8"))
        
        # Auto-convert Agent 1 logs
        if batch_data.get("schema_version") and batch_data.get("schema_version").startswith("agent1"):
            print("Detected Agent 1 log format. Running adapter...")
            batch_data = convert_agent1_to_batch(batch_data)
            
        batch = FindingBatch.from_dict(batch_data)
        config = Agent2Config()
        tools = ReadOnlySourceTools(args.source_root, config=config)
        llm = OpenAICompatibleClient.from_env()
        runner = Agent2Runner(llm=llm, tools=tools, config=config)
        result = runner.analyze_batch(batch)
    except (OSError, json.JSONDecodeError, SchemaError, ToolError, RuntimeError) as exc:
        raise SystemExit(f"Agent 2 startup failed: {exc}") from exc

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"Wrote Agent 2 result: {out_path}")
    
    report_md = build_user_report(result)
    report_path = out_path.parent / "agent2_report.md"
    report_path.write_text(report_md, encoding="utf-8")
    print(f"Wrote User Report: {report_path}")

    payload_md = build_agent3_payload(result, source_root=args.source_root)
    payload_path = out_path.parent / "agent3_fix_instructions.md"
    payload_path.write_text(payload_md, encoding="utf-8")
    print(f"Wrote Agent 3 Payload: {payload_path}")
    
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
