"""Shared on-disk handoff layout used by the dashboard and Burp agents."""
from __future__ import annotations

from datetime import datetime
import json
import os
from pathlib import Path
import re
import tempfile
import uuid

from .security import redact_data, redact_secrets

DEFAULT_LABS_ROOT = Path(os.getenv(
    "AGENT_LABS_ROOT", r"D:\Thực tập cơ sở\Agent1_Data\du_lieu_theo_lab"
))


def lab_directory(root: str | Path, lab: str) -> Path:
    if not lab or lab in {".", ".."} or re.search(r'[<>:"/\\|?*\x00-\x1f]', lab):
        raise ValueError("Tên lab phải là tên một thư mục hợp lệ.")
    base = Path(root).expanduser().resolve()
    path = (base / lab).resolve()
    if path.parent != base:
        raise ValueError("Thư mục lab nằm ngoài thư mục dữ liệu.")
    return path


def session_name(batch: dict, export_name: str) -> str:
    session = batch.get("session") or {}
    name = session.get("session_id") or batch.get("session_id")
    if not name:
        name = Path(export_name).stem.removeprefix("agent1_").removesuffix("_cho_agent2")
    # Session IDs are also filename components; never accept paths from JSON.
    name = re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_", str(name)).strip(". ")
    if not name:
        raise ValueError("Không tìm thấy mã phiên hợp lệ trong log Agent 1.")
    return name


def atomic_write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent,
                                     prefix=".handoff-", suffix=".tmp", delete=False) as handle:
        temporary = Path(handle.name)
        try:
            handle.write(content)
        except BaseException:
            handle.close()
            temporary.unlink(missing_ok=True)
            raise
    try:
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def save_analysis(root, lab, batch, export_name, result, report, instructions,
                  source_root, secrets=()) -> dict[str, str]:
    directory = lab_directory(root, lab)
    for folder in ("phien_kiem_thu", "xuat_cho_agent2", "phan_tich_agent2"):
        child = (directory / folder).resolve()
        if child.parent != directory:
            raise ValueError("Thư mục dữ liệu trỏ ra ngoài lab đã chọn.")
        child.mkdir(parents=True, exist_ok=True)
    output = directory / "phan_tich_agent2"
    sid = session_name(batch, export_name)
    stamp = datetime.now().astimezone()
    result_path = output / f"agent2_{sid}_{stamp:%Y%m%d_%H%M%S}.json"
    if result_path.exists():
        result_path = output / f"agent2_{sid}_{stamp:%Y%m%d_%H%M%S}_{uuid.uuid4().hex[:8]}.json"
    fix_path = output / f"agent3_fix_{sid}.md"
    payload = redact_data(dict(result), secrets=secrets)
    metadata = {
        "lab_name": lab, "session_id": sid, "saved_at": stamp.isoformat(),
        "agent1_export_source": str(directory / "xuat_cho_agent2" / Path(export_name).name),
        "source_root": str(Path(source_root).resolve()), "user_report": report,
        "agent3_instructions_file": fix_path.name,
    }
    # session_id identifies the lab session; it is not an authentication token.
    payload.update({key: redact_secrets(value, secrets=secrets) for key, value in metadata.items()})
    atomic_write(result_path, json.dumps(payload, ensure_ascii=False, indent=2))
    atomic_write(fix_path, redact_secrets(
        "# Agent 3 — Hướng dẫn sửa lỗi\n\n"
        f"Lab: {lab}\n\nPhiên: {sid}\n\n"
        "Trạng thái: chưa gửi Agent 3; chưa có kết quả sửa hoặc kiểm tra.\n\n"
        + instructions, secrets=secrets))
    return {"result_path": str(result_path), "fix_path": str(fix_path), "session_id": sid}


def save_fix_log(paths, instructions, state, events=(), changed_files=(), secrets=()):
    content = (
        "# Agent 3 — Hướng dẫn và nhật ký sửa lỗi\n\n"
        f"Trạng thái: {state}\n\n"
        "## Hướng dẫn đã gửi\n\n" + instructions
        + "\n\n## File đã thay đổi\n\n"
        + ("\n".join("- " + str(p) for p in changed_files) or "(chưa ghi nhận)")
        + "\n\n## Tiến độ và kiểm tra\n\n"
        + "\n".join(str(line) for line in events) + "\n"
    )
    for path in paths:
        atomic_write(Path(path), redact_secrets(content, secrets=secrets))
