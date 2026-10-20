import streamlit as st
import json
import os
import sys
import subprocess
import tempfile
from html import escape
from pathlib import Path
from datetime import datetime

from agent2.agent import Agent2Runner
from agent2.config import Agent2Config
from agent2.llm import OpenAICompatibleClient, LLMError
from agent2.schemas import FindingBatch, SchemaError
from agent2.tools import ReadOnlySourceTools
from agent2.adapter import convert_agent1_to_batch
from agent2.cli import build_user_report, build_agent3_payload, group_fix_plans
from agent2.agent3 import JobManager
from agent2.build import BuildManager
from agent2.security import redact_secrets, redact_data
from agent2.lab_storage import save_analysis
from agent2.report import generate_report_cli, agent1_report_input

@st.cache_resource
def _job_manager():
    return JobManager()


@st.cache_resource
def _build_manager():
    return BuildManager()


# ── Page config ──────────────────────────────────────────────
st.set_page_config(
    page_title="Security Testing Dashboard",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── CSS — Clean, professional look ──────────────────────────
st.markdown("""
<style>
    /* Sidebar */
    section[data-testid="stSidebar"] {
        background: #1a1a2e;
    }
    section[data-testid="stSidebar"] * { color: #e0e0e0 !important; }
    section[data-testid="stSidebar"] input {
        background: #2d2d44 !important;
        border: 1px solid #3d3d5c !important;
        color: #f0f0f0 !important;
        border-radius: 6px !important;
    }
    section[data-testid="stSidebar"] label {
        font-size: 0.85rem !important; font-weight: 500 !important;
    }
    .job-log-scroll {height: 320px; overflow-y: auto; border: 1px solid #484860;
        border-radius: 8px; background: #181825; color: #e6e9f4;}
    .job-log-scroll table {width: 100%; border-collapse: collapse; font-size: 0.86rem;}
    .job-log-scroll th {position: sticky; top: 0; background: #303047; text-align: left;
        padding: 8px 10px; z-index: 1;}
    .job-log-scroll td {padding: 7px 10px; border-top: 1px solid #38384d;
        vertical-align: top; word-break: break-word;}
    .job-log-scroll td:first-child {white-space: nowrap; color: #a6adc8;}
    .job-log-scroll td:nth-child(2) {white-space: nowrap; font-weight: 600;}
</style>
""", unsafe_allow_html=True)


# ── Folder/File picker (subprocess to avoid tkinter issues) ──
_PICKER_SCRIPT = r'''
import sys
import tkinter as tk
from tkinter import filedialog

title = sys.argv[1] if len(sys.argv) > 1 else "Select Folder"
initial = sys.argv[2] if len(sys.argv) > 2 and sys.argv[2] else None

root = tk.Tk()
root.withdraw()
root.attributes("-topmost", True)
root.update_idletasks()
root.update()

try:
    path = filedialog.askdirectory(
        title=title,
        initialdir=initial if initial else None,
        parent=root,
        mustexist=True,
    )
except Exception:
    path = ""

sys.stdout.write(path or "")
sys.stdout.flush()
root.destroy()
'''

_FILE_PICKER_SCRIPT = r'''
import sys
import json
import tkinter as tk
from tkinter import filedialog

title = sys.argv[1] if len(sys.argv) > 1 else "Select Files"
initial = sys.argv[2] if len(sys.argv) > 2 and sys.argv[2] else None

root = tk.Tk()
root.withdraw()
root.attributes("-topmost", True)
root.update_idletasks()
root.update()

try:
    paths = filedialog.askopenfilenames(
        title=title,
        initialdir=initial if initial else None,
        parent=root,
        filetypes=[("JSON Files", "*.json"), ("All Files", "*.*")]
    )
except Exception:
    paths = []

sys.stdout.write(json.dumps(paths))
sys.stdout.flush()
root.destroy()
'''


def _run_picker_script(script_body, title, initial_dir):
    """Run a file/folder picker in a subprocess."""
    if initial_dir and not os.path.isdir(initial_dir):
        initial_dir = ""
    tmp = tempfile.NamedTemporaryFile("w", suffix=".py", delete=False, encoding="utf-8")
    tmp.write(script_body)
    tmp.close()
    script_path = tmp.name
    creationflags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
    try:
        result = subprocess.run(
            [sys.executable, script_path, title, initial_dir or ""],
            capture_output=True, text=True, timeout=600,
            creationflags=creationflags,
        )
        return (result.stdout or "").strip()
    except subprocess.TimeoutExpired:
        st.warning("Picker dialog timed out.")
        return ""
    except Exception as e:
        st.error(f"Could not open picker dialog: {e}")
        return ""
    finally:
        try:
            os.unlink(script_path)
        except OSError:
            pass


def open_folder_picker(title="Select Folder", initial_dir=None):
    return _run_picker_script(_PICKER_SCRIPT, title, initial_dir)


def open_file_picker(title="Select Files", initial_dir=None):
    out = _run_picker_script(_FILE_PICKER_SCRIPT, title, initial_dir)
    if out:
        try:
            return json.loads(out)
        except (json.JSONDecodeError, TypeError):
            pass
    return []


# ── Utility functions ────────────────────────────────────────
def _is_safe_path(path_str: str) -> bool:
    normalized = os.path.normpath(path_str)
    if ".." in normalized.split(os.sep):
        return False
    return os.path.isabs(normalized)


@st.cache_data(show_spinner=False)
def _count_files(root: str) -> int:
    try:
        return sum(1 for p in Path(root).rglob("*") if p.is_file())
    except Exception:
        return 0


def _run_analysis_on_batch_data(batch_data: dict, api_key: str, base_url: str, model: str, source_root: str) -> dict:
    working = redact_data(batch_data, secrets=(api_key,))
    if working.get("schema_version", "").startswith("agent1"):
        working = convert_agent1_to_batch(working)

    batch = FindingBatch.from_dict(working)
    config = Agent2Config()
    tools = ReadOnlySourceTools(source_root, config=config)
    llm = OpenAICompatibleClient(
        api_key=api_key,
        base_url=base_url.rstrip("/"),
        model=model,
    )
    runner = Agent2Runner(llm=llm, tools=tools, config=config)
    return runner.analyze_batch(batch)


def _merge_results(all_results: list[dict]) -> dict:
    merged = {
        "batch_id": "merged-batch",
        "source_revision": "",
        "finding_count": 0,
        "elapsed_ms": 0,
        "results": [],
    }
    seen_revisions = set()
    for r in all_results:
        merged["results"].extend(r.get("results", []))
        merged["finding_count"] += r.get("finding_count", len(r.get("results", [])))
        merged["elapsed_ms"] += r.get("elapsed_ms", 0)
        rev = r.get("source_revision", "")
        if rev:
            seen_revisions.add(rev)
    if seen_revisions:
        merged["source_revision"] = ", ".join(seen_revisions)
    batch_ids = [r.get("batch_id", "") for r in all_results if r.get("batch_id")]
    if batch_ids:
        merged["batch_id"] = " + ".join(batch_ids)
    return merged


def _progress_table(events: list[str]) -> str:
    """Keep the live panel short while retaining the worker's full sanitized log."""
    rows = []
    for line in events:
        stamp, _, message = line.partition("] ")
        stamp = stamp.lstrip("[") if message else ""
        message = message or line
        if message.endswith(": đã kết thúc"):
            continue  # Adjacent start/end tool events make the live view noisy.
        if (message.startswith(("Không hoàn tất:", "CLI:", "Build & Run chưa thành công"))
                or (message.startswith("Kiểm tra") and "chưa đạt" in message)):
            phase = "Lỗi"
        elif message.startswith(("Thành công:", "Build & Run thành công")):
            phase = "Hoàn tất"
        elif message.startswith(("Kiểm tra", "CLI đã kết thúc")):
            phase = "Kiểm tra"
        elif message.startswith(("Build image", "Đã tìm thấy")):
            phase = "Build image"
        elif message.startswith(("Image đã build", "Docker Compose hoàn tất")):
            phase = "Khởi động"
        elif message.startswith("Đang kiểm tra Docker"):
            phase = "Docker"
        elif message.startswith("Lần "):
            phase = "Sửa mã"
        elif message.startswith("CLI đã khởi động"):
            phase = "Khởi động"
        elif message.endswith(": đang chạy"):
            phase = "Thao tác"
        else:
            phase = "Chi tiết"
        rows.append((stamp, phase, message))
    body = "".join(
        "<tr><td>" + escape(stamp) + "</td><td>" + escape(phase) +
        "</td><td>" + escape(message[:240]) + "</td></tr>"
        for stamp, phase, message in reversed(rows[-200:])
    )
    return ("<div class='job-log-scroll'><table><thead><tr>"
            "<th>Giờ</th><th>Giai đoạn</th><th>Tiến độ</th></tr></thead><tbody>"
            + body + "</tbody></table></div>")


# ── Session state ────────────────────────────────────────────
for key, default in [
    ("analysis_result", None), ("user_report", ""), ("agent3_payload", ""),
    ("loaded_batches", []), ("loaded_file_names", []), ("loaded_file_paths", []),
    ("source_root", ""), ("selected_log_files", []), ("log_picker_dir", ""),
    ("analysis_source_root", ""),
    ("analysis_log_files", []),
    ("analysis_artifacts", []),
    ("llm_report", ""), ("llm_report_context", ""),
]:
    if key not in st.session_state:
        st.session_state[key] = default


# ── Sidebar: LLM Configuration ──────────────────────────────
with st.sidebar:
    st.markdown("### ⚙️ LLM Configuration (Agent 2)")
    api_key = st.text_input("API Key", value=os.getenv("AGENT2_API_KEY", ""), type="password")
    base_url = st.text_input("API Base URL", value=os.getenv("AGENT2_BASE_URL", "https://api.cerebras.ai/v1"))
    model = st.text_input("Model", value=os.getenv("AGENT2_MODEL", "qwen-3.8-27b"))

    if st.button("🔌 Test Connection", key="test_llm_connection"):
        if not api_key.strip():
            st.error("Please enter an API Key first.")
        else:
            try:
                with st.spinner("Testing connection…"):
                    client = OpenAICompatibleClient(
                        api_key=api_key.strip(),
                        base_url=base_url.strip().rstrip("/"),
                        model=model.strip(),
                        timeout_seconds=30,
                    )
                    answer = client.complete([{"role": "user", "content": "Reply with OK only."}])
                if not isinstance(answer, str) or not answer.strip():
                    st.error("API responded but returned no text content.")
                else:
                    st.success("API connection is working.")
            except LLMError as exc:
                st.error(redact_secrets(exc, secrets=(api_key,)))

    st.markdown("---")
    st.markdown("### 🤖 Agent 3 Configuration")
    st.caption("Gemini 3.1 Pro Thinking · CLI chạy ngầm")
    st.caption("Dùng tài khoản Google đã đăng nhập Antigravity CLI.")
    with st.expander("Cấu hình nâng cao"):
        gemini_cli = st.text_input("Antigravity CLI (agy.exe)", value=os.getenv("AGENT3_CLI", ""),
                                   help="Để trống để dùng agy.exe cài trong dự án.")
    st.caption("Chỉ sửa mã nguồn, bỏ qua test/lint và kiểm tra tự động.")


# ── Main title ───────────────────────────────────────────────
st.markdown("## 🛡️ Security Testing Dashboard")
st.caption("Root Cause Analysis (Agent 2) → Review Recommendations → Auto-fix & Verify (Agent 3)")


# ── Callbacks ────────────────────────────────────────────────
def handle_browse_src():
    selected = open_folder_picker("Select Source Code Folder", st.session_state.get("source_root", ""))
    if selected:
        st.session_state.source_root = selected

def handle_browse_log():
    selected = open_file_picker("Select Agent 1 Log Files", st.session_state.log_picker_dir)
    if selected:
        st.session_state.selected_log_files = selected
        st.session_state.log_picker_dir = str(Path(selected[0]).parent)


def handle_clear_logs():
    st.session_state.selected_log_files = []


# ── Source Code ──────────────────────────────────────────────
st.markdown("### 📁 Source Code")
col_src1, col_src2 = st.columns([4, 1])
with col_src1:
    st.text_input(
        "Source Code Path",
        key="source_root",
        label_visibility="collapsed",
        placeholder="e.g. D:\\AI_Pentest\\lazyweb",
    )
with col_src2:
    st.button("Browse…", key="btn_src", on_click=handle_browse_src)

source_root = st.session_state.source_root
manager = _job_manager()
current_job = manager.latest(source_root) if source_root else None
agent3_busy = current_job is not None and not current_job.done.is_set()
build_manager = _build_manager()
build_job = build_manager.latest(source_root) if source_root else None
build_busy = build_job is not None and not build_job.done.is_set()
if source_root and os.path.isdir(source_root):
    file_count = _count_files(source_root)
    st.caption(f"Selected: `{source_root}` — **{file_count}** files")
elif source_root:
    st.warning("Source code directory does not exist.")


# ── Agent 1 logs ────────────────────────────────────────────
st.markdown("### 📋 Log Agent 1")
st.caption("Chọn log Agent 1 để viết báo cáo kiểm thử ban đầu hoặc phân tích bằng Agent 2.")

col_log1, col_log2 = st.columns([4, 1])
with col_log1:
    st.button("Browse…", key="btn_log", on_click=handle_browse_log)
with col_log2:
    st.button("Clear selection", key="clear_logs", on_click=handle_clear_logs,
              disabled=not st.session_state.selected_log_files)

log_paths = [Path(path).expanduser().resolve() for path in st.session_state.selected_log_files]
context = sorted(str(path) for path in log_paths)
if st.session_state.analysis_log_files and st.session_state.analysis_log_files != context:
    st.session_state.analysis_result = None
    st.session_state.user_report = ""
    st.session_state.agent3_payload = ""
    st.session_state.analysis_artifacts = []
    st.session_state.analysis_log_files = []
    st.session_state.pop("agent3_payload_editor", None)

# Reload only the selected files on each rerun to avoid stale inputs.
st.session_state.loaded_batches = []
st.session_state.loaded_file_names = []
st.session_state.loaded_file_paths = []
if log_paths:
    st.caption(f"Selected: **{len(log_paths)}** log files")
    for full_path in log_paths:
        st.caption(f"`{full_path}`")
        if _is_safe_path(str(full_path)):
            try:
                batch_data = json.loads(full_path.read_text(encoding="utf-8"))
                st.session_state.loaded_batches.append(batch_data)
                st.session_state.loaded_file_names.append(full_path.name)
                st.session_state.loaded_file_paths.append(str(full_path))
            except Exception as e:
                st.error(f"Cannot read `{full_path}`: {e}")
else:
    st.info("Click Browse… to select one or more JSON log files (Ctrl/Shift for multiple files).")


# ── Root Cause Analysis (Agent 2) ────────────────────────────
loaded = st.session_state.loaded_batches
loaded_names = st.session_state.loaded_file_names

if loaded:
    st.markdown("### 🔍 Root Cause Analysis (Agent 2)")
    col_btn, col_info = st.columns([1, 3])
    with col_btn:
        analyze_clicked = st.button("▶ Start Analysis", type="primary", use_container_width=True, disabled=agent3_busy)

    if analyze_clicked:
        if not api_key:
            st.error("Please enter an API Key in the sidebar.")
        elif not source_root or not os.path.isdir(source_root):
            st.error("Invalid source code directory.")
        else:
            st.session_state.analysis_result = None
            st.session_state.user_report = ""
            st.session_state.agent3_payload = ""
            st.session_state.analysis_artifacts = []
            st.session_state.pop("agent3_payload_editor", None)
            all_results = []
            artifacts = []
            progress = st.progress(0, text="Analyzing…")

            for idx, (name, bd, file_path) in enumerate(zip(
                    loaded_names, loaded, st.session_state.loaded_file_paths)):
                progress.progress(
                    idx / len(loaded),
                    text=f"Analyzing file {idx + 1}/{len(loaded)}: {name}",
                )
                try:
                    result = _run_analysis_on_batch_data(bd, api_key, base_url, model, source_root)
                    safe_result = redact_data(result, secrets=(api_key,))
                    # Preserve the shared handoff for each selected Agent 1 export.
                    export_dir = Path(file_path).parent
                    if export_dir.name == "xuat_cho_agent2":
                        lab_dir = export_dir.parent
                        artifact = save_analysis(
                            lab_dir.parent, lab_dir.name, bd, name, safe_result,
                            build_user_report(safe_result),
                            build_agent3_payload(safe_result, source_root=source_root),
                            source_root, secrets=(api_key,),
                        )
                        artifacts.append(artifact)
                    all_results.append(result)
                except (SchemaError, LLMError) as e:
                    st.error(redact_secrets(f"Analysis error for `{name}`: {e}", secrets=(api_key,)))
                except Exception as e:
                    st.error(redact_secrets(f"Error with `{name}`: {e}", secrets=(api_key,)))

            progress.progress(1.0, text="Complete!")

            if all_results:
                if len(all_results) == 1:
                    merged = all_results[0]
                else:
                    merged = _merge_results(all_results)

                safe_merged = redact_data(merged, secrets=(api_key,))
                st.session_state.analysis_result = safe_merged
                st.session_state.user_report = build_user_report(safe_merged)
                st.session_state.agent3_payload = build_agent3_payload(safe_merged, source_root=source_root)
                st.session_state.analysis_source_root = str(Path(source_root).resolve())
                st.session_state.analysis_log_files = context
                st.session_state.analysis_artifacts = artifacts
                st.session_state.pop("agent3_payload_editor", None)
                st.rerun()


# ── Analysis Results ─────────────────────────────────────────
if st.session_state.analysis_result:
    st.markdown("---")
    st.markdown("### 📊 Analysis Results")

    result = st.session_state.analysis_result
    for artifact in st.session_state.analysis_artifacts:
        st.caption(f"Đã lưu: `{artifact['result_path']}` · `{artifact['fix_path']}`")
    results_list = result.get("results", [])
    confirmed = sum(1 for r in results_list if r.get("analysis_status") == "confirmed")
    total = len(results_list)

    col1, col2, col3 = st.columns(3)
    col1.metric("Total Findings", total)
    col2.metric("Confirmed", confirmed)
    col3.metric("Elapsed Time", f"{result.get('elapsed_ms', 0) / 1000:.1f}s")

    tab_report, tab_raw = st.tabs(["📝 Report", "🗂 Raw JSON"])
    with tab_report:
        st.markdown(redact_secrets(st.session_state.user_report, secrets=(api_key,)))
    with tab_raw:
        st.json(redact_data(result, secrets=(api_key,)))

    # ── Review & Send to Agent 3 ─────────────────────────────
    st.markdown("---")
    st.markdown("### ✏️ Review & Send to Agent 3")

    if confirmed == 0:
        st.warning(
            "No confirmed findings yet. If there were API or analysis errors, "
            "please fix them and re-run — this does **not** mean the application is safe."
        )
    else:
        fix_count = len(group_fix_plans(result))
        st.markdown(f"**{confirmed}** finding đã xác nhận → **{fix_count}** nhóm sửa gửi Agent 3.")

        with st.expander("Hướng dẫn sửa lỗi", expanded=False):
            if "agent3_payload_editor" in st.session_state:
                st.session_state.agent3_payload_editor = redact_secrets(
                    st.session_state.agent3_payload_editor, secrets=(api_key,)
                )
            edited_payload = st.text_area(
                "Nội dung gửi Agent 3", value=redact_secrets(st.session_state.agent3_payload, secrets=(api_key,)),
                height=300, key="agent3_payload_editor",
            )
            st.download_button("Tải hướng dẫn", redact_secrets(edited_payload, secrets=(api_key,)), "agent3_fix_instructions.md")

        same_source = (bool(source_root) and st.session_state.analysis_source_root
                       == str(Path(source_root).resolve()))
        if not same_source:
            st.warning("Source đã thay đổi. Chạy lại Agent 2 trước khi gửi sửa lỗi.")
        if st.button("🚀 Gửi cho Agent 3", type="primary", use_container_width=True,
                     disabled=agent3_busy or build_busy or not same_source):
            try:
                manager.start(
                    source_root, redact_secrets(edited_payload, secrets=(api_key,)), gemini_cli,
                    report_paths=tuple(a["fix_path"] for a in st.session_state.analysis_artifacts),
                    secrets=(api_key,),
                )
            except (OSError, ValueError, RuntimeError) as exc:
                st.error(redact_secrets(exc, secrets=(api_key,)))
            else:
                st.rerun()


# Progress comes directly from the worker's condition/event stream; no timed fragments.
if current_job:
    st.markdown("---")
    st.markdown("### Agent 3 · Tiến độ")
    st.caption("Dòng mới nhất ở trên; cuộn xuống để xem lại tiến trình.")
    status = st.empty()
    log = st.empty()
    status.info("Đang sửa mã nguồn…" if not current_job.done.is_set()
                else "Đang tải kết quả…")
    lines = []
    events = current_job.events[-200:] if current_job.done.is_set() else current_job.stream()
    for line in events:
        lines.append(line)
        log.markdown(_progress_table(lines), unsafe_allow_html=True)
    if current_job.state == "succeeded":
        status.success("✅ Đã sửa mã nguồn và vượt qua các kiểm tra đã cấu hình.")
    elif current_job.state == "edited":
        status.info("Đã sửa mã nguồn. Chưa chạy kiểm thử.")
    else:
        status.error("Chưa sửa thành công. Chi tiết lỗi ở phần tiến độ.")
    # Re-enable the send/analyze controls once after completion, without a timer.
    if agent3_busy:
        st.rerun()


st.markdown("---")
st.markdown("### 🏗️ Build & Run")
st.caption("Build và chạy source đã chọn. Dừng nếu build context hoặc bind mount trỏ ra ngoài thư mục này.")
if source_root and os.path.isdir(source_root):
    st.caption(f"Source sẽ build: `{Path(source_root).resolve()}`")
if st.button("🔨 Build & Run", type="primary", use_container_width=True,
             disabled=not source_root or not os.path.isdir(source_root) or agent3_busy or build_busy):
    try:
        build_manager.start(source_root)
    except (OSError, ValueError, RuntimeError) as exc:
        st.error(redact_secrets(exc, secrets=(api_key,)))
    else:
        st.rerun()

if build_job:
    st.caption("Dòng mới nhất ở trên; cuộn xuống để xem lại tiến trình build.")
    build_status = st.empty()
    build_log = st.empty()
    build_status.info("Đang build image và khởi động dịch vụ…" if not build_job.done.is_set()
                      else "Đang tải kết quả…")
    build_lines = []
    build_events = build_job.events[-200:] if build_job.done.is_set() else build_job.stream()
    for line in build_events:
        build_lines.append(line)
        build_log.markdown(_progress_table(build_lines), unsafe_allow_html=True)
    if build_job.state == "succeeded":
        build_status.success("✅ Build & Run thành công. Các dịch vụ Docker đang chạy.")
    else:
        build_status.error("Build & Run chưa thành công. Xem tiến độ ở bảng bên dưới.")
    if build_busy:
        st.rerun()


# ── Agent 1 initial testing report ────────────────────────────
st.markdown("---")
st.markdown("### 📝 Báo cáo kiểm thử ban đầu — Agent 1")
st.caption("Dùng Gemini 3.1 Pro Thinking qua CLI để viết báo cáo tiếng Việt từ log Agent 1 đã chọn: "
           "các bước kiểm thử, request/response, bằng chứng và kết luận ban đầu. "
           "Chỉ cần nạp log Agent 1 và đăng nhập CLI để tạo báo cáo.")
agent1_inputs = [agent1_report_input(data, path, secrets=(api_key,))
                 for data, path in zip(st.session_state.loaded_batches, st.session_state.loaded_file_paths)]
loaded_report_paths = set(st.session_state.loaded_file_paths)
agent1_inputs.extend({"log_path": path, "availability": "unreadable_or_not_loaded"}
                     for path in context if path not in loaded_report_paths)
report_data = redact_data({
    "agent1_inputs": agent1_inputs,
}, secrets=(api_key,))
report_context = json.dumps(report_data, ensure_ascii=False, sort_keys=True)
report_ready = any(item.get("availability") == "loaded" for item in agent1_inputs)
if not report_ready or st.session_state.llm_report_context != report_context:
    st.session_state.llm_report = ""
if not report_ready:
    st.info("Chọn ít nhất một log Agent 1 hợp lệ để viết báo cáo kiểm thử ban đầu.")

if st.button("📝 Gửi cho LLM viết report", key="generate_llm_report", type="primary",
             use_container_width=True, disabled=not report_ready):
    try:
        with st.spinner("Gemini CLI đang viết báo cáo…"):
            report_text = generate_report_cli(report_data, gemini_cli, secrets=(api_key,))
        st.session_state.llm_report = report_text
        st.session_state.llm_report_context = report_context
        st.success("Đã tạo báo cáo bằng Gemini CLI.")
    except LLMError as exc:
        st.error(redact_secrets(f"Không thể tạo báo cáo: {exc}", secrets=(api_key,)))

if st.session_state.llm_report:
    safe_report = redact_secrets(st.session_state.llm_report, secrets=(api_key,))
    st.markdown(safe_report)
    st.download_button("⬇️ Tải report Markdown", safe_report,
                       file_name="security_report.md", mime="text/markdown", key="download_llm_report")
