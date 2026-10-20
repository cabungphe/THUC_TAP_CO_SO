# -*- coding: utf-8 -*-
# Agent 4: Post-fix Verification (Expert Mode)
# So sánh ngữ nghĩa giữa Request/Response trước vá và sau vá.
# Ép AI tư duy (Chain-of-Thought) và tự đưa ra kết luận.

from burp import IBurpExtender, IMessageEditorTabFactory, IMessageEditorTab

from java.awt import BorderLayout, FlowLayout
from javax.swing import (
    SwingUtilities, JPanel, JButton, JLabel, JComboBox
)
from java.lang import Runnable
from java.net import URL
from java.io import BufferedReader, InputStreamReader, OutputStreamWriter

import codecs
import copy
import datetime
import json
import os
import re
import threading
import time
import traceback

# ============================================================
# CONFIG
# ============================================================

GROQ_API_KEY = os.environ.get(
    "CEREBRAS_API_KEY",
    "csk-6er93f5y3th4hyf5y5rfv43feeerdketdnprpkmjf3fxe233"
).strip()
AGENT4_MODEL = "gpt-oss-120b"
AGENT4_API_URL = "https://api.cerebras.ai/v1/chat/completions"
AGENT4_VERSION = "agent4-expert-v8-cot"

AGENT4_MAX_COMPLETION_TOKENS = 12288
RETRY_MAX_COMPLETION_TOKENS = 16384
MAX_GENERATION_RETRIES = 1
CONNECT_TIMEOUT_MS = 60000
READ_TIMEOUT_MS = 90000

RESPONSE_FORMAT_MODE = "json_object"
WAF_SAFE_TRANSPORT = True

MAX_HTTP_REQUEST_BYTES = 8192
MAX_HTTP_RESPONSE_BYTES = 32768
MAX_AGENT1_EXPORT_BYTES = 40000
MAX_RETEST_TESTCASES_UI = 12
MAX_HISTORY_PER_SESSION = 50

DATA_ROOT = u"D:\\Thực tập cơ sở\\Agent1_Data"
LABS_ROOT = os.path.join(DATA_ROOT, u"du_lieu_theo_lab")
AGENT4_DATA_DIR = os.path.join(DATA_ROOT, u"agent4_verify")

PROFILE_ORDER = ["SQLi", "LFI", "File Upload"]
PROFILE_LABELS = {
    "SQLi": u"SQL Injection",
    "LFI": u"Local File Inclusion",
    "File Upload": u"Unrestricted File Upload",
}

AGENT2_LOG_FOLDER = u"phan_tich_agent2"


# ============================================================
# CLOUDFLARE WAF TRANSPORT SAFETY
# ============================================================

_CF_REPLACEMENTS = [
    (u"../../../../../../../", u"\u00abT7\u00bb"),
    (u"../../../../../../",    u"\u00abT6\u00bb"),
    (u"../../../../../",       u"\u00abT5\u00bb"),
    (u"../../../../",          u"\u00abT4\u00bb"),
    (u"../../../",             u"\u00abT3\u00bb"),
    (u"../../",                u"\u00abT2\u00bb"),
    (u"../",                   u"\u00abT1\u00bb"),
    (u"..\\..\\..\\", u"\u00abW3\u00bb"),
    (u"..\\..\\",     u"\u00abW2\u00bb"),
    (u"..\\",         u"\u00abW1\u00bb"),
    (u"/etc/passwd",   u"\u00abFPAS\u00bb"),
    (u"etc/passwd",    u"\u00abFPAS2\u00bb"),
    (u"/etc/shadow",   u"\u00abFSHA\u00bb"),
    (u"etc/shadow",    u"\u00abFSHA2\u00bb"),
    (u"/etc/hostname", u"\u00abFHOS\u00bb"),
    (u"etc/hostname",  u"\u00abFHOS2\u00bb"),
    (u"/etc/hosts",    u"\u00abFHST\u00bb"),
    (u"etc/hosts",     u"\u00abFHST2\u00bb"),
    (u"windows/win.ini", u"\u00abFWIN\u00bb"),
    (u"win.ini",       u"\u00abFWIN2\u00bb"),
    (u"access.log",    u"\u00abFLOG\u00bb"),
    (u"php://filter", u"\u00abFPHPF\u00bb"),
    (u"php://input",  u"\u00abFPHPI\u00bb"),
    (u"php://",       u"\u00abFPHPS\u00bb"),
    (u"data://",      u"\u00abFDATA\u00bb"),
    (u"expect://",    u"\u00abFEXP\u00bb"),
    (u"convert.base64-encode", u"\u00abFB64E\u00bb"),
    (u"convert.base64-decode", u"\u00abFB64D\u00bb"),
    (u"UNION ALL SELECT", u"\u00abFUNAS\u00bb"),
    (u"UNION SELECT",     u"\u00abFUNS\u00bb"),
    (u"union select",     u"\u00abFunS\u00bb"),
    (u"information_schema", u"\u00abFINFO\u00bb"),
    (u"@@version",        u"\u00abFVERS\u00bb"),
    (u"group_concat",     u"\u00abFGC\u00bb"),
    (u"OR '1'='1",        u"\u00abFOR11\u00bb"),
    (u"OR 1=1",           u"\u00abFOR11b\u00bb"),
    (u"' OR '",           u"\u00abFOR2\u00bb"),
    (u"-- -",             u"\u00abFCOMM\u00bb"),
    (u"cmd.exe",   u"\u00abFCMD\u00bb"),
    (u"/bin/bash", u"\u00abFBINBASH\u00bb"),
    (u"/bin/sh",   u"\u00abFBINSH\u00bb"),
]

_CF_LEGEND = (
    u"\nTRANSPORT ENCODING (WAF-safe tokens):\n"
    u"Attack-like substrings trong USER message đã được thay bằng token ASCII an toàn. "
    u"Khi trích dẫn bằng chứng hoặc viết retest_payload, bạn CÓ THỂ dùng nguyên token "
    u"(harness tự decode) HOẶC viết cú pháp thật.\n"
)

def _cf_encode(text):
    text = _to_unicode(text)
    for real, token in _CF_REPLACEMENTS:
        if real in text:
            text = text.replace(real, token)
    return text

def _cf_decode(text):
    text = _to_unicode(text)
    for real, token in _CF_REPLACEMENTS:
        if token in text:
            text = text.replace(token, real)
    return text

def _cf_encode_user_message(body_dict):
    out = copy.deepcopy(body_dict)
    messages = out.get("messages", [])
    if len(messages) >= 2 and messages[1].get("role") == "user":
        messages[1]["content"] = _cf_encode(messages[1].get("content", u""))
    return out


# ============================================================
# EXPERT PROMPTS & SCHEMAS
# ============================================================

AGENT4_SYSTEM_PROMPT = (
    u"You are Agent 4, a Senior AppSec Engineer verifying if a vulnerability has been successfully patched.\n"
    u"You are given ORIGINAL_EVIDENCE (from Agent 1, containing the original request, payload, and response).\n"
    u"You are also given NEW_HTTP_REQUEST and NEW_HTTP_RESPONSE (the tester's current attempt after the patch was applied).\n"
    u"Your job is to compare the BEHAVIOR of the application in the original evidence vs. the new response.\n"
    u"NOTE: The new request might have a slightly different Session Cookie or CSRF token. Focus on the SEMANTIC intent of the payload.\n\n"
    u"CRITICAL REASONING PROCESS (You MUST output this in `expert_reasoning`):\n"
    u"1. Observation: Describe what the original response contained (e.g., leaked data, error message) and what the new response contains.\n"
    u"2. Hypothesis: Did the application properly sanitize/reject the malicious input? Or is the vulnerability still present but masked by another error?\n"
    u"3. Verdict Justification: Why does the evidence lead to your final verification_status?\n\n"
    u"VERIFICATION STATUS CATEGORIES:\n"
    u"- fixed: The malicious payload no longer has any effect. The app handles it safely (e.g., inputs sanitized, upload rejected, error disappears).\n"
    u"- partially_fixed: The specific payload is blocked, but the application still returns suspicious errors or allows related bypasses.\n"
    u"- not_fixed: The same attack logic still works (data leaked, RCE confirmed, etc.).\n"
    u"- inconclusive: The new request was malformed, the server crashed, or the tester provided irrelevant evidence.\n\n"
    u"GENERATE RETEST TESTCASES: Based on your analysis, propose 1-3 testcases to definitively prove the fix or confirm the bypass. "
    u"Do not just repeat the old payload if it was blocked; propose a variant that tests the robustness of the patch.\n"
    u"All readable values must be Vietnamese; enum values remain English.\n"
)

AGENT4_RESPONSE_SCHEMA = {
    "type": "OBJECT",
    "properties": {
        "expert_reasoning": {
            "type": "OBJECT",
            "properties": {
                "observation": {"type": "STRING"},
                "hypothesis": {"type": "STRING"},
                "verdict_justification": {"type": "STRING"}
            },
            "required": ["observation", "hypothesis", "verdict_justification"]
        },
        "ui_message": {"type": "STRING"},
        "verification_status": {
            "type": "STRING",
            "enum": ["fixed", "partially_fixed", "not_fixed", "inconclusive"]
        },
        "confidence": {"type": "STRING", "enum": ["low", "medium", "high"]},
        "before_after_comparison": {
            "type": "OBJECT",
            "properties": {
                "original_behavior": {"type": "STRING"},
                "current_behavior": {"type": "STRING"},
                "key_differences": {"type": "ARRAY", "items": {"type": "STRING"}},
                "fix_indicators": {"type": "ARRAY", "items": {"type": "STRING"}},
                "remaining_concerns": {"type": "ARRAY", "items": {"type": "STRING"}}
            },
            "required": ["original_behavior", "current_behavior", "key_differences", "fix_indicators", "remaining_concerns"]
        },
        "retest_testcases": {
            "type": "ARRAY",
            "items": {
                "type": "OBJECT",
                "properties": {
                    "step": {"type": "STRING"},
                    "title": {"type": "STRING"},
                    "priority": {"type": "STRING", "enum": ["high", "medium", "low"]},
                    "target": {
                        "type": "OBJECT",
                        "properties": {
                            "parameter": {"type": "STRING"},
                            "location": {"type": "STRING", "enum": ["query", "body", "header", "cookie", "path", "unknown"]}
                        },
                        "required": ["parameter", "location"]
                    },
                    "payload_detail": {"type": "STRING"},
                    "explanation": {"type": "STRING"},
                    "expected_if_fixed": {"type": "STRING"},
                    "expected_if_not_fixed": {"type": "STRING"}
                },
                "required": ["step", "title", "priority", "target", "payload_detail", "explanation", "expected_if_fixed", "expected_if_not_fixed"]
            }
        }
    },
    "required": ["expert_reasoning", "ui_message", "verification_status", "confidence", "before_after_comparison", "retest_testcases"]
}

AGENT4_JSON_TEMPLATE = {
    "expert_reasoning": {
        "observation": "__FILL_OBS__",
        "hypothesis": "__FILL_HYP__",
        "verdict_justification": "__FILL_JUST__"
    },
    "ui_message": "__FILL__",
    "verification_status": "inconclusive",
    "confidence": "low",
    "before_after_comparison": {
        "original_behavior": "__FILL__",
        "current_behavior": "__FILL__",
        "key_differences": ["__FILL__"],
        "fix_indicators": [],
        "remaining_concerns": []
    },
    "retest_testcases": [{
        "step": "1",
        "title": "__FILL__",
        "priority": "medium",
        "target": {"parameter": "__FILL__", "location": "query"},
        "payload_detail": "__FILL__",
        "explanation": "__FILL__",
        "expected_if_fixed": "__FILL__",
        "expected_if_not_fixed": "__FILL__"
    }]
}

# ============================================================
# UTILITIES
# ============================================================

def _now_iso():
    return datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S")

def _to_unicode(value):
    if value is None:
        return u""
    try:
        if isinstance(value, unicode):
            return value
    except Exception:
        pass
    try:
        if isinstance(value, str):
            try:
                return value.decode("utf-8")
            except BaseException:
                pass
            try:
                return value.decode("latin-1")
            except BaseException:
                pass
    except Exception:
        pass
    try:
        return unicode(value)
    except BaseException:
        pass
    return u"<unrepresentable>"

def _one_line(value, max_length=260):
    value = _to_unicode(value).replace(u"\r", u" ").replace(u"\n", u" ")
    value = u" ".join(value.split())
    if len(value) > max_length:
        return value[:max_length] + u"..."
    return value

def _first_line(value):
    lines = _to_unicode(value).splitlines()
    return _one_line(lines[0]) if lines else u""

def _wrap_text(text, max_width=72, indent=u""):
    text = _to_unicode(text)
    out_lines = []
    for paragraph in text.split(u"\n"):
        if not paragraph.strip():
            out_lines.append(u"")
            continue
        words = paragraph.split()
        cur = u""
        for w in words:
            w = _to_unicode(w)
            if cur and len(cur) + 1 + len(w) > max_width:
                out_lines.append(cur)
                cur = indent + w
            else:
                cur = (cur + u" " + w) if cur else w
        if cur:
            out_lines.append(cur)
    return u"\n".join(out_lines)

def _read_java_stream(stream):
    if stream is None:
        return u""
    reader = None
    try:
        reader = BufferedReader(InputStreamReader(stream, "UTF-8"))
        lines = []
        line = reader.readLine()
        while line is not None:
            lines.append(unicode(line))
            line = reader.readLine()
        return u"\n".join(lines)
    finally:
        if reader is not None:
            try:
                reader.close()
            except:
                pass

def _clean_json_text(text):
    text = _to_unicode(text).strip()
    if text.startswith("```json"): text = text[7:]
    elif text.startswith("```"): text = text[3:]
    if text.endswith("```"): text = text[:-3]
    return text.strip()

def _extract_groq_text(api_response):
    choices = api_response.get("choices", [])
    if not choices:
        raise ValueError(u"API khong tra ve choices.")
    message = choices[0].get("message", {})
    content = message.get("content", u"")
    if isinstance(content, list):
        parts = []
        for item in content:
            if isinstance(item, dict):
                if "text" in item: parts.append(_to_unicode(item.get("text", u"")))
                elif item.get("type") == "text": parts.append(_to_unicode(item.get("content", u"")))
        content = u"".join(parts)
    content = _to_unicode(content).strip()
    if not content:
        raise ValueError(u"Choice khong co message.content.")
    return content

def _utf8_size(value):
    return len(_to_unicode(value).encode("utf-8"))

def _compact_json(value):
    return _to_unicode(json.dumps(value, ensure_ascii=False, separators=(",", ":")))

def _ensure_dir(path):
    if not os.path.isdir(path):
        os.makedirs(path)

def _write_json_atomic(path, data):
    parent = os.path.dirname(path)
    _ensure_dir(parent)
    tmp = path + ".tmp"
    text = json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True)
    with codecs.open(tmp, "w", "utf-8") as f:
        f.write(_to_unicode(text))
    if os.path.exists(path):
        os.remove(path)
    os.rename(tmp, path)

def _safe_filename(name):
    name = _to_unicode(name).strip() or u"unknown"
    invalid = u'<>:"/\\|?*'
    out = []
    for ch in name:
        if ch in invalid or ord(ch) < 32:
            out.append(u"_")
        else:
            out.append(ch)
    cleaned = u"".join(out).strip().rstrip(u".") or u"unknown"
    return cleaned[:80]

def _payload_size(body):
    return _utf8_size(_compact_json(body))

def _to_groq_json_schema(node):
    if isinstance(node, dict):
        out = {}
        for key, value in node.items():
            if key == "type" and isinstance(value, (str, unicode)):
                mapped = {
                    "OBJECT": "object", "STRING": "string", "ARRAY": "array",
                    "NUMBER": "number", "INTEGER": "integer", "BOOLEAN": "boolean"
                }.get(value, value.lower())
                out[key] = mapped
            else:
                out[key] = _to_groq_json_schema(value)
        if out.get("type") == "object":
            props = out.get("properties", {})
            out["required"] = list(props.keys())
            out["additionalProperties"] = False
        return out
    if isinstance(node, list):
        return [_to_groq_json_schema(i) for i in node]
    return node

# ============================================================
# VALIDATION
# ============================================================

class ResponseGenerationError(ValueError):
    def __init__(self, message, retryable=True):
        ValueError.__init__(self, message)
        self.retryable = retryable

def _validate_schema_value(value, schema, path=u"root"):
    kind = schema.get("type", "").lower()
    if kind == "object":
        if not isinstance(value, dict):
            raise ResponseGenerationError(u"%s phải là object." % path)
        props = schema.get("properties", {})
        missing = [n for n in schema.get("required", []) if n not in value]
        if missing:
            raise ResponseGenerationError(u"JSON thiếu %s: %s." % (path, u", ".join(missing)))
        for n, child in props.items():
            if n in value:
                _validate_schema_value(value[n], child, path + u"." + n)
    elif kind == "array":
        if not isinstance(value, list):
            raise ResponseGenerationError(u"%s phải là array." % path)
        for i, item in enumerate(value):
            _validate_schema_value(item, schema["items"], u"%s[%s]" % (path, i))
    elif kind == "string":
        if not isinstance(value, (str, unicode)):
            raise ResponseGenerationError(u"%s phải là string." % path)
        if "enum" in schema and value not in schema["enum"]:
            raise ResponseGenerationError(u"Enum không hợp lệ tại %s." % path)
        if value.startswith("__FILL") and value.endswith("__"):
            raise ResponseGenerationError(u"Placeholder tại %s." % path)

def _decode_agent4_response(response_text):
    try:
        response = json.loads(response_text)
        choices = response.get("choices", [])
        if not choices or not isinstance(choices[0], dict):
            raise ResponseGenerationError(u"API không trả choices hợp lệ.")
        choice = choices[0]
        if choice.get("finish_reason") in ("length", "max_tokens"):
            raise ResponseGenerationError(u"Output bị cắt do hết completion token.")
        message = choice.get("message", {})
        if message.get("refusal") or choice.get("finish_reason") == "content_filter":
            raise ResponseGenerationError(u"Model từ chối.", False)
        result = json.loads(_clean_json_text(_extract_groq_text(response)))
    except ResponseGenerationError:
        raise
    except Exception:
        raise ResponseGenerationError(u"Output không phải JSON hoàn chỉnh.")
    
    _validate_schema_value(result, AGENT4_RESPONSE_SCHEMA)
    if not result["ui_message"].strip(): raise ResponseGenerationError(u"ui_message rỗng.")
    if not result["expert_reasoning"]["observation"].strip(): raise ResponseGenerationError(u"reasoning rỗng.")
    return result

def _api_error_summary(response_text):
    text = _to_unicode(response_text or u"")
    try:
        data = json.loads(text)
        error = data.get("error", data)
        if isinstance(error, dict):
            message = _to_unicode(error.get("message", u""))
            code = _to_unicode(error.get("code", u""))
        else:
            message = _to_unicode(error)
            code = u""
        return _one_line((code + u": " + message) if code else (message or text), 700)
    except Exception:
        return _one_line(text, 200)

def _api_generation_failure(response_text):
    try:
        error = json.loads(response_text).get("error", {})
        if error.get("code") == "json_validate_failed":
            return u"API từ chối JSON: " + _api_error_summary(response_text)
    except Exception:
        pass
    return None

def _usage_snapshot(response_text):
    try:
        usage = json.loads(response_text).get("usage", {})
        if not isinstance(usage, dict): return {}
        return dict((k, usage[k]) for k in ("prompt_tokens", "completion_tokens", "total_tokens") if k in usage)
    except Exception:
        return {}

def _request_response_format():
    if RESPONSE_FORMAT_MODE == "json_object":
        return {"type": "json_object"}
    if RESPONSE_FORMAT_MODE == "json_schema":
        return {"type": "json_schema", "json_schema": {
            "name": "agent4_retest_response", "strict": True,
            "schema": _to_groq_json_schema(AGENT4_RESPONSE_SCHEMA)
        }}
    raise ValueError(u"RESPONSE_FORMAT_MODE sai.")

# ============================================================
# LOG DISCOVERY
# ============================================================

def _list_all_agent1_exports(profile_filter=None, lab_filter=None):
    results = []
    if not os.path.isdir(LABS_ROOT):
        return results
    try:
        for lab_name_raw in os.listdir(LABS_ROOT):
            lab_name = _to_unicode(lab_name_raw)
            if lab_filter is not None and lab_name != lab_filter:
                continue
            export_dir = os.path.join(LABS_ROOT, lab_name, u"xuat_cho_agent2")
            if not os.path.isdir(export_dir): continue
            try: names = os.listdir(export_dir)
            except Exception: continue
            for fname_raw in names:
                fname = _to_unicode(fname_raw)
                if not fname.startswith(u"agent1_") or not fname.endswith(u"_cho_agent2.json"):
                    continue
                inner = fname[len(u"agent1_"):-len(u"_cho_agent2.json")]
                if u"_phien_" in inner:
                    profile = inner.rsplit(u"_phien_", 1)[0]
                else:
                    profile = inner
                profile = profile.strip()
                if profile_filter and profile != profile_filter:
                    continue
                path = os.path.join(export_dir, fname)
                try: mtime = os.path.getmtime(path)
                except Exception: continue
                results.append((path, lab_name, profile, mtime))
    except Exception:
        pass
    results.sort(key=lambda x: x[3], reverse=True)
    return results

def _load_agent1_export_from_path(path):
    if not path or not os.path.isfile(path):
        return None
    try:
        with codecs.open(path, "r", "utf-8") as f:
            return json.loads(f.read())
    except Exception:
        return None

def _list_agent2_logs(lab_name):
    if not lab_name: return []
    folder = os.path.join(LABS_ROOT, _to_unicode(lab_name), AGENT2_LOG_FOLDER)
    if not os.path.isdir(folder): return []
    out = []
    try:
        for fname_raw in os.listdir(folder):
            fname = _to_unicode(fname_raw)
            lower = fname.lower()
            if not (lower.endswith(".json") or lower.endswith(".md") or lower.endswith(".txt")):
                continue
            path = os.path.join(folder, fname)
            try: out.append((os.path.getmtime(path), path))
            except Exception: pass
    except Exception: pass
    out.sort(reverse=True)
    return out

def _find_agent2_log_for_lab(lab_name, session_id=None):
    logs = [(mtime, path) for mtime, path in _list_agent2_logs(lab_name)
            if os.path.basename(path).lower().startswith("agent2_")
            and path.lower().endswith(".json")]
    if not logs: return None
    if session_id:
        sid = _to_unicode(session_id).lower()
        for _, path in logs:
            if os.path.basename(path).lower().startswith(u"agent2_" + sid + u"_"):
                return path
        return None
    return logs[0][1]

def _find_agent3_instructions_for_lab(lab_name, session_id=None):
    if not lab_name: return None
    folder = os.path.join(LABS_ROOT, _to_unicode(lab_name), AGENT2_LOG_FOLDER)
    if not os.path.isdir(folder): return None
    candidates = []
    try:
        for fname_raw in os.listdir(folder):
            fname = _to_unicode(fname_raw)
            if u"agent3" not in fname.lower(): continue
            lower = fname.lower()
            if not (lower.endswith(".md") or lower.endswith(".json") or lower.endswith(".txt")):
                continue
            path = os.path.join(folder, fname)
            try: candidates.append((os.path.getmtime(path), path))
            except Exception: pass
    except Exception: pass
    if not candidates: return None
    candidates.sort(reverse=True)
    if session_id:
        sid = _to_unicode(session_id).lower()
        for _, path in candidates:
            if os.path.splitext(os.path.basename(path))[0].lower() == u"agent3_fix_" + sid:
                return path
        return None
    return candidates[0][1]

def _format_evidence_for_prompt(export_data):
    if not isinstance(export_data, dict):
        return u"{}"
    
    session = export_data.get("session", {}) or {}
    observations = export_data.get("observations", []) or []
    
    chain = []
    for obs in observations:
        req = obs.get("original_request", u"")
        if not req: req = obs.get("request_content", u"")
        
        chain.append({
            "step": obs.get("step"),
            "target": obs.get("target") or {},
            "original_payload_or_request": req,
            "evidence_summary": obs.get("evidence_summary") or {
                "verdict": obs.get("verdict"),
                "confidence": obs.get("confidence"),
                "response_key_text": obs.get("response_key_text"),
                "observed_indicators": obs.get("indicators")
            }
        })
    
    compact_evidence = {
        "producer": "Agent 1",
        "lab_name": session.get("lab_name", u""),
        "session_id": session.get("session_id", u""),
        "profile": session.get("profile", u""),
        "final_verdict": session.get("final_verdict", u""),
        "workflow_chain": chain
    }
    return _compact_json(compact_evidence)

# ============================================================
# API CLIENT
# ============================================================

class Agent4ApiClient(object):
    def __init__(self, callbacks=None):
        self._callbacks = callbacks

    def _call_once(self, body_dict):
        if not GROQ_API_KEY:
            raise ValueError(u"Chưa đặt biến môi trường CEREBRAS_API_KEY.")
        outgoing = _cf_encode_user_message(body_dict) if WAF_SAFE_TRANSPORT else body_dict
        body_string = _compact_json(outgoing)
        
        if self._callbacks is not None:
            host = "api.cerebras.ai"
            port = 443
            req = (
                "POST /v1/chat/completions HTTP/1.1\r\n"
                "Host: " + host + "\r\n"
                "Content-Type: application/json\r\n"
                "Accept: application/json\r\n"
                "User-Agent: Mozilla/5.0\r\n"
                "Authorization: Bearer " + GROQ_API_KEY + "\r\n"
                "Connection: close\r\n"
                "Content-Length: " + str(len(body_string.encode("utf-8"))) + "\r\n"
                "\r\n" + body_string
            )
            svc = self._callbacks.getHelpers().buildHttpService(host, port, True)
            resp = self._callbacks.makeHttpRequest(svc, req.encode("utf-8"))
            resp_bytes = resp.getResponse()
            if not resp_bytes:
                return 500, u'{"error": "Empty response from Burp"}'
            info = self._callbacks.getHelpers().analyzeResponse(resp_bytes)
            code = info.getStatusCode()
            body = resp_bytes[info.getBodyOffset():].tostring().decode("utf-8", "replace")
            if WAF_SAFE_TRANSPORT:
                body = _cf_decode(body)
            return code, body
            
        conn = None
        try:
            conn = URL(AGENT4_API_URL).openConnection()
            conn.setRequestMethod("POST")
            conn.setRequestProperty("Content-Type", "application/json")
            conn.setRequestProperty("Accept", "application/json")
            conn.setRequestProperty("Authorization", "Bearer " + GROQ_API_KEY)
            conn.setDoOutput(True)
            conn.setConnectTimeout(CONNECT_TIMEOUT_MS)
            conn.setReadTimeout(READ_TIMEOUT_MS)
            w = OutputStreamWriter(conn.getOutputStream(), "UTF-8")
            try:
                w.write(body_string)
                w.flush()
            finally:
                w.close()
            code = conn.getResponseCode()
            stream = conn.getInputStream() if 200 <= code < 300 else conn.getErrorStream()
            text = _read_java_stream(stream)
            if WAF_SAFE_TRANSPORT:
                text = _cf_decode(text)
            return code, text
        finally:
            if conn is not None:
                try: conn.disconnect()
                except: pass

    def request_combined(self, body_dict, on_retry=None):
        request_body = copy.deepcopy(body_dict)
        metadata = {"api_requests": 0, "retried": False, "attempts": []}
        max_retries = min(1, max(0, MAX_GENERATION_RETRIES))
        transient = (403, 408, 425, 429, 500, 502, 503, 504)

        for attempt in range(1 + max_retries):
            code, response_text = self._call_once(request_body)
            metadata["api_requests"] += 1
            info = {
                "http_status": code,
                "response_format": request_body.get("response_format", {}).get("type"),
                "usage": _usage_snapshot(response_text)
            }
            metadata["attempts"].append(info)

            final_json = None
            failure = None
            is_transient = False

            if 200 <= code < 300:
                try:
                    final_json = _decode_agent4_response(response_text)
                except ResponseGenerationError as e:
                    if not e.retryable: raise
                    failure = _to_unicode(e)
            elif code == 400:
                failure = _api_generation_failure(response_text)
            elif code in transient and attempt < max_retries:
                time.sleep(1.5)
                failure = u"Transient HTTP %s; retrying." % code
                is_transient = True

            if failure is None:
                return code, response_text, request_body["model"], final_json, metadata

            info["generation_error"] = failure
            if attempt >= max_retries:
                return code, response_text, request_body["model"], None, metadata

            metadata["retried"] = True
            if on_retry is not None:
                on_retry(failure)

            if not is_transient:
                request_body["max_tokens"] = RETRY_MAX_COMPLETION_TOKENS
                request_body["response_format"] = {"type": "json_object"}
                request_body["messages"][0]["content"] += u"\nRETRY: Output không hợp lệ. Trả về JSON hoàn chỉnh."

# ============================================================
# SWING RUNNABLES
# ============================================================

class UpdateUIIfCurrent(Runnable):
    def __init__(self, tab, message_id, text):
        self.tab = tab
        self.message_id = message_id
        self.text = _to_unicode(text)
    def run(self):
        if self.tab._messageId != self.message_id: return
        try:
            self.tab._txtOutput.setText(self.text.encode("utf-8"))
        except Exception:
            self.tab._txtOutput.setText(b"[Agent4 UI render error]")

class SetVerifyIfCurrent(Runnable):
    def __init__(self, tab, message_id, enabled, text):
        self.tab = tab
        self.message_id = message_id
        self.enabled = enabled
        self.text = _to_unicode(text)
    def run(self):
        if self.tab._messageId != self.message_id: return
        try:
            self.tab._btnVerify.setEnabled(self.enabled)
            self.tab._btnVerify.setText(self.text)
        except Exception:
            pass

# ============================================================
# BURP EXTENDER
# ============================================================

class BurpExtender(IBurpExtender, IMessageEditorTabFactory):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._tabs = []
        self._api = Agent4ApiClient(callbacks)
        self._selectedProfile = "SQLi"

        callbacks.setExtensionName("Agent 4: Post-Fix Verification (Expert)")
        callbacks.registerMessageEditorTabFactory(self)

        callbacks.printOutput(u"[Agent4] Extension loaded (Expert CoT Mode v8).")
        callbacks.printOutput(u"[Agent4] Model: " + AGENT4_MODEL)
        callbacks.printOutput(u"[Agent4] Labs root: " + _to_unicode(LABS_ROOT))

        if not GROQ_API_KEY:
            callbacks.printError(u"[Agent4] CEREBRAS_API_KEY not set.")

    def createNewInstance(self, controller, editable):
        tab = Agent4VerifyTab(self, controller)
        self._tabs.append(tab)
        return tab

# ============================================================
# AGENT 4 TAB
# ============================================================

class Agent4VerifyTab(IMessageEditorTab):
    def __init__(self, extender, controller):
        self._extender = extender
        self._callbacks = extender._callbacks
        self._helpers = extender._helpers
        self._controller = controller

        self._requestBytes = None
        self._responseBytes = None
        self._isRequestView = False
        self._messageId = 0
        self._syncingUi = False

        self._txtOutput = self._callbacks.createTextEditor()
        self._txtOutput.setEditable(False)

        self._lblProfile = JLabel("Profile:")
        self._cmbProfile = JComboBox(PROFILE_ORDER)
        self._cmbProfile.addActionListener(lambda e: self._on_profile_changed())
        
        self._exportChoices = []
        self._cmbSession = JComboBox()
        self._cmbSession.addActionListener(lambda e: self._on_session_changed())

        self._btnVerify = JButton(u"Analyzing...")
        self._btnVerify.setPreferredSize(self._btnVerify.getPreferredSize())
        self._btnVerify.setText(u"Analyze")
        self._btnVerify.setEnabled(False)
        self._btnVerify.addActionListener(lambda e: self.on_verify_click())

        self._controls = JPanel(FlowLayout(FlowLayout.LEFT, 4, 3))
        self._controls.add(self._lblProfile)
        self._controls.add(self._cmbProfile)
        self._controls.add(self._btnVerify)
        
        self._cmbSession.setPrototypeDisplayValue(u"LFI_phien_04")
        self._sessionPanel = JPanel(BorderLayout(4, 0))
        self._sessionPanel.add(JLabel(u"Phiên:"), BorderLayout.WEST)
        self._sessionPanel.add(self._cmbSession, BorderLayout.CENTER)
        
        self._toolbar = JPanel(BorderLayout(6, 0))
        self._toolbar.add(self._controls, BorderLayout.WEST)
        self._toolbar.add(self._sessionPanel, BorderLayout.CENTER)

        self._panel = JPanel(BorderLayout())
        self._panel.add(self._toolbar, BorderLayout.NORTH)
        self._panel.add(self._txtOutput.getComponent(), BorderLayout.CENTER)

        try:
            self._callbacks.customizeUiComponent(self._panel)
            self._callbacks.customizeUiComponent(self._toolbar)
        except: pass

    def getTabCaption(self): return u"Agent 4 Verify"
    def getUiComponent(self): return self._panel
    def isEnabled(self, content, isRequest): return (not isRequest) and (content is not None)

    def setMessage(self, content, isRequest):
        self._messageId += 1
        self._isRequestView = isRequest

        if content is None:
            self._requestBytes = None
            self._responseBytes = None
            self._btnVerify.setEnabled(False)
            self._txtOutput.setText("".encode("utf-8"))
            return

        if isRequest:
            self._requestBytes = content
            self._responseBytes = None
            self._btnVerify.setEnabled(False)
            return

        self._responseBytes = content
        try: self._requestBytes = self._controller.getRequest()
        except: self._requestBytes = None

        self._refresh_export_choices()
        self._btnVerify.setEnabled(True)
        self._btnVerify.setText(u"Analyze")
        self._show_ready_message()

    def getMessage(self):
        return self._requestBytes if self._isRequestView else self._responseBytes

    def isModified(self): return False
    def getSelectedData(self):
        try: return self._txtOutput.getSelectedText()
        except: return None

    def _selected_profile(self):
        v = self._cmbProfile.getSelectedItem()
        return _to_unicode(v) if v else "SQLi"

    def _on_profile_changed(self):
        if self._syncingUi: return
        self._messageId += 1
        self._extender._selectedProfile = self._selected_profile()
        self._refresh_export_choices()
        if self._responseBytes is not None:
            self._show_ready_message()

    def _current_lab(self):
        try:
            service = self._controller.getHttpService()
            host = _to_unicode(service.getHost()).strip()
            port = service.getPort()
            protocol = _to_unicode(service.getProtocol()).lower()
            default = (protocol == "https" and port == 443) or (protocol == "http" and port == 80)
            name = host if default or port <= 0 else u"%s_%s" % (host, port)
            invalid = u'<>:"/\\|?*'
            return u"".join(u"_" if ch in invalid or ord(ch) < 32 else ch for ch in name).strip().rstrip(u".")[:80]
        except Exception:
            return u""

    def _refresh_export_choices(self):
        previous = self._selected_export()[0]
        lab = self._current_lab()
        self._exportChoices = (_list_all_agent1_exports(self._selected_profile(), lab) if lab else [])
        self._syncingUi = True
        try:
            self._cmbSession.removeAllItems()
            self._cmbSession.addItem(u"Chọn phiên...")
            selected = 0
            for index, item in enumerate(self._exportChoices, 1):
                name = _to_unicode(os.path.basename(item[0]))
                if name.startswith(u"agent1_") and name.endswith(u"_cho_agent2.json"):
                    name = name[len(u"agent1_"):-len(u"_cho_agent2.json")]
                self._cmbSession.addItem(name)
                if item[0] == previous:
                    selected = index
            if not selected and len(self._exportChoices) == 1:
                selected = 1
            self._cmbSession.setSelectedIndex(selected)
        finally:
            self._syncingUi = False

    def _selected_export(self):
        index = self._cmbSession.getSelectedIndex() - 1
        if 0 <= index < len(self._exportChoices):
            return self._exportChoices[index][:3]
        return None, None, None

    def _on_session_changed(self):
        if self._syncingUi: return
        self._messageId += 1
        if self._responseBytes is not None:
            self._show_ready_message()

    def _show_ready_message(self):
        profile = self._selected_profile()
        path, lab_name, _ = self._selected_export()
        self._cmbSession.setToolTipText(_to_unicode(path) if path else u"Chọn phiên Agent 1")
        self._btnVerify.setEnabled(bool(path))
        self._btnVerify.setText(u"Analyze")

        if not path:
            msg = (u"Chọn phiên Agent 1 của lab hiện tại cho profile '%s'.\n\n"
                   u"Đã quét: %s\\*\\xuat_cho_agent2\\agent1_%s_phien_*_cho_agent2.json\n\n"
                   u"Yêu cầu:\n"
                   u"  1. Agent 1 đã phát hiện lỗ hổng (verdict=vulnerable) với profile này.\n"
                   u"  2. Bạn đã bấm 'New Session' trong tab AI Assistant để Agent 1 export.\n\n"
                   u"Sau khi có log, quay lại tab này và bấm 'Analyze'.") % (profile, _to_unicode(LABS_ROOT), profile)
            self._txtOutput.setText(msg.encode("utf-8"))
            return

        export_data = _load_agent1_export_from_path(path)
        session_id = u""; final_verdict = u"?"
        if export_data:
            sess = export_data.get("session", {}) or {}
            session_id = _to_unicode(sess.get("session_id", u""))
            final_verdict = _to_unicode(sess.get("final_verdict", u"?"))

        msg = (u"Sẵn sàng.\n" + u"-"*52 + u"\n"
               u"Profile: %s\n"
               u"Log Agent 1 đã chọn:\n    %s\n"
               u"Lab: %s | Session: %s\n"
               u"Kết luận Agent 1: %s\n" + u"-"*52 + u"\n\n"
               u"Agent 4 sẽ đọc log cũ, kết hợp với Request/Response hiện tại để so sánh bằng AI.\n\n"
               u"Bấm 'Analyze' để bắt đầu.") % (
               profile, _to_unicode(path), _to_unicode(lab_name), session_id, final_verdict)
        self._txtOutput.setText(msg.encode("utf-8"))

    def on_verify_click(self):
        if self._isRequestView or self._responseBytes is None: return

        request_bytes = self._requestBytes
        response_bytes = self._responseBytes
        message_id = self._messageId
        profile = self._selected_profile()
        export_path, lab_name, _ = self._selected_export()
        if not export_path:
            self._show_ready_message()
            return

        self._btnVerify.setEnabled(False)
        self._btnVerify.setText(u"Analyzing...")
        SwingUtilities.invokeLater(UpdateUIIfCurrent(
            self, message_id,
            u"[*] Agent 4 đang so sánh hành vi ứng dụng (Trước vá vs Sau vá)...\n"
            u"Profile: %s\nModel: %s" % (profile, AGENT4_MODEL)
        ))

        try:
            req_str = self._helpers.bytesToString(request_bytes) if request_bytes else u"(không có request gốc)"
            res_str = self._helpers.bytesToString(response_bytes)
        except Exception as e:
            SwingUtilities.invokeLater(UpdateUIIfCurrent(self, message_id, u"[!] Không đọc được HTTP: " + _to_unicode(e)))
            SwingUtilities.invokeLater(SetVerifyIfCurrent(self, message_id, True, u"Analyze"))
            return

        t = threading.Thread(target=self._call_agent4, args=(req_str, res_str, message_id, profile, export_path, lab_name))
        try: t.setDaemon(True)
        except: pass
        t.start()

    def _call_agent4(self, req_str, res_str, message_id, profile, path, lab_name):
        started = time.time()
        used_model = u"không gọi AI"
        session_id = u""
        try:
            export_data = _load_agent1_export_from_path(path)
            if not isinstance(export_data, dict):
                raise ValueError(u"Không đọc được log Agent 1 đã chọn.")
            session = export_data.get("session") or {}
            session_id = _to_unicode(session.get("session_id", u""))

            evidence_json = _format_evidence_for_prompt(export_data)
            
            template = copy.deepcopy(AGENT4_JSON_TEMPLATE)
            sections = [
                ("ORIGINAL_EVIDENCE", evidence_json),
                ("NEW_HTTP_REQUEST", req_str),
                ("NEW_HTTP_RESPONSE", res_str),
            ]
            body = {
                "model": AGENT4_MODEL,
                "messages": [
                    {"role": "system", "content": AGENT4_SYSTEM_PROMPT + u"\nReturn JSON exactly matching this template:\n" + _compact_json(template)},
                    {"role": "user", "content": u"\n\n".join(u"<%s>\n%s\n</%s>" % (n, v, n) for n, v in sections)},
                ],
                "response_format": _request_response_format(),
                "max_tokens": AGENT4_MAX_COMPLETION_TOKENS,
            }
            if WAF_SAFE_TRANSPORT:
                body["messages"][0]["content"] += _CF_LEGEND
                
            if _payload_size(body) > 65536 - 1024:
                raise ValueError(u"Dữ liệu quá lớn để AI so sánh. Vui lòng kiểm tra lại log.")

            code, response_text, model, generated, metadata = self._extender._api.request_combined(body)
            if not (200 <= code < 300) or generated is None:
                raise ValueError(u"API không trả kết quả so sánh hợp lệ. " + _api_error_summary(response_text))
                
            used_model = model
            result = generated
            
            elapsed = time.time() - started
            output = self._format_output(result, elapsed, used_model, path)
            self._save_result(result, req_str, res_str, path, session_id)
            SwingUtilities.invokeLater(UpdateUIIfCurrent(self, message_id, output))

        except Exception as exc:
            self._callbacks.printError(u"[Agent4] " + _to_unicode(exc))
            SwingUtilities.invokeLater(UpdateUIIfCurrent(self, message_id, u"[!] Lỗi Agent 4: " + _to_unicode(exc)))
        finally:
            SwingUtilities.invokeLater(SetVerifyIfCurrent(self, message_id, True, u"Analyze"))

    def _format_output(self, result, elapsed, used_model, export_path):
        status_labels = {
            "fixed": u"ĐÃ VÁ THÀNH CÔNG",
            "partially_fixed": u"VÁ CHƯA HOÀN TOÀN",
            "not_fixed": u"CHƯA ĐƯỢC VÁ",
            "inconclusive": u"CHƯA ĐỦ CĂN CỨ",
        }
        conf = {"low": u"thấp", "medium": u"trung bình", "high": u"cao"}

        status = _to_unicode(result.get("verification_status", u"inconclusive"))
        confidence = _to_unicode(result.get("confidence", u"low"))

        out = u"[Agent 4] %s | confidence=%s | %.1fs\n" % (
            _to_unicode(status_labels.get(status, status.upper())),
            _to_unicode(conf.get(confidence, confidence)),
            elapsed
        )

        reasoning = result.get("expert_reasoning", {})
        if reasoning:
            if reasoning.get("observation"):
                out += u"\n- Quan sát:\n" + _wrap_text(reasoning["observation"], 68, u"   ") + u"\n"
            if reasoning.get("hypothesis"):
                out += u"- Giả thuyết:\n" + _wrap_text(reasoning["hypothesis"], 68, u"   ") + u"\n"
            if reasoning.get("verdict_justification"):
                out += u"- Lý do kết luận:\n" + _wrap_text(reasoning["verdict_justification"], 68, u"   ") + u"\n"

        out += u"\nNhận định\n" + u"-" * 52 + u"\n"
        out += _wrap_text(_to_unicode(result.get("ui_message", u"")), 72) + u"\n"

        tcs = result.get("retest_testcases", []) or []
        out += u"\nTESTCASE KIỂM THỬ LẠI (AI ĐỀ XUẤT)\n" + u"-" * 52 + u"\n"
        if not tcs:
            out += u"(Không có testcase mới.)\n"
        else:
            for idx, tc in enumerate(tcs, 1):
                step = _to_unicode(tc.get("step", u""))
                title = _to_unicode(tc.get("title", u""))
                target = tc.get("target", {}) or {}
                param = _to_unicode(target.get("parameter", u""))
                loc = _to_unicode(target.get("location", u"unknown"))
                payload = _to_unicode(tc.get("payload_detail", u""))
                explanation = _to_unicode(tc.get("explanation", u""))
                eif = _to_unicode(tc.get("expected_if_fixed", u""))
                einf = _to_unicode(tc.get("expected_if_not_fixed", u""))

                out += u"\n[%d] STEP %s — %s\n" % (idx, step or u"?", _one_line(title, 120))
                if param or loc != u"unknown":
                    out += u"    Target : %s:%s\n" % (loc, param or u"(không xác định)")
                out += u"    Lý do  : " + _wrap_text(explanation, 62, u"             ") + u"\n"
                out += u"    PAYLOAD: %s\n" % _one_line(payload, 220)
                if eif:
                    out += u"    Đã vá  : " + _wrap_text(eif, 62, u"             ") + u"\n"
                if einf:
                    out += u"    Chưa vá: " + _wrap_text(einf, 62, u"             ") + u"\n"
                out += u"-" * 60 + u"\n"

        out += u"\nModel: %s | Agent 4 chỉ phân tích — KHÔNG tự gửi request.\n" % _to_unicode(used_model)
        return out

    def _save_result(self, result, req_str, res_str, export_path, session_id):
        try:
            _ensure_dir(AGENT4_DATA_DIR)
            safe_sid = _safe_filename(session_id or u"unknown")
            fp = os.path.join(AGENT4_DATA_DIR, u"agent4_verify_%s.json" % safe_sid)

            record = {
                "timestamp": _now_iso(),
                "agent_version": AGENT4_VERSION,
                "model": AGENT4_MODEL,
                "agent1_export_source": _to_unicode(export_path),
                "request_line": _first_line(req_str),
                "response_status": _first_line(res_str),
                "verification_result": result,
            }

            if os.path.isfile(fp):
                try:
                    with codecs.open(fp, "r", "utf-8") as f:
                        data = json.loads(f.read())
                except Exception:
                    data = {}
            else:
                data = {}

            history = data.get("results") or []
            history.append(record)
            if len(history) > MAX_HISTORY_PER_SESSION:
                history = history[-MAX_HISTORY_PER_SESSION:]

            out = {
                "session_id": session_id,
                "agent_version": AGENT4_VERSION,
                "last_updated": _now_iso(),
                "results": history,
            }
            _write_json_atomic(fp, out)
            self._callbacks.printOutput(u"[Agent4] Đã lưu: " + _to_unicode(fp))
        except Exception as e:
            self._callbacks.printError(u"[Agent4] Không lưu được: " + _to_unicode(e))