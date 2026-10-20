import ast
import json
import os
import subprocess
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import streamlit as st
from streamlit.testing.v1 import AppTest

from agent2.lab_storage import lab_directory, save_analysis, session_name
from agent2.agent import Agent2Runner


class LabStorageTests(unittest.TestCase):
    def test_exports_are_separate_per_lab_and_analysis_run(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "du_lieu_theo_lab"
            batch = {"session": {"session_id": "LFI_phien_01"}}
            args = (batch, "agent1_LFI_phien_01_cho_agent2.json",
                    {"results": [], "detail": "private-test-key"}, "Báo cáo", "Sửa lỗi", temporary)
            first = save_analysis(root, "127.0.0.1", *args, secrets=("private-test-key",))
            second = save_analysis(root, "127.0.0.1", *args)
            other = save_analysis(root, "other-lab", *args)
            self.assertNotEqual(first["result_path"], second["result_path"])
            self.assertNotEqual(first["fix_path"], other["fix_path"])
            output = root.resolve() / "127.0.0.1" / "phan_tich_agent2"
            self.assertEqual(Path(first["result_path"]).parent, output)
            self.assertRegex(Path(first["result_path"]).name,
                             r"^agent2_LFI_phien_01_\d{8}_\d{6}\.json$")
            self.assertEqual(Path(first["fix_path"]).name, "agent3_fix_LFI_phien_01.md")
            data = json.loads(Path(first["result_path"]).read_text(encoding="utf-8"))
            self.assertEqual(data["session_id"], "LFI_phien_01")
            self.assertEqual(data["detail"], "[REDACTED]")
            self.assertEqual(data["lab_name"], "127.0.0.1")
            self.assertIn("chưa gửi Agent 3", Path(first["fix_path"]).read_text(encoding="utf-8"))
            self.assertTrue((output.parent / "phien_kiem_thu").is_dir())
            self.assertTrue((output.parent / "xuat_cho_agent2").is_dir())

    def test_metadata_cannot_escape_lab_directory(self):
        with tempfile.TemporaryDirectory() as temporary:
            for name in ("..", "../outside", "a/b", "a\\b", "C:\\outside"):
                with self.assertRaises(ValueError):
                    lab_directory(temporary, name)
            sid = session_name({"session": {"session_id": "../../outside"}}, "input.json")
            self.assertNotIn("/", sid)
            self.assertEqual(session_name({}, "agent1_LFI_phien_01_cho_agent2.json"), "LFI_phien_01")

    def test_agent4_selects_analysis_json_even_when_fix_markdown_is_newer(self):
        # Burp/Jython imports are unavailable in CPython; exercise the actual pure lookup helpers.
        source = Path(__file__).resolve().parents[2] / "agent4_verify.py"
        tree = ast.parse(source.read_text(encoding="utf-8"))
        names = {"_list_agent2_logs", "_find_agent2_log_for_lab", "_find_agent3_instructions_for_lab"}
        selected = ast.Module(body=[n for n in tree.body if isinstance(n, ast.FunctionDef)
                                    and n.name in names], type_ignores=[])
        with tempfile.TemporaryDirectory() as temporary:
            env = {"os": os, "LABS_ROOT": str(Path(temporary).resolve()), "AGENT2_LOG_FOLDER": "phan_tich_agent2",
                   "_to_unicode": str}
            exec(compile(selected, str(source), "exec"), env)
            saved = save_analysis(temporary, "127.0.0.1", {"session_id": "LFI_phien_01"},
                                  "input.json", {}, "report", "instructions", temporary)
            os.utime(saved["fix_path"], (2000000000, 2000000000))
            self.assertEqual(env["_find_agent2_log_for_lab"]("127.0.0.1", "LFI_phien_01"),
                             saved["result_path"])
            self.assertEqual(env["_find_agent3_instructions_for_lab"]("127.0.0.1", "LFI_phien_01"),
                             saved["fix_path"])

    def test_dashboard_selects_multiple_files_and_saves_each_to_its_lab(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "du_lieu_theo_lab"
            name = "agent1_LFI_phien_01_cho_agent2.json"
            paths = []
            for lab in ("127.0.0.1", "other-lab"):
                exports = root / lab / "xuat_cho_agent2"
                exports.mkdir(parents=True)
                (exports / name).write_text(json.dumps({
                    "schema_version": "agent1-to-agent2-1.2",
                    "session": {"session_id": "LFI_phien_01", "profile": "LFI", "lab_name": lab},
                    "observations": [], "test_cases": [],
                }), encoding="utf-8")
                paths.append(str(exports / name))
            st.cache_resource.clear()
            app = AppTest.from_file(str(Path(__file__).resolve().parents[1] / "app.py"))
            app.session_state["source_root"] = temporary
            with patch.dict(os.environ, {"AGENT2_API_KEY": "private-test-key"}), \
                 patch.object(Agent2Runner, "analyze_batch", return_value={"results": [], "batch_id": "test"}), \
                 patch("subprocess.run", return_value=subprocess.CompletedProcess(
                     [], 0, stdout=json.dumps(paths), stderr="")) as picker:
                app.run(timeout=10)
                app.button(key="btn_log").click().run(timeout=10)
                picker.assert_called_once()
                self.assertEqual(picker.call_args.args[0][2], "Select Agent 1 Log Files")
                self.assertEqual(app.session_state["loaded_file_paths"], paths)
                self.assertEqual(len(app.session_state["loaded_batches"]), 2)
                next(b for b in app.button if b.label == "▶ Start Analysis").click().run(timeout=10)
            self.assertEqual(len(app.exception), 0)
            self.assertEqual(len(app.error), 0, [e.value for e in app.error])
            self.assertEqual(len(list((root / "127.0.0.1" / "phan_tich_agent2").glob("agent2_*.json"))), 1)
            self.assertEqual(len(list((root / "other-lab" / "phan_tich_agent2").glob("agent2_*.json"))), 1)
            self.assertEqual(len(app.session_state["analysis_artifacts"]), 2)
            # Cancelling the picker preserves both selection and analysis.
            with patch("subprocess.run", return_value=subprocess.CompletedProcess(
                    [], 0, stdout="[]", stderr="")):
                app.button(key="btn_log").click().run(timeout=10)
            self.assertEqual(app.session_state["loaded_file_paths"], paths)
            self.assertIsNotNone(app.session_state["analysis_result"])
            # Choosing a different file set in the same folder invalidates old results.
            with patch("subprocess.run", return_value=subprocess.CompletedProcess(
                    [], 0, stdout=json.dumps(paths[:1]), stderr="")):
                app.button(key="btn_log").click().run(timeout=10)
            self.assertEqual(app.session_state["loaded_file_paths"], paths[:1])
            self.assertIsNone(app.session_state["analysis_result"])
            self.assertEqual(app.session_state["analysis_artifacts"], [])
            app.button(key="clear_logs").click().run(timeout=10)
            self.assertEqual(len(app.exception), 0)
            self.assertEqual(app.session_state["loaded_batches"], [])
            self.assertIsNone(app.session_state["analysis_result"])
            self.assertEqual(app.session_state["analysis_artifacts"], [])
            st.cache_resource.clear()


if __name__ == "__main__":
    unittest.main()
