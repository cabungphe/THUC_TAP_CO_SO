from pathlib import Path
import os
import tempfile
import unittest
from unittest.mock import patch

import streamlit as st
from streamlit.testing.v1 import AppTest

from agent2.build import BuildJob, BuildManager


class DashboardBuildTests(unittest.TestCase):
    def test_switching_source_sends_the_new_path_and_hides_old_build(self):
        with tempfile.TemporaryDirectory(prefix="dashboard-source-") as temporary:
            roots = [Path(temporary) / drive / 'lazyweb' for drive in ('C', 'D', 'E')]
            for root in roots:
                root.mkdir(parents=True)
            jobs = {}
            started = []

            def start(_manager, path):
                started.append(path)
                job = BuildJob(Path(path), ['docker', 'compose'])
                job.state = 'succeeded'
                job.events = [f'[12:30:00] Build context (web): {path}']
                job.done.set()
                jobs[path] = job
                return job

            st.cache_resource.clear()
            app_path = Path(__file__).resolve().parents[1] / 'app.py'
            with patch.object(BuildManager, 'start', start), \
                 patch.object(BuildManager, 'latest', lambda _manager, path: jobs.get(path)):
                app = AppTest.from_file(str(app_path)).run(timeout=10)
                for root in roots:
                    source_input = next(t for t in app.text_input if t.label == 'Source Code Path')
                    source_input.set_value(str(root)).run(timeout=10)
                    self.assertFalse(any('Build & Run thành công' in s.value for s in app.success))
                    self.assertTrue(any(str(root) in c.value for c in app.caption))
                    next(b for b in app.button if b.label == '🔨 Build & Run').click().run(timeout=10)
                    self.assertEqual(len(app.exception), 0)
                    self.assertEqual(started[-1], str(root))
                    self.assertTrue(any('Build & Run thành công' in s.value for s in app.success))
            self.assertEqual(started, [str(root) for root in roots])
            st.cache_resource.clear()

    def test_report_json_and_handoff_mask_api_key(self):
        secret = "private-test-key-123"
        st.cache_resource.clear()
        app_path = Path(__file__).resolve().parents[1] / "app.py"
        with patch.dict(os.environ, {"AGENT2_API_KEY": secret}):
            app = AppTest.from_file(str(app_path))
            app.session_state["analysis_result"] = {
                "results": [{"analysis_status": "confirmed", "root_cause": {"summary": secret}}],
                "api_key": secret,
            }
            app.session_state["user_report"] = "Finding includes " + secret
            app.session_state["agent3_payload"] = "Fix key=" + secret
            app.session_state["agent3_payload_editor"] = "Previously edited key=" + secret
            app.run(timeout=10)
        self.assertEqual(len(app.exception), 0)
        self.assertNotIn(secret, "\n".join(m.value for m in app.markdown))
        self.assertNotIn(secret, str([j.value for j in app.json]))
        self.assertNotIn(secret, str([t.value for t in app.text_area]))
        st.cache_resource.clear()

    def test_build_button_starts_job_and_shows_scrolling_escaped_progress(self):
        with tempfile.TemporaryDirectory(prefix="dashboard-build-") as temporary:
            root = Path(temporary)
            (root / "compose.yaml").write_text("services: {}\n", encoding="utf-8")
            job = BuildJob(root, ["docker", "compose"])
            job.state = "succeeded"
            job.events = ["[12:30:00] Docker Compose đã chạy <script>alert(1)</script>"]
            job.done.set()
            started = []

            def start(_manager, path):
                started.append(path)
                return job

            def latest(_manager, _path):
                return job if started else None

            st.cache_resource.clear()
            app_path = Path(__file__).resolve().parents[1] / "app.py"
            with patch.object(BuildManager, "start", start), patch.object(BuildManager, "latest", latest):
                app = AppTest.from_file(str(app_path))
                app.session_state["source_root"] = str(root)
                app.run(timeout=10)
                button = next(b for b in app.button if b.label == "🔨 Build & Run")
                self.assertFalse(button.disabled)
                button.click().run(timeout=10)

            self.assertEqual(len(app.exception), 0)
            self.assertEqual(started, [str(root)])
            self.assertTrue(any("Build & Run thành công" in item.value for item in app.success))
            panels = [m.value for m in app.markdown if m.value.startswith("<div class='job-log-scroll'>")]
            self.assertTrue(panels)
            self.assertIn("<table>", panels[0])
            self.assertIn("&lt;script&gt;", panels[0])
            self.assertNotIn("<script>", panels[0])
            st.cache_resource.clear()


if __name__ == "__main__":
    unittest.main()
