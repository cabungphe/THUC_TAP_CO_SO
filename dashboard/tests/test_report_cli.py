import json
from pathlib import Path
import unittest
from unittest.mock import patch

from agent2.agent3 import MODEL
from agent2.llm import LLMError
from agent2.report import generate_report_cli


def stream(status="SUCCESS", response="# Báo cáo", model=MODEL, exit_code=0, tool=False):
    def events(*args):
        yield "stdout", json.dumps({"event": "init", "init": {"model": model}})
        if tool:
            yield "stdout", json.dumps({"event": "step_update", "step_update": {"step_type": "tool"}})
        yield "stdout", json.dumps({"event": "result", "result": {"status": status, "response": response}})
        yield "exit", exit_code
    return events


class ReportCLITests(unittest.TestCase):
    def test_command_prompt_environment_and_isolated_directory(self):
        with patch("agent2.report.cli_command", return_value=["fake-cli"]), \
             patch("agent2.report.process_lines", side_effect=stream(response="# Báo cáo secret-for-test")) as call, \
             patch.dict("os.environ", {"AGENT2_API_KEY": "secret-for-test"}):
            answer = generate_report_cli({"agent1_inputs": [{"session": {"summary": "secret-for-test"}}]},
                                         secrets=("secret-for-test",))
        command, cwd, env, wire, timeout = call.call_args.args
        self.assertEqual(timeout, 420)
        self.assertEqual(command[command.index("--model") + 1], MODEL)
        self.assertNotIn("--dangerously-skip-permissions", command)
        self.assertNotIn("AGENT2_API_KEY", env)
        self.assertNotIn("secret-for-test", wire + answer)
        self.assertIn("[REDACTED]", answer)
        self.assertIn("Không dùng tool", json.loads(wire)["message"]["content"])
        self.assertEqual(cwd.parent.name, ".report-runs")
        self.assertFalse(cwd.exists())

    def test_missing_wrong_model_failure_or_tool_request_never_produces_report(self):
        cases = [stream(model="wrong-model"), stream(status="ERROR"),
                 stream(exit_code=1), stream(tool=True), stream(response="")]
        def missing_init(*args):
            yield "stdout", json.dumps({"event": "result", "result": {"status": "SUCCESS", "response": "# Fake"}})
            yield "exit", 0
        cases.append(missing_init)
        for index, events in enumerate(cases):
            with self.subTest(case=index), patch("agent2.report.cli_command", return_value=["fake-cli"]), \
                 patch("agent2.report.process_lines", side_effect=events):
                with self.assertRaises(LLMError):
                    generate_report_cli({})

    def test_timeout_has_a_short_actionable_error(self):
        with patch("agent2.report.cli_command", return_value=["fake-cli"]), \
             patch("agent2.report.process_lines", side_effect=TimeoutError("timeout private-data")):
            with self.assertRaises(LLMError) as caught:
                generate_report_cli({})
        self.assertNotIn("private-data", str(caught.exception))
        self.assertIn("7 phút", str(caught.exception))
