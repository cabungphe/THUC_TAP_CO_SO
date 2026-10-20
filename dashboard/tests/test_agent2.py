from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from agent2.agent import Agent2Runner
from agent2.config import Agent2Config
from agent2.schemas import Finding, FindingBatch, SchemaError
from agent2.tools import ReadOnlySourceTools, ToolError


HERE = Path(__file__).resolve().parent
FIXTURE = HERE / "fixture_app"


class ScriptedLLM:
    """Deterministic fake model used to verify the agent/tool loop offline."""

    def __init__(self):
        self.turn = 0

    def complete(self, messages):
        self.turn += 1
        if self.turn == 1:
            return json.dumps(
                {
                    "action": "search_code",
                    "args": {"query": "username", "path": ".", "max_results": 10},
                    "reason": "Locate the parameter flow."
                }
            )
        if self.turn == 2:
            return json.dumps(
                {
                    "action": "read_file",
                    "args": {"path": "routes/auth.js", "start_line": 1, "end_line": 20},
                    "reason": "Read the relevant handler."
                }
            )
        return json.dumps(
            {
                "action": "finish",
                "result": {
                    "analysis_status": "confirmed",
                    "code_locations": [
                        {"path": "routes/auth.js", "start_line": 1, "end_line": 4, "role": "vulnerable_handler"}
                    ],
                    "root_cause": {
                        "summary": "User-controlled username is concatenated into an SQL query before db.query executes it.",
                        "source": "req.body.username",
                        "sink": "db.query",
                        "data_flow": ["req.body.username", "string concatenation", "db.query"]
                    },
                    "remediation": {
                        "recommended_strategy": "Replace string concatenation with a parameterized query.",
                        "rationale": "Separate SQL code from user-controlled data.",
                        "constraints": ["Preserve login behavior"],
                        "alternatives": []
                    },
                    "confidence": "high",
                    "notes": []
                }
            }
        )


class UnreadEvidenceLLM:
    def __init__(self):
        self.turn = 0

    def complete(self, messages):
        self.turn += 1
        if self.turn == 1:
            return json.dumps({
                "action": "read_file",
                "args": {"path": "routes/auth.js", "start_line": 1, "end_line": 8},
                "reason": "Read actual handler."
            })
        if self.turn == 2:
            return json.dumps({
                "action": "finish",
                "result": {
                    "analysis_status": "confirmed",
                    "code_locations": [{"path": "routes/not-read.js", "start_line": 1, "end_line": 2, "role": "sink"}],
                    "root_cause": {"summary": "Unsupported claim", "source": "x", "sink": "y", "data_flow": []},
                    "remediation": {"recommended_strategy": "Do something", "rationale": "", "constraints": [], "alternatives": []},
                    "confidence": "high"
                }
            })
        return json.dumps({
            "action": "finish",
            "result": {
                "analysis_status": "unresolved",
                "code_locations": [],
                "root_cause": {},
                "remediation": {},
                "confidence": "low",
                "reason": "Could not ground every claimed code location."
            }
        })


class Agent2Tests(unittest.TestCase):
    def setUp(self):
        self.config = Agent2Config(max_steps=8, max_tool_calls=6)
        self.tools = ReadOnlySourceTools(FIXTURE, self.config)

    def test_search_and_read(self):
        result = self.tools.search_code("username")
        self.assertGreaterEqual(result["count"], 1)
        content = self.tools.read_file("routes/auth.js", 1, 8)["content"]
        self.assertIn("db.query", content)

    def test_blocks_path_escape(self):
        with self.assertRaises(ToolError):
            self.tools.read_file("../../etc/passwd")

    def test_blocks_secret_file(self):
        with self.assertRaises(ToolError):
            self.tools.read_file("config/.env")

    def test_batch_schema_rejects_out_of_scope_vuln(self):
        with self.assertRaises(SchemaError):
            FindingBatch.from_dict(
                {
                    "batch_id": "B",
                    "source_revision": "R",
                    "findings": [
                        {
                            "finding_id": "F",
                            "vulnerability_type": "ssrf",
                            "endpoint": "/",
                            "method": "GET"
                        }
                    ]
                }
            )

    def test_confirmed_requires_read_evidence(self):
        finding = Finding.from_dict({
            "finding_id": "F-002",
            "vulnerability_type": "sqli",
            "endpoint": "/login",
            "method": "POST"
        })
        runner = Agent2Runner(UnreadEvidenceLLM(), self.tools, self.config)
        result = runner.analyze_finding(finding, "fixture-r1")
        self.assertEqual(result["analysis_status"], "unresolved")

    def test_isolated_finding_run(self):
        finding = Finding.from_dict(
            {
                "finding_id": "F-001",
                "vulnerability_type": "sqli",
                "endpoint": "/login",
                "method": "POST",
                "parameter": {"name": "username", "location": "body"},
                "evidence": {"summary": "finalized"}
            }
        )
        runner = Agent2Runner(ScriptedLLM(), self.tools, self.config)
        result = runner.analyze_finding(finding, "fixture-r1")
        self.assertEqual(result["analysis_status"], "confirmed")
        self.assertEqual(result["root_cause"]["sink"], "db.query")
        self.assertEqual(result["metrics"]["search_calls"], 1)
        self.assertEqual(result["metrics"]["read_calls"], 1)


if __name__ == "__main__":
    unittest.main()
