from copy import deepcopy
import unittest

from agent2.report import agent1_report_input, REPORT_PROMPT


def log():
    return {
        "schema_version": "agent1-to-agent2-1.3",
        "session": {"session_id": "SQLi-demo", "profile": "SQLi", "final_verdict": "vulnerable"},
        "observations": [{"step": 1, "request_line": "POST /login HTTP/1.1",
                          "request_content": "POST /login HTTP/1.1\r\nCookie: sid=private-session\r\n\r\nemail=observed-payload",
                          "response_status": "HTTP/1.1 200 OK", "response_key_text": "observed-response",
                          "verdict": "vulnerable", "uncertainties": ["Synthetic offline fixture."]}],
        "test_cases": [{"testcase_id": "TC-next", "generated_at_step": 1, "status": "pending",
                        "payload_detail": "proposed-payload", "expected_signal": "expected-response"}],
    }


class Agent1ReportTests(unittest.TestCase):
    def test_observed_requests_and_proposals_are_distinct_and_input_unchanged(self):
        data = log()
        original = deepcopy(data)
        evidence = agent1_report_input(data, "chosen.json")
        self.assertEqual(evidence["session"]["id"], "SQLi-demo")
        observation = evidence["observations"][0]
        self.assertIn("observed-payload", observation["request_content"])
        self.assertNotIn("private-session", observation["request_content"])
        self.assertEqual(observation["response_key_text"], "observed-response")
        self.assertEqual(observation["evidence_kind"], "recorded_observation")
        proposal = evidence["proposed_testcases"][0]
        self.assertEqual(proposal["payload_detail"], "proposed-payload")
        self.assertEqual(proposal["evidence_kind"], "proposed_testcase")
        self.assertEqual(proposal["generated_at_step"], 1)
        self.assertEqual(proposal["status"], "pending")
        self.assertEqual(data, original)
        self.assertIn("không chứng minh đã thực thi", REPORT_PROMPT)

    def test_legacy_raw_session_and_missing_request_are_explicit(self):
        exported = log()
        raw = dict(exported["session"], observations=exported["observations"], test_cases=[])
        raw["observations"][0].pop("request_content")
        evidence = agent1_report_input(raw, "raw.json")
        self.assertEqual(evidence["availability"], "loaded")
        self.assertFalse(evidence["observations"][0]["request_recorded"])
        self.assertEqual(evidence["observations"][0]["response_key_text"], "observed-response")

    def test_limits_retain_vulnerable_observation_and_mark_omissions(self):
        data = log()
        data["observations"] = [dict(data["observations"][0], step=i, verdict="safe") for i in range(30)]
        data["observations"][12]["verdict"] = "vulnerable"
        data["test_cases"] *= 30
        data["test_cases"][0] = dict(data["test_cases"][0], payload_detail="x" * 9000)
        evidence = agent1_report_input(data, "large.json")
        self.assertEqual(evidence["omitted_observation_count"], 6)
        self.assertEqual(evidence["omitted_proposed_testcase_count"], 6)
        self.assertTrue(any(obs["step"] == 12 for obs in evidence["observations"]))
        self.assertIn("truncated_fields", evidence)

    def test_fingerprint_changes_and_invalid_or_direct_batches_are_not_agent1_evidence(self):
        data = log()
        first = agent1_report_input(data, "chosen.json")["content_sha256"]
        data["observations"][0]["response_key_text"] = "changed response"
        self.assertNotEqual(first, agent1_report_input(data, "chosen.json")["content_sha256"])
        self.assertEqual(agent1_report_input({"findings": []}, "batch.json")["availability"], "not_an_agent1_log")
        self.assertEqual(agent1_report_input([], "invalid.json")["availability"], "not_an_agent1_log")
        data["observations"] = None
        self.assertEqual(agent1_report_input(data, "invalid.json")["availability"], "invalid_agent1_log")
