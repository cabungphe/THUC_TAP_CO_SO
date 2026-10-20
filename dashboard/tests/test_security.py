import unittest
from pathlib import Path
import uuid

from agent2.security import child_process_env, redact_data, redact_secrets
from agent2.tools import ReadOnlySourceTools


class SecurityTests(unittest.TestCase):
    def test_source_lines_hide_embedded_key_without_changing_finding_location(self):
        root = Path(__file__).resolve().parent
        source = root / f"security_sample_{uuid.uuid4().hex}.js"
        try:
            source.write_text("const API_KEY = 'sk-fictional-secret-123456789';\n"
                              "function login() { return true; }\n", encoding="utf-8")
            tools = ReadOnlySourceTools(root)
            found = tools.search_code("API_KEY", source.name)
            read = tools.read_file(source.name, 1, 3)

            self.assertEqual(found["results"][0]["path"], source.name)
            self.assertEqual(found["results"][0]["line"], 1)
            self.assertEqual(read["path"], source.name)
            self.assertIn("login", read["content"])
            self.assertNotIn("sk-fictional-secret-123456789", str(found))
            self.assertNotIn("sk-fictional-secret-123456789", str(read))
            self.assertIn("[REDACTED]", read["content"])
        finally:
            source.unlink(missing_ok=True)

    def test_redacts_known_values_and_json_fields(self):
        key = "fictional:api/secret+123"
        text = "token=" + key + " URL: https://user:pass@example.test/x"
        self.assertNotIn(key, redact_secrets(text, (key,)))
        self.assertNotIn("fictional%3Aapi%2Fsecret%2B123",
                         redact_secrets("fictional%3Aapi%2Fsecret%2B123", (key,)))
        result = redact_data({"details": [{"api_key": "opaque-value"}],
                              "path": "app.py", "message": "Bearer abc123"})
        self.assertEqual(result["details"][0]["api_key"], "[REDACTED]")
        self.assertEqual(result["path"], "app.py")
        self.assertNotIn("abc123", result["message"])

    def test_child_process_has_no_api_credentials(self):
        env = {"PATH": "bin", "USERPROFILE": "home", "AGENT2_API_KEY": "one",
               "GEMINI_API_KEY": "two", "GITHUB_TOKEN": "three",
               "DATABASE_URL": "postgres://user:pass@localhost/db"}
        child = child_process_env(env)
        self.assertEqual(child, {"PATH": "bin", "USERPROFILE": "home"})


if __name__ == "__main__":
    unittest.main()
