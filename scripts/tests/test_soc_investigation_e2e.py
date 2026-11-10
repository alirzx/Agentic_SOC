"""Offline, standard-library regression checks for Server 55 SOC E2E script."""
from __future__ import annotations

import contextlib
import importlib.util
import io
import pathlib
import unittest
from unittest import mock

SCRIPT = pathlib.Path(__file__).resolve().parents[1] / "soc_investigation_e2e.py"
spec = importlib.util.spec_from_file_location("soc_investigation_e2e", SCRIPT)
assert spec is not None and spec.loader is not None
app = importlib.util.module_from_spec(spec)
spec.loader.exec_module(app)

TENANT = "00000000-0000-0000-0000-000000000001"
ALERT = "00000000-0000-0000-0000-000000000072"


class Server55E2ETests(unittest.TestCase):
    def test_readonly_tty_avoids_seek_error(self):
        with mock.patch("builtins.open", mock.mock_open(read_data="analyst@example.test\n")) as opener:
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(app.ask("User: "), "analyst@example.test")
        opener.assert_called_once_with("/dev/tty", "r", encoding="utf-8")

    def test_invalid_or_noncanonical_uuid_rejected(self):
        for value in ("wrong", "ABCDEF00-0000-0000-0000-000000000001"):
            with self.subTest(value=value), self.assertRaises(SystemExit):
                app.canonical_uuid(value)
        self.assertEqual(app.canonical_uuid(TENANT), TENANT)

    def test_test_marker_requires_explicit_word_or_tag(self):
        self.assertFalse(app.is_test_alert({"title": "Latest security alert", "tags": []}))
        self.assertTrue(app.is_test_alert({"title": "Synthetic password spray", "tags": []}))
        self.assertTrue(app.is_test_alert({"title": "Auth event", "tags": ["test"]}))

    def test_default_mode_never_starts_investigation(self):
        def api(method, path, payload=None, token=None):
            if path.startswith("/api/v1/alerts?search="):
                return {"items": [{"id": ALERT, "title": "Synthetic alert"}]}
            raise AssertionError(f"Unexpected API request: {method} {path}")
        with (
            mock.patch.dict("os.environ", {"AISOC_PRIVACY_TEST_TENANT_ID": TENANT}),
            mock.patch.object(app, "authenticate", return_value=("temporary-jwt", TENANT)),
            mock.patch.object(app, "api", side_effect=api),
            contextlib.redirect_stdout(io.StringIO()) as output,
        ):
            app.main([])
        self.assertIn("PASS: Authentication", output.getvalue())

    def test_run_refuses_non_test_alert_before_post(self):
        def api(method, path, payload=None, token=None):
            self.assertEqual(method, "GET")
            return {"tenant_id": TENANT, "title": "Production breach"}
        with (
            mock.patch.dict("os.environ", {"AISOC_PRIVACY_TEST_TENANT_ID": TENANT}),
            mock.patch.object(app, "authenticate", return_value=("jwt", TENANT)),
            mock.patch.object(app, "api", side_effect=api),
            self.assertRaises(SystemExit),
        ):
            app.main(["--run", "--alert-id", ALERT])

    def test_run_requires_confirmation_and_polls(self):
        calls = []
        def api(method, path, payload=None, token=None):
            calls.append((method, path))
            if method == "GET" and path.endswith(ALERT):
                return {"tenant_id": TENANT, "title": "Synthetic alert"}
            if method == "POST":
                return {"id": "test-run_123", "status": "running"}
            if path.endswith("test-run_123"):
                return {"status": "completed", "findings": "synthetic only", "recommendations": ["review"]}
            raise AssertionError(path)
        with (
            mock.patch.dict("os.environ", {"AISOC_PRIVACY_TEST_TENANT_ID": TENANT}),
            mock.patch.object(app, "authenticate", return_value=("jwt", TENANT)),
            mock.patch.object(app, "api", side_effect=api),
            mock.patch.object(app, "ask", return_value="RUN"),
            contextlib.redirect_stdout(io.StringIO()) as output,
        ):
            app.main(["--run", "--alert-id", ALERT])
        self.assertEqual(sum(m == "POST" for m, _ in calls), 1)
        self.assertIn("PASS: Investigation completed", output.getvalue())
        self.assertNotIn("synthetic only", output.getvalue())

    def test_resume_never_posts(self):
        with (
            mock.patch.dict("os.environ", {"AISOC_PRIVACY_TEST_TENANT_ID": TENANT}),
            mock.patch.object(app, "authenticate", return_value=("jwt", TENANT)),
            mock.patch.object(app, "api", return_value={"status": "completed"}) as mocked,
            contextlib.redirect_stdout(io.StringIO()),
        ):
            app.main(["--resume-run-id", "previous-run_456"])
        mocked.assert_called_once_with("GET", "/api/v1/agents/investigations/previous-run_456", token="jwt")


if __name__ == "__main__":
    unittest.main()
