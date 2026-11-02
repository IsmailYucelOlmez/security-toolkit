"""python3 -m unittest discover tests"""
import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "staging_request.py"


class Handler(BaseHTTPRequestHandler):
    calls = []

    def respond(self):
        Handler.calls.append((self.command, self.path, self.headers.get("Authorization")))
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "https://baska.example.test/")
            self.end_headers()
            return
        body = json.dumps({"id": 1, "email": "gizli-deger@example.test"}).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = do_PUT = respond

    def log_message(self, *args):
        pass


class StagingRequestTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.base = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def setUp(self):
        Handler.calls.clear()
        self.dir = Path(tempfile.mkdtemp())
        (self.dir / "tokens.env").write_text("USER_A_TOKEN=gizli-a\n", encoding="utf-8")

    def run_cli(self, *args):
        return subprocess.run([sys.executable, str(SCRIPT), *args], capture_output=True, text=True, encoding="utf-8",
                              env={**os.environ, "STAGING_STATE": str(self.dir / "state.json"),
                                   "STAGING_TOKENS": str(self.dir / "tokens.env")})

    def init(self):
        proc = self.run_cli("init", "--base", self.base)
        self.assertEqual(proc.returncode, 0, proc.stdout)

    def test_request_prints_status_and_field_names_only(self):
        self.init()
        proc = self.run_cli("request", "--user", "USER_A_TOKEN", "GET", "/orders/1")
        self.assertEqual(proc.returncode, 0, proc.stdout)
        self.assertIn("200", proc.stdout)
        self.assertIn("email", proc.stdout)
        self.assertNotIn("gizli", proc.stdout)
        self.assertEqual(Handler.calls, [("GET", "/orders/1", "Bearer gizli-a")])

    def test_requires_init(self):
        proc = self.run_cli("request", "--user", "USER_A_TOKEN", "GET", "/a")
        self.assertEqual(proc.returncode, 3)
        self.assertEqual(Handler.calls, [])

    def test_write_requires_flag(self):
        self.init()
        self.assertEqual(self.run_cli("request", "--user", "USER_A_TOKEN", "PUT", "/a").returncode, 3)
        self.assertEqual(Handler.calls, [])
        proc = self.run_cli("request", "--user", "USER_A_TOKEN", "PUT", "/a", "--allow-write", "--json", "{}")
        self.assertEqual(proc.returncode, 0, proc.stdout)

    def test_other_hosts_are_refused(self):
        self.init()
        for path in ("https://baska.example.test/a", "//baska.example.test/a"):
            self.assertEqual(self.run_cli("request", "--user", "USER_A_TOKEN", "GET", path).returncode, 3)
        self.assertEqual(Handler.calls, [])

    def test_request_limit(self):
        self.init()
        state = self.dir / "state.json"
        state.write_text(json.dumps({"base": self.base, "count": 50}), encoding="utf-8")
        proc = self.run_cli("request", "--user", "USER_A_TOKEN", "GET", "/a")
        self.assertEqual(proc.returncode, 3)
        self.assertIn("sınırı", proc.stdout)
        self.assertEqual(Handler.calls, [])

    def test_redirect_is_not_followed(self):
        self.init()
        proc = self.run_cli("request", "--user", "USER_A_TOKEN", "GET", "/redirect")
        self.assertEqual(proc.returncode, 0, proc.stdout)
        self.assertIn("302", proc.stdout)
        self.assertEqual(len(Handler.calls), 1)

    def test_production_like_host_needs_confirmation(self):
        self.assertEqual(self.run_cli("init", "--base", "https://api.ornek.com").returncode, 3)
        self.assertEqual(self.run_cli("init", "--base", "https://staging-api.ornek.com").returncode, 0)
        self.assertEqual(self.run_cli("init", "--base", "https://api.ornek.com", "--confirm-not-production").returncode, 0)

    def test_plain_http_only_for_localhost(self):
        self.assertEqual(self.run_cli("init", "--base", "http://staging.ornek.com").returncode, 3)


if __name__ == "__main__":
    unittest.main()
