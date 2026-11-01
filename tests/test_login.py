"""python3 -m unittest discover tests"""
import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PASSWORD = "parola-gizli-123"
TOKEN = "taze.jwt.token"


class Api(BaseHTTPRequestHandler):
    def do_POST(self):
        raw = self.rfile.read(int(self.headers["Content-Length"])).decode()
        if self.headers["Content-Type"] == "application/json":
            fields, reply = json.loads(raw), {"data": {"token": TOKEN}}
        else:
            fields = dict(urllib.parse.parse_qsl(raw))
            reply = {"access_token": TOKEN, "token_type": "bearer"}
        if self.path == "/bozuk":
            reply = {"echo": PASSWORD}
        elif self.path == "/bosluklu":
            reply = {"access_token": "abc\nheader=enjekte"}
        elif PASSWORD not in fields.values():
            reply = {"detail": f"yanlış parola {PASSWORD}"}
            self.send_response(401)
            self.end_headers()
            self.wfile.write(json.dumps(reply).encode())
            return
        self.send_response(200)
        self.end_headers()
        self.wfile.write(json.dumps(reply).encode())

    def log_message(self, *args):
        pass


class LoginTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = HTTPServer(("127.0.0.1", 0), Api)
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.base = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def run_login(self, url, **env):
        out = Path(tempfile.mkdtemp()) / "output"
        out.touch()
        full = {**os.environ, "PYTHONUTF8": "1", "GITHUB_OUTPUT": str(out), "LOGIN_URL": url,
                "TEST_USER_EMAIL": "test@ornek.com", "TEST_USER_PASSWORD": PASSWORD, **env}
        proc = subprocess.run([sys.executable, str(ROOT / "scripts" / "login.py")],
                              capture_output=True, text=True, encoding="utf-8", env=full)
        self.assertNotIn(PASSWORD, proc.stdout + proc.stderr)
        return proc, out.read_text(encoding="utf-8")

    def test_form_login_masks_token_before_output(self):
        proc, output = self.run_login(self.base + "/token")
        self.assertEqual(proc.returncode, 0, proc.stdout)
        self.assertEqual(proc.stdout.splitlines()[0], f"::add-mask::{TOKEN}")
        self.assertEqual(output, f"header=Bearer {TOKEN}\n")

    def test_json_login_with_nested_token(self):
        proc, output = self.run_login(self.base + "/login", LOGIN_FORMAT="json", LOGIN_USER_FIELD="email",
                                      LOGIN_TOKEN_FIELD="data.token")
        self.assertEqual(proc.returncode, 0, proc.stdout)
        self.assertEqual(output, f"header=Bearer {TOKEN}\n")

    def test_wrong_password_fails_without_echoing_body(self):
        proc, output = self.run_login(self.base + "/token", TEST_USER_PASSWORD="yanlis")
        self.assertEqual(proc.returncode, 1)
        self.assertIn("HTTP 401", proc.stdout)
        self.assertNotIn("yanlış parola", proc.stdout)
        self.assertEqual(output, "")

    def test_missing_token_field_fails(self):
        proc, output = self.run_login(self.base + "/bozuk")
        self.assertEqual(proc.returncode, 1)
        self.assertEqual(output, "")

    def test_multiline_token_rejected(self):
        proc, output = self.run_login(self.base + "/bosluklu")
        self.assertEqual(proc.returncode, 1)
        self.assertEqual(output, "")

    def test_plain_http_rejected_for_remote_host(self):
        proc, _ = self.run_login("http://staging.ornek.com/token")
        self.assertEqual(proc.returncode, 1)
        self.assertIn("https", proc.stdout)

    def test_missing_credentials_fail(self):
        proc, _ = self.run_login(self.base + "/token", TEST_USER_PASSWORD="")
        self.assertEqual(proc.returncode, 1)


if __name__ == "__main__":
    unittest.main()
