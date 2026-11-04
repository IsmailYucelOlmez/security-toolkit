"""python3 -m unittest discover tests"""
import base64
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = str(ROOT / "scripts" / "gitleaks_redact.py")


def jwt(payload: dict) -> str:
    enc = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()
    return f"{enc({'alg': 'HS256', 'typ': 'JWT'})}.{enc(payload)}.c2lnbmF0dXJlLWJ5dGVz"


ANON = jwt({"iss": "supabase", "ref": "abcdefghijklmnopqrst", "role": "anon"})
SERVICE = jwt({"iss": "supabase", "ref": "abcdefghijklmnopqrst", "role": "service_role"})
OTHER = jwt({"iss": "https://auth.example.com", "role": "anon"})


class GitleaksRedactTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def redact(self, findings):
        raw, out = self.tmp / "raw.json", self.tmp / "gitleaks.json"
        raw.write_text(json.dumps(findings))
        proc = subprocess.run([sys.executable, SCRIPT, raw, out], capture_output=True, text=True, encoding="utf-8")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        return out.read_text(encoding="utf-8"), proc

    def leak(self, secret):
        return {"RuleID": "jwt", "Secret": secret, "Match": f"key = '{secret}'", "Line": f"const key = '{secret}';"}

    def test_role_is_kept_and_secret_never_written(self):
        text, proc = self.redact([self.leak(ANON), self.leak(SERVICE), self.leak(OTHER), self.leak("ghp_abc123")])
        for secret in (ANON, SERVICE, OTHER, "ghp_abc123"):
            self.assertNotIn(secret, text)
            self.assertNotIn(secret, proc.stdout + proc.stderr)
        roles = [r.get("SupabaseRole") for r in json.loads(text)]
        self.assertEqual(roles, ["anon", "service_role", None, None])
        self.assertTrue(all(r["Secret"] == "REDACTED" for r in json.loads(text)))

    def test_malformed_jwt_is_not_classified(self):
        text, _ = self.redact([self.leak("eyJhbGciOi.eyJ%%%.sig")])
        self.assertNotIn("SupabaseRole", json.loads(text)[0])

    def test_non_list_report_fails(self):
        raw, out = self.tmp / "raw.json", self.tmp / "gitleaks.json"
        raw.write_text("{}")
        proc = subprocess.run([sys.executable, SCRIPT, raw, out], capture_output=True, text=True)
        self.assertEqual(proc.returncode, 1)
        self.assertFalse(out.exists())


if __name__ == "__main__":
    unittest.main()
