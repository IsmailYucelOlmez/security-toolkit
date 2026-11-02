"""python3 -m unittest discover tests"""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
JUNIT = """<?xml version="1.0" encoding="utf-8"?>
<testsuites errors="0" failures="2" skipped="0" tests="3" time="1.0">
  <testsuite name="schemathesis" errors="0" failures="2" skipped="0" tests="3" time="1.0">
    <testcase name="GET /orders/{id}" time="0.1">
      <failure type="failure" message="ST101, ST204">sunucu hatası</failure>
      <failure type="failure" message="ST402">idor</failure>
    </testcase>
    <testcase name="GET /me" time="0.1">
      <failure type="failure" message="ST401">kimliksiz</failure>
    </testcase>
    <testcase name="POST /notes" time="0.1"/>
  </testsuite>
</testsuites>
"""
ONLY_OTHER = JUNIT.replace('message="ST402"', 'message="ST204"').replace('message="ST401"', 'message="ST101"')


def run(script, *args, **env):
    return subprocess.run([sys.executable, str(SCRIPTS / script), *map(str, args)], capture_output=True, text=True,
                          encoding="utf-8", env={**os.environ, "PYTHONUTF8": "1", **env})


class ReportTest(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())

    def report(self, junit, rc=1, *flags):
        (self.dir / "junit.xml").write_text(junit, encoding="utf-8")
        return run("schemathesis_report.py", self.dir, rc, *flags)

    def test_authz_failures_fail_and_are_listed(self):
        proc = self.report(JUNIT, 1, "--peers")
        self.assertEqual(proc.returncode, 1)
        self.assertIn("`GET /orders/{id}` — ST402", proc.stdout)
        self.assertIn("`GET /me` — ST401", proc.stdout)
        self.assertIn("İşlem sayısı: **3**", proc.stdout)

    def test_other_failures_are_report_only(self):
        proc = self.report(ONLY_OTHER, 1, "--peers")
        self.assertEqual(proc.returncode, 0)
        self.assertNotIn("Yetki hataları", proc.stdout)

    def test_scan_that_could_not_run_fails(self):
        proc = run("schemathesis_report.py", self.dir, 2)
        self.assertEqual(proc.returncode, 1)
        self.assertIn("Tarama çalışamadı", proc.stdout)

    def test_without_peers_says_idor_did_not_run(self):
        proc = self.report(ONLY_OTHER, 1)
        self.assertEqual(proc.returncode, 0)
        self.assertIn("IDOR kontrolü çalışmadı", proc.stdout)


class ReportGateTest(ReportTest):
    def test_no_report_fails_even_with_exit_zero(self):
        proc = run("schemathesis_report.py", self.dir, 0, "--peers")
        self.assertEqual(proc.returncode, 1)
        self.assertIn("Tarama çalışamadı", proc.stdout)

    def test_zero_operations_fails_even_with_exit_zero(self):
        empty = '<testsuites tests="0"><testsuite name="s" tests="0" failures="0" errors="0"/></testsuites>'
        proc = self.report(empty, 0, "--peers")
        self.assertEqual(proc.returncode, 1)

    def test_corrupt_report_fails(self):
        proc = self.report("<testsuites", 0, "--peers")
        self.assertEqual(proc.returncode, 1)

    def test_undeclared_security_is_listed(self):
        schema = self.dir / "openapi.json"
        schema.write_text(json.dumps({"paths": {
            "/acik": {"get": {}},
            "/kapali": {"get": {"security": [{"b": []}]}, "parameters": []},
        }}), encoding="utf-8")
        proc = self.report(ONLY_OTHER, 1, "--peers", "--openapi", schema.as_uri())
        self.assertEqual(proc.returncode, 0)
        self.assertIn("`GET /acik`", proc.stdout)
        self.assertNotIn("`GET /kapali`", proc.stdout)


class MobsfSummaryTest(unittest.TestCase):
    def test_flutter_false_positives_are_dropped_and_counted(self):
        card = Path(tempfile.mkdtemp()) / "card.json"
        card.write_text(json.dumps({"security_score": 50, "high": [
            {"title": "Stack canary eksik", "description": "libapp.so", "section": "binary"},
            {"title": "Uygulama yedeklenebilir", "section": "manifest"},
            {"title": "libapp.so gömülü anahtar içeriyor", "section": "secrets"},
        ], "warning": [{"title": "RELRO", "description": "libapp.so"}]}), encoding="utf-8")
        proc = run("mobsf_summary.py", card)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("yüksek: **2**", proc.stdout)
        self.assertIn("uyarı: **0**", proc.stdout)
        self.assertIn("2 `libapp.so`", proc.stdout)
        self.assertIn("gömülü anahtar", proc.stdout)
        self.assertNotIn("Stack canary", proc.stdout)


class ConfigTest(unittest.TestCase):
    def test_writes_two_peers(self):
        out = Path(tempfile.mkdtemp())
        proc = run("schemathesis_config.py", out, AUTH_HEADER_A="Bearer aaa", AUTH_HEADER_B="Bearer bbb")
        self.assertEqual(proc.returncode, 0, proc.stdout)
        auth = json.loads((out / "auth.json").read_text(encoding="utf-8"))
        self.assertEqual([a["fixedHeaders"][0]["value"] for a in auth["auth"]], ["Bearer aaa", "Bearer bbb"])
        self.assertIn('peers = ["user_a", "user_b"]', (out / "schemathesis.toml").read_text(encoding="utf-8"))
        self.assertNotIn("aaa", proc.stdout + proc.stderr)

    def test_missing_user_fails(self):
        proc = run("schemathesis_config.py", tempfile.mkdtemp(), AUTH_HEADER_A="Bearer aaa", AUTH_HEADER_B="")
        self.assertEqual(proc.returncode, 1)


class RedactTest(unittest.TestCase):
    ENV = {"AUTH_HEADER_A": "Bearer gizli-a", "AUTH_HEADER_B": "Bearer gizli-b"}

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        (self.dir / "alt").mkdir()
        self.dirty = self.dir / "alt" / "rapor.har"
        self.dirty.write_text("x gizli-a y gizli-b z", encoding="utf-8")
        self.clean = self.dir / "temiz.txt"
        self.clean.write_text("temiz", encoding="utf-8")

    def test_check_fails_without_touching_or_printing_tokens(self):
        proc = run("redact_tokens.py", self.dir, "--check", **self.ENV)
        self.assertEqual(proc.returncode, 1)
        self.assertIn("rapor.har", proc.stdout)
        self.assertNotIn("gizli", proc.stdout.replace(str(self.dir), ""))
        self.assertIn("gizli-a", self.dirty.read_text(encoding="utf-8"))

    def test_default_masks_tokens(self):
        proc = run("redact_tokens.py", self.dir, **self.ENV)
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(self.dirty.read_text(encoding="utf-8"), "x [Filtered] y [Filtered] z")
        self.assertEqual(self.clean.read_text(encoding="utf-8"), "temiz")

    def test_clean_directory_passes_check(self):
        self.dirty.unlink()
        self.assertEqual(run("redact_tokens.py", self.dir, "--check", **self.ENV).returncode, 0)

    def test_no_tokens_configured_passes(self):
        proc = run("redact_tokens.py", self.dir, "--check", AUTH_HEADER_A="", AUTH_HEADER_B="")
        self.assertEqual(proc.returncode, 0)


if __name__ == "__main__":
    unittest.main()
