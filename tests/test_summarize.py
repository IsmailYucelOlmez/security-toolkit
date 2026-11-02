"""python3 -m unittest discover tests"""
import datetime as dt
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIX = ROOT / "tests" / "fixtures"


def run(fail_on="high"):
    tmp = Path(tempfile.mkdtemp())
    reports, target = tmp / "reports", tmp / "target"
    shutil.copytree(FIX, reports)
    target.mkdir()
    shutil.move(str(reports / "security-ignore.yml"), target / ".security-ignore.yml")
    proc = subprocess.run([sys.executable, str(ROOT / "scripts" / "summarize.py"), "--reports", str(reports),
                           "--target", str(target), "--fail-on", fail_on], capture_output=True, text=True, encoding="utf-8")
    return proc, json.loads((reports / "findings.json").read_text()), reports


class SummarizeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.proc, cls.data, cls.reports = run()

    def by(self, **kw):
        return [f for f in self.data["findings"] if all(f.get(k) == v for k, v in kw.items())]

    def test_exit_code_reflects_threshold(self):
        self.assertEqual(self.proc.returncode, 1, self.proc.stderr)
        self.assertEqual(run("none")[0].returncode, 0)

    def test_osv_and_pip_audit_deduplicated(self):
        osv_requests = self.by(tool="osv", package="requests")
        self.assertEqual(len(osv_requests), 1)
        self.assertIn("pip-audit", osv_requests[0]["also_found_by"])
        self.assertEqual(osv_requests[0]["severity"], "critical")  # 9.8 CVSS
        # osv'de olmayan açık pip-audit kaydı olarak kalır
        self.assertEqual(len(self.by(tool="pip-audit", package="requests")), 1)

    def test_grouped_fix_version(self):
        self.assertEqual(self.by(tool="osv", package="requests")[0]["fixed_version"], "2.31.0")

    def test_ignores(self):
        ignored_ids = {f["rule_id"] for f in self.data["ignored"]}
        self.assertIn("B403", ignored_ids)
        self.assertFalse(self.by(package="pyyaml"), "CVE-2020-14343 bastırılmalıydı")
        self.assertTrue(self.by(rule_id="rules.semgrep.fastapi-debug-enabled"), "süresi dolan bastırma uygulanmamalı")

    def test_low_confidence_downgrade(self):
        self.assertEqual(self.by(rule_id="B602")[0]["severity"], "medium")

    def test_all_tools_parsed(self):
        self.assertEqual({f["tool"] for f in self.data["findings"]},
                         {"gitleaks", "osv", "pip-audit", "bandit", "semgrep", "trivy", "dotnet"})

    def test_sarif_shape(self):
        sarif = json.loads((self.reports / "findings.sarif").read_text())
        self.assertEqual(sarif["version"], "2.1.0")
        for r in sarif["runs"]:
            for rule in r["tool"]["driver"]["rules"]:
                self.assertIn("security-severity", rule["properties"])


class UnresolvedOsvTest(unittest.TestCase):
    """OSV `>=0.0.9` için 0.0.9'u, pip-audit gerçekten kurulacak sürümü görür."""

    def summarize(self, osv_version="0.0.9", audit=None):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        (tmp / "osv.json").write_text(json.dumps({"results": [{
            "source": {"path": "requirements.txt"},
            "packages": [{"package": {"name": "python-multipart", "version": osv_version},
                          "vulnerabilities": [{"id": "GHSA-a", "aliases": ["CVE-1"], "database_specific": {"severity": "HIGH"}}]}],
        }]}))
        if audit is not None:
            (tmp / "pip-audit-0.json").write_text(json.dumps({"dependencies": audit}))
            (tmp / "pip-audit-0.source").write_text("requirements.txt")
        proc = subprocess.run([sys.executable, str(ROOT / "scripts" / "summarize.py"), "--reports", str(tmp),
                               "--target", str(tmp)], capture_output=True, text=True, encoding="utf-8",
                              env={**os.environ, "PYTHONUTF8": "1"})
        return proc, json.loads((tmp / "findings.json").read_text(encoding="utf-8"))

    def test_other_resolved_version_drops_finding(self):
        proc, data = self.summarize(audit=[{"name": "python_multipart", "version": "0.0.33", "vulns": []}])
        self.assertEqual(proc.returncode, 0, proc.stdout)
        self.assertEqual(data["findings"], [])
        self.assertEqual(len(data["unresolved_osv"]), 1)
        self.assertIn("1 OSV bulgusu atlandı", proc.stdout)

    def test_pinned_version_keeps_finding(self):
        proc, data = self.summarize(audit=[{"name": "python-multipart", "version": "0.0.9", "vulns": []}])
        self.assertEqual(proc.returncode, 1)
        self.assertEqual(data["unresolved_osv"], [])
        self.assertEqual(data["findings"][0]["severity"], "high")

    def test_without_pip_audit_keeps_finding(self):
        proc, data = self.summarize()
        self.assertEqual(proc.returncode, 1)
        self.assertEqual(len(data["findings"]), 1)

    def test_vulnerability_in_resolved_version_keeps_osv_severity(self):
        vuln = {"id": "PYSEC-1", "aliases": ["CVE-1"], "fix_versions": ["0.0.40"]}
        proc, data = self.summarize(audit=[{"name": "python-multipart", "version": "0.0.33", "vulns": [vuln]}])
        self.assertEqual(proc.returncode, 1)
        found = data["findings"][0]
        self.assertEqual((found["tool"], found["version"], found["severity"]), ("pip-audit", "0.0.33", "high"))


class IncompleteScanTest(unittest.TestCase):
    """Çalışmayan tarama hiçbir zaman temiz sonuç gibi görünmemeli."""

    def summarize(self, statuses=None, files=None, *args):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        if statuses is not None:
            (tmp / "_status.tsv").write_text("".join(f"{t}\t{s}\t\n" for t, s in statuses), encoding="utf-8")
        for name, text in (files or {}).items():
            (tmp / name).write_text(text, encoding="utf-8")
        proc = subprocess.run([sys.executable, str(ROOT / "scripts" / "summarize.py"), "--reports", str(tmp),
                               "--target", str(tmp), *args], capture_output=True, text=True, encoding="utf-8",
                              env={**os.environ, "PYTHONUTF8": "1"})
        data = json.loads((tmp / "findings.json").read_text(encoding="utf-8")) if (tmp / "findings.json").exists() else None
        return proc, data

    def assert_incomplete(self, proc, data):
        self.assertEqual(proc.returncode, 3, proc.stdout + proc.stderr)
        self.assertFalse(data["complete"])
        self.assertNotIn("Bulgu yok", proc.stdout)
        self.assertNotIn("Eşik aşılmadı", proc.stdout)

    def test_all_ok_is_clean(self):
        proc, data = self.summarize([("gitleaks", "ok")], {"gitleaks.json": "[]"})
        self.assertEqual(proc.returncode, 0, proc.stdout)
        self.assertTrue(data["complete"])
        self.assertIn("Bulgu yok", proc.stdout)

    def test_missing_error_and_partial_are_incomplete(self):
        for st in ("missing", "error", "partial"):
            with self.subTest(st):
                self.assert_incomplete(*self.summarize([("semgrep", st)], {"semgrep.json": '{"results": []}'}))

    def test_legit_skip_is_clean(self):
        proc, data = self.summarize([("gitleaks", "ok"), ("osv", "skipped")], {"gitleaks.json": "[]"})
        self.assertEqual(proc.returncode, 0, proc.stdout)
        self.assertTrue(data["complete"])

    def test_no_tool_ran_is_incomplete(self):
        self.assert_incomplete(*self.summarize([]))

    def test_truncated_report_is_incomplete(self):
        proc, data = self.summarize([("gitleaks", "ok")], {"gitleaks.json": '[{"RuleID": "a"'})
        self.assert_incomplete(proc, data)
        self.assertEqual(data["tools"][0]["status"], "error")

    def test_empty_or_changed_report_is_incomplete(self):
        for text in ("", '{"sonuclar": []}', '["beklenmeyen"]'):
            with self.subTest(text):
                self.assert_incomplete(*self.summarize([("semgrep", "ok")], {"semgrep.json": text}))

    def test_report_missing_for_ok_tool_is_incomplete(self):
        self.assert_incomplete(*self.summarize([("bandit", "ok")]))

    def test_unexpected_entry_does_not_crash(self):
        self.assert_incomplete(*self.summarize([("gitleaks", "ok")], {"gitleaks.json": '["beklenmeyen"]'}))

    def test_corrupt_report_without_status_file_is_incomplete(self):
        self.assert_incomplete(*self.summarize(None, {"osv.json": "{"}))

    def test_incomplete_outranks_threshold_but_keeps_findings(self):
        leak = '[{"RuleID": "a", "File": "x", "StartLine": 1}]'
        proc, data = self.summarize([("gitleaks", "ok"), ("semgrep", "missing")], {"gitleaks.json": leak})
        self.assertEqual(proc.returncode, 3)
        self.assertEqual(len(data["findings"]), 1)
        self.assertIn("Eşik aşıldı", proc.stdout)

    def test_allow_incomplete_exits_by_threshold_but_still_warns(self):
        proc, data = self.summarize([("semgrep", "missing")], None, "--allow-incomplete")
        self.assertEqual(proc.returncode, 0)
        self.assertFalse(data["complete"])
        self.assertIn("Tarama eksik", proc.stdout)
        leak = '[{"RuleID": "a", "File": "x", "StartLine": 1}]'
        proc, _ = self.summarize([("gitleaks", "ok"), ("semgrep", "missing")], {"gitleaks.json": leak}, "--allow-incomplete")
        self.assertEqual(proc.returncode, 1)

    def test_fail_on_none_reports_without_failing(self):
        proc, data = self.summarize([("semgrep", "missing")], None, "--fail-on", "none")
        self.assertEqual(proc.returncode, 0)
        self.assertFalse(data["complete"])
        self.assertIn("Tarama eksik", proc.stdout)

    def test_crash_is_not_threshold_exit(self):
        proc, _ = self.summarize([("gitleaks", "ok")], {"gitleaks.json": "[]", ".security-ignore.yml": "- id: [kapanmamis\n"})
        self.assertNotEqual(proc.returncode, 1, proc.stderr)


class SuppressionTest(unittest.TestCase):
    RULE = {"check_id": "rules.semgrep.kural-a", "path": "a.py", "start": {"line": 1},
            "extra": {"severity": "ERROR", "message": "m", "metadata": {"cwe": ["CWE-489: debug"]}}}

    def summarize(self, ignore):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        (tmp / ".security-ignore.yml").write_text(ignore, encoding="utf-8")
        (tmp / "semgrep.json").write_text(json.dumps({"results": [self.RULE]}), encoding="utf-8")
        proc = subprocess.run([sys.executable, str(ROOT / "scripts" / "summarize.py"), "--reports", str(tmp),
                               "--target", str(tmp), "--fail-on", "none"], capture_output=True, text=True, encoding="utf-8")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        return proc, json.loads((tmp / "findings.json").read_text(encoding="utf-8"))

    def assert_not_applied(self, ignore, word):
        proc, data = self.summarize(ignore)
        self.assertEqual(len(data["findings"]), 1, "bulgu bastırılmamalı")
        self.assertEqual(data["suppression_issues"][0]["status"], "geçersiz")
        self.assertIn(word, proc.stdout)

    def test_invalid_date_does_not_suppress(self):
        self.assert_not_applied("- id: kural-a\n  reason: r\n  expires: 31-12-2099\n", "expires geçersiz")

    def test_reason_and_expires_required(self):
        self.assert_not_applied("- id: kural-a\n  expires: 2999-01-01\n", "reason zorunlu")
        self.assert_not_applied("- id: kural-a\n  reason: r\n", "expires zorunlu")

    def test_cwe_and_wildcard_rejected(self):
        self.assert_not_applied("- id: CWE-489\n  reason: r\n  expires: 2999-01-01\n", "CWE")
        self.assert_not_applied("- id: '*'\n  reason: r\n  expires: 2999-01-01\n", "joker")

    def test_bare_semgrep_rule_name_matches(self):
        _, data = self.summarize("- id: kural-a\n  reason: r\n  expires: 2999-01-01\n")
        self.assertEqual(data["findings"], [])
        self.assertEqual(data["suppression_issues"], [])

    def test_expired_is_reported(self):
        proc, data = self.summarize("- id: kural-a\n  reason: r\n  expires: 2000-01-01\n")
        self.assertEqual(len(data["findings"]), 1)
        self.assertEqual(data["suppression_issues"][0]["status"], "süresi doldu")
        self.assertIn("süresi doldu", proc.stdout)

    def test_expiring_soon_warns_but_applies(self):
        soon = (dt.date.today() + dt.timedelta(days=10)).isoformat()
        _, data = self.summarize(f"- id: kural-a\n  reason: r\n  expires: {soon}\n")
        self.assertEqual(data["findings"], [])
        self.assertEqual(data["suppression_issues"][0]["status"], "süresi doluyor")


class MultiManifestTest(unittest.TestCase):
    def summarize(self, ignore=None):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        vuln = {"id": "GHSA-a", "aliases": ["CVE-1"], "database_specific": {"severity": "HIGH"}}
        (tmp / "osv.json").write_text(json.dumps({"results": [
            {"source": {"path": f"{s}/poetry.lock"},
             "packages": [{"package": {"name": "requests", "version": "2.0"}, "vulnerabilities": [vuln]}]}
            for s in ("svc-a", "svc-b")]}), encoding="utf-8")
        if ignore:
            (tmp / ".security-ignore.yml").write_text(ignore, encoding="utf-8")
        proc = subprocess.run([sys.executable, str(ROOT / "scripts" / "summarize.py"), "--reports", str(tmp),
                               "--target", str(tmp), "--fail-on", "none"], capture_output=True, text=True, encoding="utf-8")
        return proc, json.loads((tmp / "findings.json").read_text(encoding="utf-8")), tmp

    def test_same_cve_keeps_every_location(self):
        proc, data, tmp = self.summarize()
        self.assertEqual(len(data["findings"]), 1)
        self.assertEqual(data["findings"][0]["locations"], ["svc-a/poetry.lock", "svc-b/poetry.lock"])
        self.assertIn("svc-b/poetry.lock", proc.stdout)
        sarif = json.loads((tmp / "findings.sarif").read_text(encoding="utf-8"))
        uris = {l["physicalLocation"]["artifactLocation"]["uri"] for l in sarif["runs"][0]["results"][0]["locations"]}
        self.assertEqual(uris, {"svc-a/poetry.lock", "svc-b/poetry.lock"})

    def test_path_suppression_does_not_hide_other_location(self):
        ignore = "- id: CVE-1\n  path: svc-a/*\n  reason: r\n  expires: 2999-01-01\n"
        _, data, _ = self.summarize(ignore)
        self.assertEqual(len(data["findings"]), 1)
        _, data, _ = self.summarize(ignore.replace("svc-a/*", "svc-*"))
        self.assertEqual(data["findings"], [])


if __name__ == "__main__":
    unittest.main()
