"""python3 -m unittest discover tests"""
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
                           "--target", str(target), "--fail-on", fail_on], capture_output=True, text=True)
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


if __name__ == "__main__":
    unittest.main()
