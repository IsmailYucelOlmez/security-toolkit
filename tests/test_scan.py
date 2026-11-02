"""python3 -m unittest discover tests"""
import importlib.util
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def scan(*args, cwd):
    return subprocess.run([shutil.which("bash"), str(ROOT / "scripts" / "scan.sh"), *args], cwd=cwd,
                          capture_output=True, text=True, encoding="utf-8", errors="replace",
                          env={**os.environ, "PYTHONUTF8": "1"})


class ScanArgumentsTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def test_missing_target_is_usage_error_not_clean_scan(self):
        proc = scan("--path", "yok", cwd=self.tmp)
        self.assertEqual(proc.returncode, 2, proc.stdout)
        self.assertEqual(list(self.tmp.iterdir()), [], "rapor yanlış yere yazılmamalı")

    def test_reports_ignored_without_touching_existing_gitignore(self):
        proc = scan("--path", ".", "--only", "bandit", "--fail-on", "none", cwd=self.tmp)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        ignore = self.tmp / "security-reports" / ".gitignore"
        self.assertEqual(ignore.read_text(), "*\n")
        ignore.write_text("ozel\n")
        scan("--path", ".", "--only", "bandit", "--fail-on", "none", cwd=self.tmp)
        self.assertEqual(ignore.read_text(), "ozel\n")


class RelTest(unittest.TestCase):
    def test_paths_use_forward_slashes(self):
        spec = importlib.util.spec_from_file_location("summarize", ROOT / "scripts" / "summarize.py")
        summarize = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(summarize)
        target = Path(tempfile.gettempdir()).resolve()
        self.assertEqual(summarize.rel(str(target / "a" / "b.py"), target), "a/b.py")
        self.assertEqual(summarize.rel(str(Path("a") / "b.py"), target), "a/b.py")


if __name__ == "__main__":
    unittest.main()
