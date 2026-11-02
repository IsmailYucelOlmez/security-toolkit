"""python3 -m unittest discover tests"""
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASH = shutil.which("bash")
# Gerçek Strix yerine: argümanları ve talimat dosyasını kaydeder, istenen kodla çıkar
STUB = """#!/usr/bin/env bash
printf '%s\\n' "$@" > "$STUB_DIR/args"
while [[ $# -gt 0 ]]; do
  if [[ "$1" == "--instruction-file" ]]; then
    cat "$2" > "$STUB_DIR/instructions"
    echo "$2" > "$STUB_DIR/instruction_path"
  fi
  shift
done
exit "$STUB_RC"
"""


@unittest.skipUnless(BASH, "bash gerekli")
class RunStrixTest(unittest.TestCase):
    def run_script(self, rc=0, **env):
        self.dir = Path(tempfile.mkdtemp())
        stub = self.dir / "strix"
        stub.write_text(STUB, encoding="utf-8", newline="\n")
        stub.chmod(0o755)
        full = {**os.environ, "PATH": f"{self.dir}{os.pathsep}{os.environ['PATH']}", "STUB_DIR": self.dir.as_posix(),
                "STUB_RC": str(rc), "STRIX_LLM": "m", "LLM_API_KEY": "k", "MODE": "quick", "TARGET_DIR": "./project",
                "BASE": "https://staging.ornek.com", "AUTH_HEADER_A": "", "AUTH_HEADER_B": "",
                "GITHUB_STEP_SUMMARY": (self.dir / "summary.md").as_posix(), **env}
        proc = subprocess.run([BASH, str(ROOT / "scripts" / "run_strix.sh")], capture_output=True, text=True,
                              encoding="utf-8", env=full)
        summary = self.dir / "summary.md"
        return proc, summary.read_text(encoding="utf-8") if summary.exists() else ""

    def test_without_auth_summary_warns_about_coverage(self):
        proc, summary = self.run_script()
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("Doğrulanmış açık bulunmadı", summary)
        self.assertIn("yalnızca girişsiz yüzeyi", summary)
        self.assertNotIn("--instruction-file", (self.dir / "args").read_text(encoding="utf-8"))

    def test_two_users_are_passed_by_file_not_arguments(self):
        proc, summary = self.run_script(AUTH_HEADER_A="Bearer gizli-a", AUTH_HEADER_B="Bearer gizli-b")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        args = (self.dir / "args").read_text(encoding="utf-8")
        self.assertNotIn("gizli", args)
        instructions = (self.dir / "instructions").read_text(encoding="utf-8")
        self.assertIn("Bearer gizli-a", instructions)
        self.assertIn("Bearer gizli-b", instructions)
        self.assertNotIn("gizli", proc.stdout + proc.stderr + summary)
        self.assertIn("iki test kullanıcısıyla", summary)

    def test_one_user_says_idor_cannot_be_proven(self):
        _, summary = self.run_script(AUTH_HEADER_A="Bearer gizli-a")
        self.assertIn("IDOR", summary)
        self.assertIn("tek test kullanıcısıyla", summary)

    def test_findings_are_reported_without_failing(self):
        proc, summary = self.run_script(rc=2)
        self.assertEqual(proc.returncode, 0)
        self.assertIn("doğrulanmış bulgu", summary)

    def test_crash_is_not_reported_as_finding(self):
        proc, summary = self.run_script(rc=1)
        self.assertEqual(proc.returncode, 1)
        self.assertIn("Tarama çalışamadı", summary)
        self.assertNotIn("doğrulanmış bulgu", summary)

    def test_no_live_target_says_source_only(self):
        _, summary = self.run_script(BASE="")
        self.assertIn("yalnızca kaynak kod", summary)

    def test_missing_llm_secrets_fail(self):
        proc, _ = self.run_script(LLM_API_KEY="")
        self.assertEqual(proc.returncode, 1)
        self.assertFalse((self.dir / "args").exists())


if __name__ == "__main__":
    unittest.main()
