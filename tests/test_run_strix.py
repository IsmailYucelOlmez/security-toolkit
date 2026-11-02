"""python3 -m unittest discover tests"""
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from support import find_bash

ROOT = Path(__file__).resolve().parents[1]
BASH = find_bash()
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
                              encoding="utf-8", errors="replace", env=full)
        summary = self.dir / "summary.md"
        return proc, summary.read_text(encoding="utf-8") if summary.exists() else ""

    def test_without_auth_summary_warns_about_coverage(self):
        proc, summary = self.run_script()
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("Doğrulanmış açık bulunmadı", summary)
        self.assertIn("yalnızca girişsiz yüzeyi", summary)
        self.assertNotIn("Authorization", (self.dir / "instructions").read_text(encoding="utf-8"))
        self.assertIn("Never run binaries", (self.dir / "instructions").read_text(encoding="utf-8"))

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

    def test_verified_finding_fails_by_default(self):
        proc, summary = self.run_script(rc=2)
        self.assertEqual(proc.returncode, 1)
        self.assertIn("doğrulanmış bulgu", summary)

    def test_verified_finding_can_be_report_only(self):
        proc, summary = self.run_script(rc=2, STRIX_FAIL_ON_FINDING="false")
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


@unittest.skipUnless(BASH, "bash gerekli")
class EgressTest(unittest.TestCase):
    def run_script(self, base, ips="203.0.113.7 STREAM\\n203.0.113.7 DGRAM\\n203.0.113.8 STREAM\\n"):
        tmp = Path(tempfile.mkdtemp())
        log = tmp / "rules"
        (tmp / "sudo").write_text(f'#!/usr/bin/env bash\nshift\necho "$*" >> "{log.as_posix()}"\n', encoding="utf-8", newline="\n")
        (tmp / "getent").write_text(f"#!/usr/bin/env bash\nprintf '{ips}'\n", encoding="utf-8", newline="\n")
        for tool in ("sudo", "getent"):
            (tmp / tool).chmod(0o755)
        proc = subprocess.run([BASH, str(ROOT / "scripts" / "strix_egress.sh")], capture_output=True, text=True,
                              encoding="utf-8", errors="replace",
                              env={**os.environ, "PATH": f"{tmp}{os.pathsep}{os.environ['PATH']}", "BASE": base})
        return proc, log.read_text(encoding="utf-8").splitlines() if log.exists() else []

    def test_allows_only_dns_and_target_then_drops(self):
        proc, rules = self.run_script("https://staging.ornek.test:8443/api")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("-A DOCKER-USER -d 203.0.113.7 -j RETURN", rules)
        self.assertIn("-A DOCKER-USER -d 203.0.113.8 -j RETURN", rules)
        self.assertEqual(rules[-1], "-A DOCKER-USER -j DROP")
        self.assertEqual(sum("-d " in r for r in rules), 2)

    def test_no_target_allows_only_dns(self):
        proc, rules = self.run_script("")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertFalse([r for r in rules if "-d " in r])
        self.assertEqual(rules[-1], "-A DOCKER-USER -j DROP")

    def test_unresolved_target_fails_without_rules(self):
        proc, rules = self.run_script("https://yok.ornek.test", ips="")
        self.assertEqual(proc.returncode, 1)
        self.assertEqual(rules, [])


if __name__ == "__main__":
    unittest.main()
