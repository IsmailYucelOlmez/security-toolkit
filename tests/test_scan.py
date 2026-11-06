"""python3 -m unittest discover tests"""
import importlib.util
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from support import find_bash

ROOT = Path(__file__).resolve().parents[1]


def scan(*args, cwd):
    return subprocess.run([find_bash(), str(ROOT / "scripts" / "scan.sh"), *args], cwd=cwd,
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


class FailClosedTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.tools = self.tmp / "tools"
        (self.tools / "bin").mkdir(parents=True)
        self.project = self.tmp / "proje"
        self.project.mkdir()

    def run_scan(self, *args):
        # Makinede kurulu araçlar sonucu değiştirmesin: gitleaks ve osv-scanner bulunan dizinler PATH'ten çıkar
        dirs = [d for d in os.environ["PATH"].split(os.pathsep)
                if not any(shutil.which(t, path=d) for t in ("gitleaks", "osv-scanner"))]
        env = {**os.environ, "PYTHONUTF8": "1", "SECURITY_TOOLS_DIR": str(self.tools), "PATH": os.pathsep.join(dirs)}
        proc = subprocess.run([find_bash(), str(ROOT / "scripts" / "scan.sh"), "--path", str(self.project), *args],
                              capture_output=True, text=True, encoding="utf-8", errors="replace", env=env)
        reports = self.project / "security-reports"
        findings = reports / "findings.json"
        return proc, json.loads(findings.read_text(encoding="utf-8")) if findings.exists() else None

    def stub_osv(self, rc):
        stub = self.tools / "bin" / "osv-scanner"
        stub.write_text(f'#!/usr/bin/env bash\necho \'{{"results": []}}\'\nexit {rc}\n', newline="\n")
        stub.chmod(0o755)

    def tool_status(self, data, tool):
        return next((t["status"] for t in data["tools"] if t["tool"] == tool), None)

    def test_missing_tool_fails_closed(self):
        proc, data = self.run_scan("--only", "gitleaks")
        self.assertEqual(proc.returncode, 3, proc.stdout + proc.stderr)
        self.assertFalse(data["complete"])
        self.assertNotIn("Bulgu yok", proc.stdout)

    def test_allow_incomplete_flag_reaches_summary(self):
        proc, data = self.run_scan("--only", "gitleaks", "--allow-incomplete")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertFalse(data["complete"])
        self.assertIn("Tarama eksik", proc.stdout)

    def test_manifest_without_lock_is_incomplete(self):
        self.stub_osv(128)
        cases = {"pyproject.toml": '[project]\nname = "a"\ndependencies = ["fastapi"]\n',
                 "pubspec.yaml": "name: a\ndependencies:\n  http: any\n",
                 "package.json": '{"dependencies": {"a": "1"}}\n'}
        for name, text in cases.items():
            with self.subTest(name):
                (self.project / name).write_text(text)
                proc, data = self.run_scan("--only", "osv")
                self.assertEqual(proc.returncode, 3, proc.stdout + proc.stderr)
                self.assertEqual(self.tool_status(data, "dependencies"), "error")
                (self.project / name).unlink()

    def test_lock_files_cover_manifest(self):
        self.stub_osv(0)
        (self.project / "pyproject.toml").write_text('[project]\ndependencies = ["fastapi"]\n')
        (self.project / "uv.lock").write_text("")
        pkg = self.project / "packages" / "a"
        pkg.mkdir(parents=True)
        (pkg / "package.json").write_text('{"dependencies": {"a": "1"}}\n')
        (self.project / "package-lock.json").write_text("{}")  # workspace kilidi kökte
        proc, data = self.run_scan("--only", "osv")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIsNone(self.tool_status(data, "dependencies"))

    def test_project_without_dependencies_is_clean(self):
        self.stub_osv(128)
        (self.project / "pyproject.toml").write_text('[tool.ruff]\nline-length = 100\n')
        (self.project / "a.py").write_text("print(1)\n")
        proc, data = self.run_scan("--only", "osv")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertTrue(data["complete"])

    def test_kubernetes_only_repo_triggers_trivy(self):
        (self.project / "k8s.yaml").write_text("apiVersion: v1\nkind: Pod\n")
        proc, data = self.run_scan("--only", "trivy", "--allow-incomplete")
        self.assertIn("infra", data["stacks"], proc.stdout)
        self.assertIsNotNone(self.tool_status(data, "trivy"))

    def test_plain_yaml_is_not_infra(self):
        (self.project / "conf.yaml").write_text("anahtar: deger\n")
        _, data = self.run_scan("--only", "gitleaks", "--allow-incomplete")
        self.assertNotIn("infra", data["stacks"])

    def test_deno_lock_is_scanned_and_reported_with_its_own_path(self):
        self.stub_osv(0)
        funcs = self.project / "supabase" / "functions"
        funcs.mkdir(parents=True)
        (funcs / "deno.json").write_text('{"imports": {"a": "npm:a@1"}}\n')
        (funcs / "deno.lock").write_text('{"version": "5", "npm": {"a@1.0.0": {}}, "jsr": {"@std/assert@1.0.0": {}}}')
        proc, data = self.run_scan("--only", "osv")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        row = next(t for t in data["tools"] if t["tool"] == "osv-deno")
        self.assertEqual(row["status"], "ok")
        self.assertIn("supabase/functions/deno.lock: 1 npm paketi; 1 jsr", row["note"])
        self.assertFalse(list((self.project / "security-reports").glob("_deno-*")), "geçici dizin kalmamalı")

    def test_unreadable_deno_lock_is_incomplete(self):
        self.stub_osv(0)
        (self.project / "deno.lock").write_text('{"version": "2"}')
        proc, data = self.run_scan("--only", "osv")
        self.assertEqual(proc.returncode, 3, proc.stdout + proc.stderr)
        self.assertEqual(self.tool_status(data, "osv-deno"), "error")

    def test_osv_failure_on_deno_lock_is_incomplete(self):
        self.stub_osv(127)
        (self.project / "deno.lock").write_text('{"version": "5", "npm": {"a@1.0.0": {}}}')
        proc, data = self.run_scan("--only", "osv")
        self.assertEqual(proc.returncode, 3, proc.stdout + proc.stderr)
        self.assertEqual(self.tool_status(data, "osv-deno"), "error")

    def test_deno_json_without_lock_is_incomplete(self):
        self.stub_osv(128)
        (self.project / "deno.json").write_text('{"imports": {"a": "npm:a@1"}}\n')
        proc, data = self.run_scan("--only", "osv")
        self.assertEqual(proc.returncode, 3, proc.stdout + proc.stderr)
        self.assertEqual(self.tool_status(data, "dependencies"), "error")

    def test_flutter_generated_python_is_not_python_stack(self):
        helper = self.project / "ios" / "Flutter" / "ephemeral"
        helper.mkdir(parents=True)
        (helper / "flutter_lldb_helper.py").write_text("print(1)\n")
        _, data = self.run_scan("--only", "gitleaks", "--allow-incomplete")
        self.assertNotIn("python", data["stacks"])
        (self.project / "app.py").write_text("print(1)\n")
        _, data = self.run_scan("--only", "gitleaks", "--allow-incomplete")
        self.assertIn("python", data["stacks"])

    def test_supabase_check_runs_and_reports(self):
        mig = self.project / "supabase" / "migrations"
        mig.mkdir(parents=True)
        (mig / "1_init.sql").write_text("create table public.notes (id int);\n")
        proc, data = self.run_scan("--only", "supabase")
        self.assertIn("supabase", data["stacks"])
        self.assertEqual(self.tool_status(data, "supabase"), "ok")
        rules = {(f["rule_id"], f["file"]) for f in data["findings"]}
        self.assertIn(("supabase-table-without-rls", "supabase/migrations/1_init.sql"), rules)
        self.assertEqual(proc.returncode, 1)

    def test_skipping_osv_disables_coverage_check(self):
        (self.project / "pubspec.yaml").write_text("name: a\n")
        (self.tools / "bin" / "gitleaks").write_text('#!/usr/bin/env bash\necho "[]" > "$(printf "%s\\n" "$@" | sed -n "/gitleaks.json/p")"\n', newline="\n")
        (self.tools / "bin" / "gitleaks").chmod(0o755)
        proc, data = self.run_scan("--only", "gitleaks")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertTrue(data["complete"])


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
