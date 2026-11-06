"""python3 -m unittest discover tests"""
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = str(ROOT / "scripts" / "deno_lock.py")
LOCK = {"version": "5", "npm": {"@a/b@1.0.0": {}, "c@2.0.0_d@1.0.0": {}, "c@3.0.0": {}}, "jsr": {"@std/assert@1.0.19": {}},
        "remote": {"https://esm.sh/x": "abc"}}


class DenoLockTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.lock = self.tmp / "deno.lock"
        self.lock.write_text(json.dumps(LOCK))

    def cli(self, *args):
        return subprocess.run([sys.executable, SCRIPT, *map(str, args)], capture_output=True, text=True, encoding="utf-8")

    def versions(self, lock_data):
        return {(p.rsplit("node_modules/", 1)[1], e["version"]) for p, e in lock_data["packages"].items() if p}

    def test_keeps_every_version_and_drops_peer_suffix(self):
        out = self.tmp / "package-lock.json"
        proc = self.cli("npm", self.lock, out)
        self.assertEqual((proc.returncode, proc.stdout), (0, "3 1 1"), proc.stderr)
        data = json.loads(out.read_text(encoding="utf-8"))
        self.assertEqual(data["lockfileVersion"], 3)
        self.assertEqual(self.versions(data), {("@a/b", "1.0.0"), ("c", "2.0.0"), ("c", "3.0.0")})
        self.assertEqual(data["packages"]["node_modules/@a/b"]["resolved"], "https://registry.npmjs.org/@a/b/-/b-1.0.0.tgz")

    def test_v3_layout(self):
        self.lock.write_text(json.dumps({"version": "3", "packages": {"npm": {"c@2.0.0": {}}}}))
        proc = self.cli("npm", self.lock, self.tmp / "out.json")
        self.assertEqual((proc.returncode, proc.stdout), (0, "1 0 0"), proc.stderr)

    def test_unknown_lock_fails_instead_of_scanning_nothing(self):
        for text in ('{"version": "2", "npm": {}}', '{"version": "5", "npm": {"bozuk": {}}}', "{bozuk", "[]"):
            with self.subTest(text):
                self.lock.write_text(text)
                self.assertEqual(self.cli("npm", self.lock, self.tmp / "out.json").returncode, 1)

    def test_sbom_adds_components_once(self):
        sbom = self.tmp / "sbom.json"
        sbom.write_text(json.dumps({"bomFormat": "CycloneDX", "components": [{"name": "c", "version": "3.0.0"}]}))
        self.assertEqual(self.cli("sbom", sbom, self.lock, self.lock).returncode, 0)
        comps = json.loads(sbom.read_text(encoding="utf-8"))["components"]
        self.assertEqual(len(comps), 4)
        purls = {c.get("purl") for c in comps}
        self.assertIn("pkg:npm/%40a/b@1.0.0", purls)
        self.assertIn("pkg:npm/c@2.0.0", purls)
        self.assertIn("@std/assert", {c["name"] for c in comps})


if __name__ == "__main__":
    unittest.main()
