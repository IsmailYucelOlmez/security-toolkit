#!/usr/bin/env python3
"""Gerçek araçlarla sözleşme testi: araç çıktı biçimi değişirse ayrıştırıcının sessizce bulgu kaybetmediğini sınar.

Kurulu araçlar gerektirir: bash scripts/install-tools.sh && python tests/contract.py
Sahte sırlar push korumasına takılmasın diye çalışma anında parçalardan üretilir.
"""
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from support import find_bash

ROOT = Path(__file__).resolve().parents[1]
FILES = {
    "api/requirements.txt": "requests==2.19.0\n",
    "api/app.py": """import pickle, subprocess
from fastapi import FastAPI
from sqlalchemy import text
app = FastAPI(debug=True)

def a(q, db, raw, cmd):
    db.execute(text(f"SELECT '{q}'"))
    pickle.loads(raw)
    subprocess.check_output(cmd, shell=True)
""",
    "api/settings.py": 'KEY = "' + "AKIA" + "Z7Q2MNB4XKCV9LTD" + '"\n',
    "mobile/pubspec.yaml": "name: app\n",
    "mobile/pubspec.lock": 'packages:\n  http:\n    dependency: "direct main"\n    description:\n'
                           '      name: http\n      url: "https://pub.dev"\n    source: hosted\n    version: "0.13.0"\n'
                           'sdks:\n  dart: ">=2.12.0 <3.0.0"\n',
    "mobile/lib/main.dart": 'void c(h) { h.badCertificateCallback = (cert, host, port) => true; }\n',
    "infra/Dockerfile": "FROM python:3.8\nUSER root\n",
}
EXPECTED_TOOLS = {"gitleaks", "osv", "bandit", "semgrep", "trivy"}
EXPECTED_RULES = {"rules.semgrep.fastapi-debug-enabled", "rules.semgrep.sqlalchemy-text-fstring",
                  "rules.semgrep.dart-bad-certificate-callback", "B602"}


def main():
    tmp = Path(tempfile.mkdtemp())
    try:
        for name, text in FILES.items():
            path = tmp / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8", newline="\n")
        git = ["git", "-C", str(tmp), "-c", "user.name=t", "-c", "user.email=t@example.test"]
        subprocess.run(["git", "-C", str(tmp), "init", "-q"], check=True)
        subprocess.run([*git, "add", "-A"], check=True, capture_output=True)
        subprocess.run([*git, "commit", "-qm", "sozlesme"], check=True)
        proc = subprocess.run([find_bash(), str(ROOT / "scripts" / "scan.sh"), "--path", str(tmp), "--skip", "dotnet"],
                              capture_output=True, text=True, encoding="utf-8", errors="replace")
        data = json.loads((tmp / "security-reports" / "findings.json").read_text(encoding="utf-8"))
        tools = {f["tool"] for f in data["findings"]} | {t for f in data["findings"] for t in f.get("also_found_by", [])}
        rules = {f["rule_id"] for f in data["findings"]}
        problems = []
        if proc.returncode != 1:
            problems.append(f"çıkış kodu {proc.returncode}, beklenen 1")
        if not data["complete"]:
            problems.append(f"tarama eksik: {data['tools']}")
        if EXPECTED_TOOLS - tools:
            problems.append(f"bulgu üretmeyen araçlar: {sorted(EXPECTED_TOOLS - tools)}")
        if EXPECTED_RULES - rules:
            problems.append(f"ateşlenmeyen kurallar: {sorted(EXPECTED_RULES - rules)}")
        if problems:
            print("BAŞARISIZ:", *problems, sep="\n- ")
            sys.exit(1)
        print(f"Sözleşme testi geçti: {len(data['findings'])} bulgu, araçlar: {sorted(tools)}")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    main()
