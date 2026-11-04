#!/usr/bin/env python3
"""Gerçek araçlarla sözleşme testi: araç çıktı biçimi değişirse ayrıştırıcının sessizce bulgu kaybetmediğini sınar.

Kurulu araçlar gerektirir: bash scripts/install-tools.sh && python tests/contract.py
Sahte sırlar push korumasına takılmasın diye çalışma anında parçalardan üretilir.
"""
import base64
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from support import find_bash

ROOT = Path(__file__).resolve().parents[1]


def supabase_jwt(role):
    enc = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()
    return f"{enc({'alg': 'HS256', 'typ': 'JWT'})}.{enc({'iss': 'supabase', 'ref': 'qwertyuiopasdfghjklz', 'role': role})}.Zk3Vq8Lm2Xw9Rt5Ny7Pb4Hd6Gf1Js0Ac"


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
    "mobile/android/app/src/main/AndroidManifest.xml": '<application android:usesCleartextTraffic="true" />\n',
    "mobile/android/app/src/debug/AndroidManifest.xml": '<application android:usesCleartextTraffic="true" />\n',
    "functions/deno.lock": '{"version": "5", "npm": {"form-data@4.0.5": {}, "form-data@2.5.0": {}}}\n',
    "web/public.html": '<div data-anon-key="' + "sb_publishable_" + "Zk3Vq8Lm2Xw9Rt5Ny7Pb4Hd6Gf1Js0Ac" + '"></div>\n',
    "web/anon.ts": f'const supabaseKey = "{supabase_jwt("anon")}";\n',
    "web/service.ts": f'const supabaseKey = "{supabase_jwt("service_role")}";\n',
    "web/secret.html": '<div data-api-key="' + "sb_secret_" + "Zk3Vq8Lm2Xw9Rt5Ny7Pb4Hd6Gf1Js0Ac" + '"></div>\n',
}
EXPECTED_TOOLS = {"gitleaks", "osv", "bandit", "semgrep", "trivy"}
EXPECTED_RULES = {"rules.semgrep.fastapi-debug-enabled", "rules.semgrep.sqlalchemy-text-fstring",
                  "rules.semgrep.dart-bad-certificate-callback", "rules.semgrep.android-cleartext-traffic", "B602"}


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
        files = lambda tool: {f["file"] for f in data["findings"] if f["tool"] == tool}
        deno = {f["version"] for f in data["findings"] if f["file"] == "functions/deno.lock" and f["package"] == "form-data"}
        if deno != {"4.0.5", "2.5.0"}:
            problems.append(f"deno.lock sürümleri eksik: {sorted(deno)}")
        if "web/public.html" in files("gitleaks"):
            problems.append("Supabase publishable anahtarı sır sayıldı")
        if "web/secret.html" not in files("gitleaks"):
            problems.append("Supabase secret anahtarı kaçırıldı")
        manifests = {f["file"] for f in data["findings"] if f["rule_id"].endswith("android-cleartext-traffic")}
        if manifests != {"mobile/android/app/src/main/AndroidManifest.xml"}:
            problems.append(f"manifest kuralı yanlış dosyalarda: {sorted(manifests)}")
        sbom = {c.get("purl") for c in json.loads((tmp / "security-reports" / "sbom.cdx.json").read_text(encoding="utf-8"))["components"]}
        if "pkg:npm/form-data@4.0.5" not in sbom:
            problems.append("deno.lock paketleri SBOM'da yok")
        jwt = {f["file"]: f["severity"] for f in data["findings"] if f["tool"] == "gitleaks" and f["file"].endswith(".ts")}
        if jwt != {"web/anon.ts": "low", "web/service.ts": "critical"}:
            problems.append(f"Supabase JWT rolleri ayrılmadı: {jwt}")
        raw = "\n".join(p.read_text(encoding="utf-8", errors="replace") for p in (tmp / "security-reports").glob("*.json"))
        if supabase_jwt("service_role") in raw:
            problems.append("gitleaks raporunda maskelenmemiş sır var")
        if problems:
            print("BAŞARISIZ:", *problems, sep="\n- ")
            sys.exit(1)
        print(f"Sözleşme testi geçti: {len(data['findings'])} bulgu, araçlar: {sorted(tools)}")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    main()
