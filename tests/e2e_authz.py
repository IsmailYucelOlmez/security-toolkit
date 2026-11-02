#!/usr/bin/env python3
"""Derin taramanın yetki akışını bilerek açıklı API'ye karşı uçtan uca sınar.

Kurulu Schemathesis gerektirdiği için birim testlerinden ayrı çalışır: python tests/e2e_authz.py
Bu test olmadan IDOR kontrolünün sessizce hiçbir şey sınamadığı fark edilemez.
"""
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
BASH = shutil.which("bash")
ENV = {**os.environ, "PYTHONUTF8": "1", "PYTHON": sys.executable}


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def login(base, user):
    with tempfile.TemporaryDirectory() as tmp:
        output = Path(tmp) / "output"
        output.touch()
        subprocess.run([sys.executable, str(SCRIPTS / "login.py")], check=True, capture_output=True, env={
            **ENV, "GITHUB_OUTPUT": str(output), "LOGIN_URL": f"{base}/token",
            "TEST_USER_EMAIL": user, "TEST_USER_PASSWORD": f"{user}-parola"})
        return output.read_text(encoding="utf-8").strip().removeprefix("header=")


def scan(base, directory, **env):
    summary = Path(directory) / "summary.md"
    report_dir = Path(directory) / "reports"
    proc = subprocess.run([BASH, str(SCRIPTS / "run_schemathesis.sh")], capture_output=True, text=True,
                          encoding="utf-8", errors="replace", cwd=directory, env={
                              **ENV, "OPENAPI": f"{base}/openapi.json", "MAX_TIME": os.environ.get("E2E_MAX_TIME", "30"),
                              "REPORT_DIR": str(report_dir), "GITHUB_STEP_SUMMARY": str(summary), **env})
    text = summary.read_text(encoding="utf-8") if summary.exists() else ""
    return proc, text, report_dir


def check(condition, message, proc=None):
    if not condition:
        print(f"BAŞARISIZ: {message}")
        if proc is not None:
            print(proc.stdout[-3000:], proc.stderr[-1000:])
        sys.exit(1)
    print(f"tamam: {message}")


def main():
    port = free_port()
    base = f"http://127.0.0.1:{port}"
    server = subprocess.Popen([sys.executable, str(ROOT / "tests" / "fixtures" / "authz_api.py"), str(port)])
    try:
        for _ in range(50):
            try:
                urllib.request.urlopen(f"{base}/openapi.json", timeout=1)
                break
            except OSError:
                time.sleep(0.1)
        alice, bob = login(base, "alice"), login(base, "bob")

        with tempfile.TemporaryDirectory() as tmp:
            proc, summary, reports = scan(base, tmp, AUTH_HEADER_A=alice, AUTH_HEADER_B=bob)
            check(proc.returncode == 1, "iki kullanıcıyla IDOR bulunca iş başarısız olur", proc)
            check("`GET /orders/{item_id}` — ST402" in summary, "açıklı uçta ST402 raporlanır", proc)
            check("`GET /notes/{item_id}` — ST402" not in summary, "güvenli uçta ST402 raporlanmaz", proc)
            tokens = subprocess.run([sys.executable, str(SCRIPTS / "redact_tokens.py"), str(reports), "--check"],
                                    env={**ENV, "AUTH_HEADER_A": alice, "AUTH_HEADER_B": bob})
            check(tokens.returncode == 0, "raporlarda token bulunmaz")

        with tempfile.TemporaryDirectory() as tmp:
            proc, summary, _ = scan(base, tmp, AUTH_HEADER_A=alice)
            check(proc.returncode == 0, "tek kullanıcıyla iş başarısız olmaz", proc)
            check("ST402" not in summary, "tek kullanıcıyla ST402 üretilmez", proc)
            check("IDOR kontrolü çalışmadı" in summary, "tek kullanıcıda özet bunu açıkça söyler", proc)

        with tempfile.TemporaryDirectory() as tmp:
            proc, summary, _ = scan(f"{base}/yok", tmp, AUTH_HEADER_A=alice)
            check(proc.returncode == 1 and "Tarama çalışamadı" in summary, "şema yüklenemezse iş başarısız olur", proc)
    finally:
        server.terminate()
        server.wait(timeout=10)
    print("Uçtan uca yetki testi geçti.")


if __name__ == "__main__":
    main()
