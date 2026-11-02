#!/usr/bin/env python3
"""security-review skill'inin staging'e attığı istekler için sınır uygulayan sarmalayıcı.

  staging_request.py init --base https://staging-api.ornek.test [--confirm-not-production]
  staging_request.py request --user USER_A_TOKEN GET /orders/1
  staging_request.py request --user USER_B_TOKEN PUT /orders/1 --allow-write --json '{"text": "x"}'

Kurallar modelin talimatına bırakılmaz: oturum başına en fazla 50 istek, yalnızca init ile onaylanan
adres, yazma istekleri için --allow-write, yönlendirme izlenmez. Çıktıda token ve yanıt değerleri
bulunmaz; yalnızca durum kodu, boyut ve JSON alan adları yazılır.

Ortam değişkenleri: STAGING_TOKENS (token dosyası), STAGING_STATE (oturum dosyası)
Çıkış kodu: 0 = yanıt alındı, 1 = istek gönderilemedi, 3 = kural nedeniyle reddedildi
"""
import argparse
import json
import os
import re
import shlex
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

MAX_REQUESTS = 50
READ_METHODS = {"GET", "HEAD"}
LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}
TEST_LIKE = re.compile(r"staging|stage|test|dev|preview")
CACHE = Path.home() / ".cache" / "security-toolkit"


def refuse(message):
    print(f"REDDEDİLDİ: {message}")
    sys.exit(3)


def state_path():
    return Path(os.environ.get("STAGING_STATE") or CACHE / "staging-session.json")


def tokens_path():
    return Path(os.environ.get("STAGING_TOKENS") or CACHE / "staging-tokens.env")


def init(args):
    parsed = urllib.parse.urlparse(args.base)
    if parsed.scheme != "https" and not (parsed.scheme == "http" and parsed.hostname in LOCAL_HOSTS):
        refuse("adres https olmalı; http yalnızca localhost için kabul edilir.")
    host = parsed.hostname or ""
    if host not in LOCAL_HOSTS and not TEST_LIKE.search(host) and not args.confirm_not_production:
        refuse(f"{host} test ortamına benzemiyor. Kullanıcı bunun staging olduğunu yazılı onayladıysa "
               "--confirm-not-production verin.")
    path = state_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"base": args.base.rstrip("/"), "count": 0}), encoding="utf-8")
    print(f"Oturum hazır. Hedef: {args.base.rstrip('/')} · en fazla {MAX_REQUESTS} istek")


def read_token(name):
    try:
        lines = tokens_path().read_text(encoding="utf-8").splitlines()
    except OSError:
        refuse(f"token dosyası okunamadı: {tokens_path()}")
    for line in lines:
        if line.startswith(f"{name}="):
            return shlex.split(line.split("=", 1)[1])[0]
    refuse(f"{name} token dosyasında yok.")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def field_names(body):
    try:
        data = json.loads(body)
    except ValueError:
        return "JSON değil"
    if isinstance(data, list):
        data = data[0] if data and isinstance(data[0], dict) else {}
        return "liste, ilk kayıt alanları: " + ", ".join(sorted(data)) if data else "liste"
    return "alanlar: " + ", ".join(sorted(data)) if isinstance(data, dict) else type(data).__name__


def request(args):
    try:
        state = json.loads(state_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        refuse("oturum yok; önce kullanıcıya hedefi onaylatıp init çalıştırın.")
    method = args.method.upper()
    if not args.path.startswith("/") or args.path.startswith("//"):
        refuse("yalnızca / ile başlayan yol verin; hedef init ile belirlenir.")
    if method not in READ_METHODS and not args.allow_write:
        refuse(f"{method} veri değiştirebilir; kullanıcı bu denemeyi onayladıysa --allow-write verin.")
    if state["count"] >= MAX_REQUESTS:
        refuse(f"oturum sınırı doldu ({MAX_REQUESTS} istek).")
    token = read_token(args.user)
    # Sayaç istekten önce artar: sonuç ne olursa olsun sınır aşılmaz
    state["count"] += 1
    state_path().write_text(json.dumps(state), encoding="utf-8")

    data = args.json.encode() if args.json else None
    headers = {"Authorization": f"Bearer {token}"}
    if data:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(state["base"] + args.path, data=data, headers=headers, method=method)
    opener = urllib.request.build_opener(NoRedirect)
    try:
        with opener.open(req, timeout=30) as resp:
            status, body = resp.status, resp.read()
    except urllib.error.HTTPError as e:
        status, body = e.code, e.read()
    except (urllib.error.URLError, TimeoutError) as e:
        print(f"İstek gönderilemedi ({type(e).__name__}).")
        sys.exit(1)
    print(f"{method} {args.path} -> {status} · {len(body)} bayt · {field_names(body)} · istek {state['count']}/{MAX_REQUESTS}")


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    start = sub.add_parser("init")
    start.add_argument("--base", required=True)
    start.add_argument("--confirm-not-production", action="store_true")
    send = sub.add_parser("request")
    send.add_argument("--user", required=True)
    send.add_argument("method")
    send.add_argument("path")
    send.add_argument("--allow-write", action="store_true")
    send.add_argument("--json")
    args = parser.parse_args()
    (init if args.command == "init" else request)(args)


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    main()
