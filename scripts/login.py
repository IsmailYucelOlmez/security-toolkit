#!/usr/bin/env python3
"""Test kullanıcısıyla giriş yapar, taze token'ı maskeleyip adım çıktısına yazar.

Ortam değişkenleri:
  LOGIN_URL                                   giriş adresi (https; http yalnızca localhost için)
  TEST_USER_EMAIL, TEST_USER_PASSWORD         kimlik bilgileri
  LOGIN_FORMAT                                form (FastAPI OAuth2) | json
  LOGIN_USER_FIELD, LOGIN_PASSWORD_FIELD      istek alanları
  LOGIN_TOKEN_FIELD                           yanıttaki token alanı; iç içe ise noktalı (data.token)

Yerel kullanım: login.py --env-file <dosya> --name USER_A_TOKEN
  Token'ı ekrana yazmadan, kabuğun okuyabileceği NAME=değer satırı olarak dosyaya kaydeder.
  Yanlışlıkla commit'lenmemesi için dosya bir git deposunun içinde olamaz.

Sunucu yanıtı parolayı geri yansıtabileceği için yanıt gövdesi hiçbir zaman yazdırılmaz.
Çıkış kodu: 0 = token alındı, 1 = giriş başarısız
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

LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}


def fail(message):
    print(f"::error::Test kullanıcısı girişi başarısız: {message}")
    sys.exit(1)


def request_for(url, fmt, fields):
    if fmt == "json":
        return urllib.request.Request(url, json.dumps(fields).encode(), {"Content-Type": "application/json"})
    if fmt == "form":
        return urllib.request.Request(url, urllib.parse.urlencode(fields).encode(),
                                      {"Content-Type": "application/x-www-form-urlencoded"})
    fail(f"bilinmeyen biçim '{fmt}' (form veya json olmalı)")


def extract_token(body, path):
    value = body
    for key in path.split("."):
        value = value.get(key) if isinstance(value, dict) else None
    return value if isinstance(value, str) and value and value.split() == [value] else None


def write_env_file(path, name, token):
    path = path.expanduser().resolve()
    if any((parent / ".git").exists() for parent in path.parents):
        fail(f"{path} bir git deposunun içinde; token dosyası depo dışında olmalı.")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.touch(mode=0o600)
    lines = [line for line in path.read_text(encoding="utf-8").splitlines() if not line.startswith(f"{name}=")]
    lines.append(f"{name}={shlex.quote(token)}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--env-file", type=Path)
    parser.add_argument("--name", default="USER_A_TOKEN")
    args = parser.parse_args()
    if not re.fullmatch(r"[A-Z_][A-Z0-9_]*", args.name):
        fail("--name büyük harfli bir değişken adı olmalı.")
    return args


def main():
    args = parse_args()
    env = os.environ
    url = env.get("LOGIN_URL", "")
    user, password = env.get("TEST_USER_EMAIL", ""), env.get("TEST_USER_PASSWORD", "")
    token_field = env.get("LOGIN_TOKEN_FIELD") or "access_token"
    if not user or not password:
        fail("TEST_USER_EMAIL ve TEST_USER_PASSWORD secret'ları tanımlı değil.")
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https" and not (parsed.scheme == "http" and parsed.hostname in LOCAL_HOSTS):
        fail("giriş adresi https olmalı; parola şifresiz gönderilmez.")

    fields = {env.get("LOGIN_USER_FIELD") or "username": user,
              env.get("LOGIN_PASSWORD_FIELD") or "password": password}
    try:
        with urllib.request.urlopen(request_for(url, env.get("LOGIN_FORMAT") or "form", fields), timeout=30) as resp:
            body = json.load(resp)
    except urllib.error.HTTPError as e:
        fail(f"sunucu HTTP {e.code} döndürdü.")
    except (urllib.error.URLError, TimeoutError) as e:
        fail(f"sunucuya ulaşılamadı ({type(e).__name__}).")
    except ValueError:
        fail("yanıt JSON değil.")

    token = extract_token(body, token_field)
    if not token:
        fail(f"yanıtta '{token_field}' alanı bulunamadı.")

    if args.env_file:
        write_env_file(args.env_file, args.name, token)
        print(f"{args.name} kaydedildi: {args.env_file}")
        return

    # Maske, değer herhangi bir yere yazılmadan önce verilmeli
    print(f"::add-mask::{token}", flush=True)
    with open(env["GITHUB_OUTPUT"], "a", encoding="utf-8") as fh:
        fh.write(f"header=Bearer {token}\n")
    print("Test kullanıcısıyla giriş yapıldı.")


if __name__ == "__main__":
    main()
