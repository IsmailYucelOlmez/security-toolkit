#!/usr/bin/env python3
"""İki test kullanıcısının token'larından Schemathesis yapılandırması üretir.

Kullanım: schemathesis_config.py <dizin>
Ortam değişkenleri: AUTH_HEADER_A, AUTH_HEADER_B (Authorization değerleri)

Dizine auth.json (Web Fuzzing Commons biçimi) ve schemathesis.toml yazar. Token içerdikleri için
dizin rapor klasörünün dışında olmalı ve iş bitince silinmelidir.
"""
import json
import os
import sys
from pathlib import Path


def main():
    out = Path(sys.argv[1]).resolve()
    headers = {"user_a": os.environ.get("AUTH_HEADER_A", ""), "user_b": os.environ.get("AUTH_HEADER_B", "")}
    missing = [name for name, value in headers.items() if not value]
    if missing:
        print(f"::error::Eksik kullanıcı token'ı: {', '.join(missing)}")
        sys.exit(1)

    auth = {"auth": [{"name": name, "fixedHeaders": [{"name": "Authorization", "value": value}]}
                     for name, value in headers.items()]}
    auth_file = out / "auth.json"
    auth_file.touch(mode=0o600)
    auth_file.write_text(json.dumps(auth), encoding="utf-8")
    (out / "schemathesis.toml").write_text(
        f'[auth.wfc]\npath = "{auth_file.as_posix()}"\npeers = ["user_a", "user_b"]\n', encoding="utf-8")


if __name__ == "__main__":
    main()
