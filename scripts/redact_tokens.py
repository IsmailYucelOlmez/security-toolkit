#!/usr/bin/env python3
"""Rapor dizininde test kullanıcısı token'ı arar. ::add-mask:: yalnızca logları korur, artifact'leri korumaz.

Kullanım: redact_tokens.py <dizin> [--check]
Ortam değişkenleri: AUTH_HEADER_A, AUTH_HEADER_B (Authorization değerleri, ör. "Bearer abc")

Varsayılan olarak token'ları dosyalarda maskeler. --check ile dosyaya dokunmaz, token bulursa
başarısız olur. Token değerleri hiçbir zaman yazdırılmaz.
Çıkış kodu: 0 = temiz veya maskelendi, 1 = --check token buldu
"""
import argparse
import base64
import os
from pathlib import Path
from urllib.parse import quote

MASK = b"[Filtered]"


def tokens():
    values = (os.environ.get(name, "") for name in ("AUTH_HEADER_A", "AUTH_HEADER_B"))
    found = set()
    for value in values:
        if value.strip():
            # "Bearer abc" başlığında sızıntı yalnızca abc olarak da görünebilir; rapor biçimi kodlamış da olabilir
            for raw in (value.strip(), value.split()[-1]):
                found |= {raw.encode(), quote(raw, safe="").encode(), base64.b64encode(raw.encode()),
                          base64.urlsafe_b64encode(raw.encode()).rstrip(b"=")}
    # Uzun olan önce: başlığın tamamı, içindeki token'dan önce maskelenmeli
    return sorted(found, key=len, reverse=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("directory")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()

    secrets = tokens()
    found = []
    for path in sorted(p for p in Path(args.directory).rglob("*") if p.is_file()):
        data = path.read_bytes()
        if not any(secret in data for secret in secrets):
            continue
        found.append(path)
        if not args.check:
            for secret in secrets:
                data = data.replace(secret, MASK)
            path.write_bytes(data)

    if args.check and found:
        print(f"::error::Raporlarda test kullanıcısı token'ı var; artifact yüklenmeyecek: {', '.join(map(str, found))}")
        raise SystemExit(1)
    print(f"Token içeren dosya: {len(found)}" + (" (maskelendi)" if found else ""))


if __name__ == "__main__":
    main()
