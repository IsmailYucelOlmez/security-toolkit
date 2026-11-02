#!/usr/bin/env python3
"""Schemathesis JUnit raporundan iş özeti yazar ve yetki hatalarında işi başarısız yapar.

Kullanım: schemathesis_report.py <rapor-dizini> <schemathesis-çıkış-kodu> [--peers] [--openapi URL]

Çıkış kodu: 0 = yetki hatası yok, 1 = yetki hatası var veya tarama çalışamadı
Diğer kontrollerin bulguları yalnızca raporlanır, işi başarısız yapmaz.
"""
import argparse
import glob
import json
import os
import urllib.request
import xml.etree.ElementTree as ET

AUTHZ_CODES = {
    "ST401": "kimlik doğrulaması uygulanmıyor",
    "ST402": "başka kullanıcının nesnesi okunabiliyor (IDOR)",
}


HTTP_METHODS = {"get", "put", "post", "delete", "patch"}


def undeclared_operations(url):
    """Şemada güvenlik bildirmeyen işlemler: ST401 bunlar için sonuç üretmeyebilir."""
    try:
        with urllib.request.urlopen(url, timeout=30) as resp:
            schema = json.load(resp)
    except (OSError, ValueError):
        return None
    default = schema.get("security")
    return sorted(f"{method.upper()} {path}" for path, item in (schema.get("paths") or {}).items()
                  for method, op in item.items()
                  if method in HTTP_METHODS and not op.get("security", default))


def read_junit(report_dir):
    tests = failures = errors = 0
    authz = []
    paths = glob.glob(os.path.join(report_dir, "*.xml"))
    if not paths:
        return None
    for path in paths:
        try:
            root = ET.parse(path).getroot()
        except ET.ParseError:
            return None
        for suite in root.iter("testsuite"):
            tests += int(suite.get("tests", 0))
            failures += int(suite.get("failures", 0))
            errors += int(suite.get("errors", 0))
        for case in root.iter("testcase"):
            for failure in case.findall("failure"):
                for code in (failure.get("message") or "").split(", "):
                    if code in AUTHZ_CODES and (case.get("name"), code) not in authz:
                        authz.append((case.get("name"), code))
    return tests, failures, errors, authz


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("report_dir")
    parser.add_argument("rc", type=int)
    parser.add_argument("--peers", action="store_true")
    parser.add_argument("--openapi", default="")
    args = parser.parse_args()

    report = read_junit(args.report_dir)
    print("## 🧪 Schemathesis\n")
    # Rapor yoksa veya hiçbir işlem sınanmadıysa çıkış kodu 0 olsa bile temiz sonuç çıkarılamaz
    unusable = report is None or report[0] == 0
    tests, failures, errors, authz = report or (0, 0, 0, [])
    print(f"İşlem sayısı: **{tests}** · başarısız: **{failures}** · hata: **{errors}**\n")

    if args.rc > 1 or unusable:
        print(f"🔴 **Tarama çalışamadı** (çıkış kodu {args.rc}): şema yüklenemedi, yapılandırma hatalı, "
              "rapor okunamadı veya hiçbir işlem test edilmedi.\n")
    if authz:
        print("### 🔴 Yetki hataları\n")
        for name, code in authz:
            print(f"- `{name}` — {code}: {AUTHZ_CODES[code]}")
        print()
    elif args.peers and args.rc <= 1:
        print("IDOR bulgusu yok. API nesne oluşturamıyorsa kontrolün sınayacak kaydı olmaz; "
              "oluşturma uçlarının başarılı olduğunu rapordan doğrulayın.\n")
    if not args.peers:
        print("⚠️ İkinci test kullanıcısı tanımlı değil: **IDOR kontrolü çalışmadı.**\n")
    undeclared = undeclared_operations(args.openapi) if args.openapi else []
    if undeclared:
        print("⚠️ Şu uçlar şemada güvenlik bildirmiyor; kimlik doğrulama kontrolü (ST401) bunlar için sonuç "
              "üretmeyebilir. Herkese açık değillerse `Depends(...)` yanında güvenlik şemasını da bildirin:\n")
        print("\n".join(f"- `{name}`" for name in undeclared[:30]) + "\n")
    print("Başarısız durumların yeniden üretim adımları artifact içindeki JUnit raporunda.")

    raise SystemExit(1 if authz or args.rc > 1 or unusable else 0)


if __name__ == "__main__":
    main()
