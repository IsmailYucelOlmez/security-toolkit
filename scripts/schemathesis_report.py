#!/usr/bin/env python3
"""Schemathesis JUnit raporundan iş özeti yazar ve yetki hatalarında işi başarısız yapar.

Kullanım: schemathesis_report.py <rapor-dizini> <schemathesis-çıkış-kodu> [--peers]

Çıkış kodu: 0 = yetki hatası yok, 1 = yetki hatası var veya tarama çalışamadı
Diğer kontrollerin bulguları yalnızca raporlanır, işi başarısız yapmaz.
"""
import argparse
import glob
import os
import xml.etree.ElementTree as ET

AUTHZ_CODES = {
    "ST401": "kimlik doğrulaması uygulanmıyor",
    "ST402": "başka kullanıcının nesnesi okunabiliyor (IDOR)",
}


def read_junit(report_dir):
    tests = failures = errors = 0
    authz = []
    for path in glob.glob(os.path.join(report_dir, "*.xml")):
        root = ET.parse(path).getroot()
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
    args = parser.parse_args()

    tests, failures, errors, authz = read_junit(args.report_dir)
    print("## 🧪 Schemathesis\n")
    print(f"İşlem sayısı: **{tests}** · başarısız: **{failures}** · hata: **{errors}**\n")

    if args.rc > 1:
        print(f"🔴 **Tarama çalışamadı** (çıkış kodu {args.rc}): şema yüklenemedi, yapılandırma hatalı "
              "veya hiçbir işlem test edilmedi.\n")
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
    print("Başarısız durumların yeniden üretim adımları artifact içindeki JUnit raporunda.")

    raise SystemExit(1 if authz or args.rc > 1 else 0)


if __name__ == "__main__":
    main()
