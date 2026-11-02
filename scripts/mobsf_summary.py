#!/usr/bin/env python3
"""MobSF puan kartından iş özeti yazar. Flutter'ın yanlış pozitif olarak belgelediği bulguları ayıklar.

Kullanım: mobsf_summary.py <mobsf-scorecard.json>
libapp.so Dart'tan derlenir; RELRO, stack canary ve fortify gibi yerel derleme korumaları ona uygulanmaz:
https://docs.flutter.dev/reference/security-false-positives
"""
import json
import re
import sys

HARDENING = re.compile(r"relro|canar|fortif|stack|symbols|strip|\bpie\b|\bnx\b", re.I)


def flutter_false_positive(item) -> bool:
    text = " ".join(str(item.get(key, "")) for key in ("title", "description", "section"))
    return "libapp.so" in text and bool(HARDENING.search(text))


def main():
    with open(sys.argv[1], encoding="utf-8") as fh:
        card = json.load(fh)
    high = card.get("high", [])
    warning = card.get("warning", [])
    real_high = [i for i in high if not flutter_false_positive(i)]
    real_warning = [i for i in warning if not flutter_false_positive(i)]
    dropped = len(high) + len(warning) - len(real_high) - len(real_warning)
    print("## 📱 MobSF\n")
    print(f"Güvenlik puanı: **{card.get('security_score', '?')}/100** · yüksek: **{len(real_high)}** · uyarı: **{len(real_warning)}**\n")
    if dropped:
        print(f"_Flutter'ın yanlış pozitif olarak belgelediği {dropped} `libapp.so` bulgusu ayıklandı; puan MobSF'in kendi hesabıdır._\n")
    for item in real_high[:15]:
        print(f"- 🟠 {item.get('title')} ({item.get('section', '')})")
    print("\nMobSF Dart mantığını analiz etmez; temiz sonuç uygulama kodunun güvenli olduğunu göstermez.")


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    main()
