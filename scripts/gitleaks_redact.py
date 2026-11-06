#!/usr/bin/env python3
"""Gitleaks'in maskesiz raporunu maskeler; Supabase JWT'lerinin rolünü maskelemeden önce kaydeder.

  gitleaks_redact.py <ham-rapor> <çıktı>

--redact ile sır rapora hiç yazılmaz ve anon anahtarı service_role anahtarından ayrılamaz.
Ham rapor rapor dizini dışında tutulmalı ve bu betikten sonra silinmelidir. Sır hiçbir zaman yazdırılmaz.
Yalnızca standart kütüphane kullanır.
"""
from __future__ import annotations

import base64
import json
import sys
from pathlib import Path

MASK = "REDACTED"
SUPABASE_ROLES = {"anon", "service_role"}


def supabase_role(secret: str) -> str:
    """Supabase'in imzaladığı JWT ise rolünü döner; imza doğrulanmaz, yalnızca sınıflandırma içindir."""
    parts = secret.split(".")
    if len(parts) != 3 or not parts[0].startswith("ey"):
        return ""
    try:
        payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4)))
    except ValueError:
        return ""
    if not isinstance(payload, dict) or "supabase" not in str(payload.get("iss", "")):
        return ""
    role = payload.get("role")
    return role if role in SUPABASE_ROLES else ""


def redact(findings: list) -> list:
    for r in findings:
        secret = r.get("Secret") or ""
        role = supabase_role(secret)
        if role:
            r["SupabaseRole"] = role
        for key in ("Match", "Line"):
            if secret and isinstance(r.get(key), str):
                r[key] = r[key].replace(secret, MASK)
        r["Secret"] = MASK
    return findings


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__, file=sys.stderr)
        return 2
    raw, out = Path(sys.argv[1]), Path(sys.argv[2])
    data = json.loads(raw.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        print("gitleaks raporu liste değil", file=sys.stderr)
        return 1
    tmp = out.with_suffix(".tmp")
    tmp.write_text(json.dumps(redact(data), ensure_ascii=False, indent=1), encoding="utf-8")
    tmp.replace(out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
