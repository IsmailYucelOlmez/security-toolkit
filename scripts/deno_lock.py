#!/usr/bin/env python3
"""OSV-Scanner ve Trivy deno.lock okumaz; paketleri onların anlayacağı biçime aktarır.

  deno_lock.py npm <deno.lock> <package-lock.json>   npm paketlerini yazar, "npm jsr uzak" sayılarını basar
  deno_lock.py sbom <sbom.cdx.json> <deno.lock>...   paketleri CycloneDX bileşeni olarak ekler

Yalnızca standart kütüphane kullanır.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from urllib.parse import quote


def split_spec(key: str) -> tuple[str, str]:
    """'@a/b@1.2.0_c@3.0.0' -> ('@a/b', '1.2.0'); alt çizgiden sonrası npm eş bağımlılığıdır."""
    at = key.find("@", 1)
    if at < 0 or at == len(key) - 1:
        raise ValueError(f"paket kaydı tanınmadı: {key}")
    return key[:at], key[at + 1:].split("_")[0]


def read_lock(path: Path) -> tuple[list[tuple[str, str]], list[tuple[str, str]], int]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or int(data.get("version", 0)) < 3:
        raise ValueError(f"desteklenmeyen deno.lock sürümü: {data.get('version') if isinstance(data, dict) else '?'}")
    # v3 paketleri "packages" altında, v4 ve sonrası kökte tutar
    section = data.get("packages", data)
    npm, jsr = section.get("npm", {}), section.get("jsr", {})
    return sorted({split_spec(k) for k in npm}), sorted({split_spec(k) for k in jsr}), len(data.get("remote", {}))


def to_package_lock(packages: list[tuple[str, str]]) -> dict:
    """Aynı paketin farklı sürümleri aynı yola yazılamaz; sonraki sürümler iç içe yola konur.

    OSV-Scanner `resolved` alanı olmayan kaydı hata vermeden açık sorgusuna katmaz.
    """
    entries = {"": {"name": "deno-lock", "version": "0.0.0"}}
    for i, (name, version) in enumerate(packages):
        path = f"node_modules/{name}"
        if path in entries:
            path = f"node_modules/.deno-{i}/node_modules/{name}"
        tarball = name.rsplit("/", 1)[-1]
        entries[path] = {"version": version, "resolved": f"https://registry.npmjs.org/{name}/-/{tarball}-{version}.tgz"}
    return {"name": "deno-lock", "version": "0.0.0", "lockfileVersion": 3, "requires": True, "packages": entries}


def add_to_sbom(sbom: dict, locks: list[Path]) -> None:
    components = sbom.setdefault("components", [])
    seen = {(c.get("name"), c.get("version")) for c in components}
    for lock in locks:
        npm, jsr, _ = read_lock(lock)
        for name, version in npm:
            if (name, version) not in seen:
                seen.add((name, version))
                purl = f"pkg:npm/{quote(name, safe='/')}@{version}"
                components.append({"bom-ref": purl, "type": "library", "name": name, "version": version, "purl": purl})
        for name, version in jsr:
            if (name, version) not in seen:  # purl tanımında jsr türü yok
                seen.add((name, version))
                components.append({"bom-ref": f"jsr:{name}@{version}", "type": "library", "name": name, "version": version})


def main(argv: list[str]) -> int:
    if len(argv) >= 3 and argv[0] == "npm":
        npm, jsr, remote = read_lock(Path(argv[1]))
        Path(argv[2]).write_text(json.dumps(to_package_lock(npm), indent=2), encoding="utf-8")
        sys.stdout.write(f"{len(npm)} {len(jsr)} {remote}")
        return 0
    if len(argv) >= 3 and argv[0] == "sbom":
        path = Path(argv[1])
        sbom = json.loads(path.read_text(encoding="utf-8"))
        add_to_sbom(sbom, [Path(p) for p in argv[2:]])
        path.write_text(json.dumps(sbom, indent=2), encoding="utf-8")
        return 0
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")  # Windows kod sayfası Türkçe metinde bozulmasın
    try:
        sys.exit(main(sys.argv[1:]))
    except (OSError, ValueError, TypeError, AttributeError) as exc:  # json.JSONDecodeError bir ValueError'dır
        print(f"[deno_lock] {type(exc).__name__}: {exc}", file=sys.stderr)
        sys.exit(1)
