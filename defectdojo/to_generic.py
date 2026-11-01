#!/usr/bin/env python3
"""findings.json'daki seçili araçların bulgularını DefectDojo 'Generic Findings Import' JSON'una çevirir.

Bulgu yoksa boş çıktı üretir (upload.sh boş dosyayı yüklemez).
"""
import argparse
import json
import sys

SEV = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low", "info": "Info"}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("findings")
    ap.add_argument("--tools", default="", help="virgülle araç adları; boşsa hepsi")
    a = ap.parse_args()
    tools = {t for t in a.tools.split(",") if t}
    data = json.load(open(a.findings, encoding="utf-8"))
    out = []
    for f in data.get("findings", []):
        if tools and f["tool"] not in tools:
            continue
        cves = [i for i in f.get("ids", []) if i.startswith("CVE-")]
        item = {
            "title": f["title"][:500],
            "severity": SEV.get(f["severity"], "Medium"),
            "description": f.get("detail") or f["title"],
            "file_path": f.get("file") or None,
            "line": f.get("line") or None,
            "component_name": f.get("package") or None,
            "component_version": f.get("version") or None,
            "mitigation": f"{f['fixed_version']} sürümüne yükseltin" if f.get("fixed_version") else None,
            "references": f.get("url") or None,
            "vuln_id_from_tool": f.get("rule_id"),
            "unique_id_from_tool": f"{f['tool']}:{f.get('rule_id')}:{f.get('file')}:{f.get('package')}",
        }
        if cves:
            item["cve"] = cves[0]
        out.append({k: v for k, v in item.items() if v is not None})
    if out:
        json.dump({"findings": out}, sys.stdout, ensure_ascii=False, indent=2)


if __name__ == "__main__":
    main()
