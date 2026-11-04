#!/usr/bin/env python3
"""Araç çıktılarını ortak bir bulgu formatına çevirir, tekrarları ayıklar,
.security-ignore.yml ile bastırılanları düşer ve şunları yazar:

  findings.json   normalize bulgular (skill / diğer araçlar için)
  findings.sarif  GitHub Code Scanning'e yüklenebilir SARIF 2.1.0
  summary.md      insan okuyabilir özet (PR yorumu ve iş özeti)

Yalnızca standart kütüphane kullanır.
"""
from __future__ import annotations

import argparse
import datetime as dt
import fnmatch
import glob
import hashlib
import json
import os
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

SEVERITIES = ["critical", "high", "medium", "low", "info"]
RANK = {s: i for i, s in enumerate(SEVERITIES)}
EMOJI = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}
TOOL_NAMES = {
    "gitleaks": "Gitleaks (sırlar)",
    "osv": "OSV-Scanner (bağımlılıklar)",
    "osv-deno": "OSV-Scanner (deno.lock)",
    "pip-audit": "pip-audit (Python bağımlılıkları)",
    "bandit": "Bandit (Python SAST)",
    "semgrep": "Semgrep (SAST)",
    "supabase": "Supabase (RLS, Edge Functions)",
    "trivy": "Trivy (altyapı yapılandırması)",
    "dotnet": "dotnet (NuGet bağımlılıkları)",
    "dependencies": "Bağımlılık kapsamı",
    "sbom": "SBOM (CycloneDX)",
    "trivy-image": "Trivy (konteyner imajı)",
    "tarama": "Tarama",
}
EXPIRY_WARNING_DAYS = 30
EXIT_THRESHOLD = 1
EXIT_INCOMPLETE = 3  # 2 scan.sh'in kullanım hatasıdır
INCOMPLETE_STATUSES = {"missing", "error", "partial"}
# Araç "ok" dese bile bu anahtar yoksa çıktı biçimi değişmiş olabilir; sıfır bulgu sayılmamalı
REPORT_KEYS = {"osv": "results", "osv-deno": "results", "bandit": "results", "semgrep": "results",
               "pip-audit": "dependencies", "dotnet": "projects", "sbom": "bomFormat", "zap": "site",
               "supabase": "results"}
REPORT_FILES = {"gitleaks": "gitleaks.json", "osv": "osv.json", "osv-deno": "osv-deno-*.json",
                "bandit": "bandit.json", "semgrep": "semgrep.json",
                "trivy": "trivy.json", "pip-audit": "pip-audit-*.json", "dotnet": "dotnet-*.json",
                "sbom": "sbom.cdx.json", "trivy-image": "trivy-image.json", "zap": "zap.json",
                "mobsf": "mobsf-scorecard.json", "supabase": "supabase.json"}
ZAP_RISK = {"3": "high", "2": "medium", "1": "low", "0": "info"}


def load_json(path: Path):
    try:
        text = path.read_text(encoding="utf-8").strip()
        return json.loads(text) if text else None
    except (OSError, json.JSONDecodeError) as exc:
        print(f"[summarize] {path.name} okunamadı: {exc}", file=sys.stderr)
        return None


def report_problem(data, tool) -> str | None:
    if data is None:
        return "rapor boş veya okunamadı"
    expected = list if tool == "gitleaks" else dict
    if not isinstance(data, expected) or (tool in REPORT_KEYS and REPORT_KEYS[tool] not in data):
        return "rapor biçimi tanınmadı"
    return None


def read_report(path: Path, tool, parse, target, problems, *extra):
    """Raporu ayrıştırır; sorun varsa bulgu dönmez, araç için problems'e not düşer."""
    data = load_json(path)
    problem = report_problem(data, tool)
    if not problem:
        try:
            return data, list(parse(data, target, *extra))
        except (AttributeError, KeyError, TypeError, ValueError) as exc:
            problem = f"rapor ayrıştırılamadı: {type(exc).__name__}"
    problems[tool] = f"{path.name}: {problem}"
    return None, []


def rel(path: str | None, target: Path) -> str:
    if not path:
        return ""
    p = Path(path)
    try:
        return (p.resolve().relative_to(target) if p.is_absolute() else p).as_posix()
    except ValueError:
        return p.as_posix()


def cvss_to_sev(score) -> str | None:
    try:
        s = float(score)
    except (TypeError, ValueError):
        return None
    if s >= 9.0:
        return "critical"
    if s >= 7.0:
        return "high"
    if s >= 4.0:
        return "medium"
    if s > 0:
        return "low"
    return None


def word_to_sev(word) -> str | None:
    w = str(word or "").strip().lower()
    return {
        "critical": "critical", "high": "high", "error": "high",
        "medium": "medium", "moderate": "medium", "warning": "medium",
        "low": "low", "info": "info", "informational": "info", "note": "info",
    }.get(w)


def finding(tool, rule_id, severity, title, *, file="", line=None, package="",
            version="", fixed="", ids=None, url="", detail=""):
    return {
        "tool": tool, "rule_id": rule_id, "severity": severity or "medium",
        "title": title.strip() if title else rule_id, "file": file, "line": line,
        "package": package, "version": version, "fixed_version": fixed,
        "ids": sorted({i for i in (ids or []) if i}), "url": url, "detail": detail,
    }


# ------------------------------------------------------------------ ayrıştırıcılar
SUPABASE_KEYS = {
    "anon": ("low", "Supabase anon anahtarı: istemciye verilmek için üretilir, korumayı RLS politikaları sağlar"),
    "service_role": ("critical", "Supabase service_role anahtarı sızmış: RLS'i atlar, anahtarı hemen yenileyin"),
}


def parse_gitleaks(data, target):
    for r in data or []:
        severity, title = SUPABASE_KEYS.get(
            r.get("SupabaseRole"), ("critical", f"Sızdırılmış sır: {r.get('Description') or r.get('RuleID')}"))
        yield finding(
            "gitleaks", r.get("RuleID", "secret"), severity, title,
            file=rel(r.get("File"), target), line=r.get("StartLine"),
            ids=[r.get("Fingerprint")],
            detail=f"commit {r['Commit'][:10]}" if r.get("Commit") else "",
        )


def _osv_fixed(vulns, pkg_name):
    """Her sürüm dalının düzeltmesi; mevcut sürüme uyanı best_fix seçer."""
    fixes = []
    for v in vulns:
        for aff in v.get("affected", []):
            if aff.get("package", {}).get("name", "").lower() != pkg_name.lower():
                continue
            for rng in aff.get("ranges", []):
                for ev in rng.get("events", []):
                    if ev.get("fixed") and ev["fixed"] not in fixes:
                        fixes.append(ev["fixed"])
    return ", ".join(fixes)


def parse_osv(data, target, source=""):
    for res in (data or {}).get("results", []):
        src = source or rel(res.get("source", {}).get("path"), target)
        for pkg in res.get("packages", []):
            info = pkg.get("package", {})
            vulns = {v["id"]: v for v in pkg.get("vulnerabilities", [])}
            groups = pkg.get("groups") or [{"ids": [i]} for i in vulns]
            for g in groups:
                gv = [vulns[i] for i in g.get("ids", []) if i in vulns]
                sev = cvss_to_sev(g.get("max_severity"))
                if not sev:
                    sev = next((word_to_sev(v.get("database_specific", {}).get("severity"))
                                for v in gv if v.get("database_specific", {}).get("severity")), None)
                ids = set(g.get("ids", [])) | set(g.get("aliases", []))
                for v in gv:
                    ids |= set(v.get("aliases", []))
                main = sorted(ids, key=lambda x: (not x.startswith("CVE-"), not x.startswith("GHSA-"), x))[0]
                summary = next((v.get("summary") for v in gv if v.get("summary")), "")
                yield finding(
                    "osv", main, sev or "medium",
                    f"{info.get('name')} {info.get('version')}: {summary or main}",
                    file=src, package=info.get("name", ""), version=info.get("version", ""),
                    fixed=_osv_fixed(gv, info.get("name", "")), ids=list(ids),
                    url=f"https://osv.dev/vulnerability/{g.get('ids', [main])[0]}",
                )


def parse_pip_audit(data, target, source=""):
    for dep in (data or {}).get("dependencies", []):
        for v in dep.get("vulns", []):
            yield finding(
                "pip-audit", v["id"], "medium",  # pip-audit önem derecesi vermez; OSV ile eşleşirse oradan alınır
                f"{dep['name']} {dep.get('version', '')}: {v['id']}",
                file=source, package=dep["name"], version=dep.get("version", ""),
                fixed=", ".join(v.get("fix_versions", [])), ids=[v["id"], *v.get("aliases", [])],
                url=f"https://osv.dev/vulnerability/{v['id']}",
                detail=(v.get("description") or "")[:300],
            )


def parse_bandit(data, target):
    for r in (data or {}).get("results", []):
        sev = word_to_sev(r.get("issue_severity")) or "medium"
        if str(r.get("issue_confidence", "")).upper() == "LOW" and sev != "low":
            sev = SEVERITIES[min(RANK[sev] + 1, RANK["low"])]  # düşük güvende bir kademe indir
        cwe = (r.get("issue_cwe") or {}).get("id")
        yield finding(
            "bandit", r.get("test_id", ""), sev,
            f"{r.get('test_name', '')}: {r.get('issue_text', '')}",
            file=rel(r.get("filename"), target), line=r.get("line_number"),
            ids=[f"CWE-{cwe}"] if cwe else [], url=r.get("more_info", ""),
        )


def parse_semgrep(data, target):
    for r in (data or {}).get("results", []):
        extra = r.get("extra", {})
        meta = extra.get("metadata", {}) or {}
        sev = word_to_sev(extra.get("severity")) or "medium"
        if meta.get("impact") and meta.get("confidence"):
            # Kayıt defteri kuralları için etki/güven bilgisi varsa daha isabetli derece
            sev = word_to_sev(meta["impact"]) or sev
        cwes = meta.get("cwe") or []
        cwes = [cwes] if isinstance(cwes, str) else cwes
        yield finding(
            "semgrep", r.get("check_id", ""), sev, extra.get("message", ""),
            file=rel(r.get("path"), target), line=r.get("start", {}).get("line"),
            ids=[c.split(":")[0] for c in cwes],
            url=(meta.get("references") or [""])[0] if isinstance(meta.get("references"), list) else "",
        )


def semgrep_partial_note(data, target) -> str:
    """Kısmen okunan dosya taramayı eksik saydırmaz ama "ok" satırında görünmeli."""
    paths = sorted({rel(e["path"], target) for e in (data or {}).get("errors", []) if e.get("path")})
    if not paths:
        return ""
    return f"{len(paths)} dosya kısmen ayrıştırılamadı: " + ", ".join(paths[:3]) + ("…" if len(paths) > 3 else "")


def parse_supabase(data, target):
    for r in (data or {}).get("results", []):
        yield finding("supabase", r.get("rule_id", ""), r.get("severity"), r.get("title", ""),
                      file=r.get("file", ""), line=r.get("line"))


def parse_trivy(data, target):
    for res in (data or {}).get("Results", []) or []:
        for m in res.get("Misconfigurations", []) or []:
            if m.get("Status", "FAIL") != "FAIL":
                continue
            yield finding(
                "trivy", m.get("AVDID") or m.get("ID", ""), word_to_sev(m.get("Severity")),
                f"{m.get('Title', '')}: {m.get('Message', '')}",
                file=rel(res.get("Target"), target),
                line=(m.get("CauseMetadata") or {}).get("StartLine"),
                ids=[m.get("ID"), m.get("AVDID")], url=m.get("PrimaryURL", ""),
            )


def parse_trivy_image(data, target):
    for res in (data or {}).get("Results", []) or []:
        for v in res.get("Vulnerabilities", []) or []:
            yield finding(
                "trivy-image", v.get("VulnerabilityID", ""), word_to_sev(v.get("Severity")),
                f"{v.get('PkgName')} {v.get('InstalledVersion', '')}: {v.get('Title') or v.get('VulnerabilityID')}",
                file=res.get("Target", ""), package=v.get("PkgName", ""), version=v.get("InstalledVersion", ""),
                fixed=v.get("FixedVersion", ""), ids=[v.get("VulnerabilityID")], url=v.get("PrimaryURL", ""),
            )


def parse_zap(data, target):
    for site in (data or {}).get("site", []):
        for a in site.get("alerts", []):
            instances = a.get("instances") or [{}]
            yield finding(
                "zap", f"zap-{a.get('pluginid', '')}", ZAP_RISK.get(str(a.get("riskcode")), "medium"), a.get("name", ""),
                file=instances[0].get("uri", site.get("@name", "")), ids=[f"CWE-{a['cweid']}"] if a.get("cweid") else [],
                detail=f"{a.get('count', len(instances))} örnek",
            )


def parse_mobsf(data, target):
    from mobsf_summary import flutter_false_positive
    for key, sev in (("high", "high"), ("warning", "medium")):
        for item in (data or {}).get(key, []):
            if not flutter_false_positive(item):
                title = str(item.get("title", ""))
                yield finding("mobsf", f"mobsf-{item.get('section', 'genel')}", sev, title, file=str(item.get("section", "")))


def parse_schemathesis(path: Path):
    """JUnit raporundaki başarısız kontroller; yetki kodları yüksek, diğerleri düşük derecelidir."""
    from schemathesis_report import AUTHZ_CODES
    root = ET.parse(path).getroot()
    for case in root.iter("testcase"):
        for failure in case.findall("failure"):
            for code in (failure.get("message") or "").split(", "):
                yield finding("schemathesis", code or "schemathesis", "high" if code in AUTHZ_CODES else "low",
                              f"{case.get('name')}: {AUTHZ_CODES.get(code, code)}", file=case.get("name") or "")


def parse_dotnet(data, target):
    for proj in (data or {}).get("projects", []):
        for fw in proj.get("frameworks", []):
            for kind in ("topLevelPackages", "transitivePackages"):
                for p in fw.get(kind, []):
                    for v in p.get("vulnerabilities", []):
                        url = v.get("advisoryurl", "")
                        ghsa = re.search(r"GHSA-[\w-]+", url)
                        yield finding(
                            "dotnet", ghsa.group(0) if ghsa else url, word_to_sev(v.get("severity")),
                            f"{p['id']} {p.get('resolvedVersion', '')}: bilinen açık"
                            + (" (dolaylı bağımlılık)" if kind == "transitivePackages" else ""),
                            file=rel(proj.get("path"), target), package=p["id"],
                            version=p.get("resolvedVersion", ""), ids=[ghsa.group(0)] if ghsa else [], url=url,
                        )


# ------------------------------------------------------------------ tekrar ayıklama
def norm_pkg(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name.lower())


def drop_unresolved_osv(findings, resolved):
    """OSV, requirements dosyasındaki `>=` aralığını alt sınır sürüm gibi okur; kurulacak sürümü pip-audit çözer.

    Aynı dosyada sürümler farklıysa OSV bulgusu kurulmayacak bir sürüme aittir ve düşürülür. Sürüm
    sabitlenmişse ikisi aynı sürümü görür, bulgu korunur. pip-audit raporu yoksa da korunur.
    """
    kept, dropped = [], []
    for f in findings:
        got = resolved.get(f["file"], {}).get(norm_pkg(f["package"]))
        (dropped if f["tool"] == "osv" and got and got != f["version"] else kept).append(f)
    for d in dropped:
        # pip-audit derece vermez; açık kurulacak sürümde de varsa OSV'nin derecesi korunmalı
        for f in kept:
            if (f["tool"] == "pip-audit" and f["file"] == d["file"] and norm_pkg(f["package"]) == norm_pkg(d["package"])
                    and set(f["ids"]) & set(d["ids"])):
                f["severity"] = d["severity"]
    return kept, dropped


def dedupe(findings):
    """Aynı paket sürümü+açık birden çok araçtan gelirse tek kayda indirger, en yüksek dereceyi tutar."""
    out, index, sites = [], {}, set()
    for f in findings:
        # Semgrep iç içe .replaceAll() zincirinde aynı satırı her çağrı için ayrı raporlar
        if f["tool"] == "semgrep":
            site = (f["rule_id"], f["file"], f["line"])
            if site in sites:
                continue
            sites.add(site)
        f = {**f, "also_found_by": [], "locations": [f["file"]] if f["file"] else []}
        if not (f["package"] and f["ids"]):
            out.append(f)
            continue
        pkg = (norm_pkg(f["package"]), f["version"])  # farklı sürümlerin düzeltmesi de ayrıdır
        hit = next((index[(pkg, i)] for i in f["ids"] if (pkg, i) in index), None)
        if hit is None:
            out.append(f)
            hit = len(out) - 1
        else:
            cur = out[hit]
            # pip-audit derece vermediği için diğer araçların kaydı esas alınır
            base, other = (f, cur) if cur["tool"] == "pip-audit" and f["tool"] != "pip-audit" else (cur, f)
            rated = [x["severity"] for x in (cur, f) if x["tool"] != "pip-audit"] or [base["severity"]]
            merged = {**base,
                      "severity": min(rated, key=lambda s: RANK[s]),
                      "ids": sorted(set(cur["ids"]) | set(f["ids"])),
                      "fixed_version": base["fixed_version"] or other["fixed_version"]}
            merged["also_found_by"] = sorted({cur["tool"], f["tool"], *cur["also_found_by"]} - {merged["tool"]})
            # Aynı açık başka manifestte de olabilir; tek kayda insek de hiçbir konum kaybolmamalı
            merged["locations"] = sorted(set(cur["locations"]) | set(f["locations"]))
            out[hit] = merged
        for i in out[hit]["ids"]:
            index[(pkg, i)] = hit
    return out


def vkey(v: str):
    return [int(x) if x.isdigit() else -1 for x in re.split(r"[^0-9A-Za-z]+", v or "") if x != ""]


def best_fix(current: str, fixes: list[str]) -> str:
    """Her açık için mevcut sürümden büyük en küçük düzeltmeyi seçer, sonra bunların en büyüğünü döner."""
    picks = []
    for entry in fixes:
        cands = sorted((c.strip() for c in entry.split(",") if c.strip()), key=vkey)
        if not cands:
            continue
        newer = [c for c in cands if vkey(c) > vkey(current)]
        picks.append(newer[0] if newer else cands[-1])
    return max(picks, key=vkey) if picks else ""


def group_by_package(findings):
    """Aynı paketin birden çok açığını tek bulguya indirger: 'requests 2.19.0: 5 açık → 2.33.0'."""
    out, pos = [], {}
    for f in findings:
        if not f["package"]:
            out.append(f)
            continue
        key = (f["tool"], norm_pkg(f["package"]), f["version"], f["file"])
        if key not in pos:
            pos[key] = len(out)
            out.append({**f, "vulnerabilities": [f["rule_id"]], "_fixes": [f["fixed_version"]]})
            continue
        g = out[pos[key]]
        g["vulnerabilities"].append(f["rule_id"])
        g["ids"] = sorted(set(g["ids"]) | set(f["ids"]))
        g["_fixes"].append(f["fixed_version"])
        g["also_found_by"] = sorted(set(g["also_found_by"]) | set(f["also_found_by"]))
        g["locations"] = sorted(set(g["locations"]) | set(f["locations"]))
        if RANK[f["severity"]] < RANK[g["severity"]]:
            g["severity"] = f["severity"]
    for g in out:
        fixes = g.pop("_fixes", None)
        if fixes is None:
            continue
        g["fixed_version"] = best_fix(g["version"], fixes)
        n = len(g["vulnerabilities"])
        if n > 1:
            shown = ", ".join(g["vulnerabilities"][:3]) + ("…" if n > 3 else "")
            g["title"] = f"{g['package']} {g['version']}: {n} bilinen açık ({shown})"
        g["rule_id"] = f"vulnerable-dependency/{norm_pkg(g['package'])}"
    return out


def add_fingerprints(findings):
    """Satır kaymasından etkilenmeyen kimlik üretir; aynı dosyadaki aynı kural sıra numarasıyla ayrılır."""
    seen = {}
    for f in sorted(findings, key=lambda x: x["line"] or 0):
        if f["package"]:
            parts = [f["tool"], f["rule_id"], f["package"], f["version"], *f.get("locations", [f["file"]])]
        else:
            parts = [f["tool"], f["rule_id"], f["file"], f["title"]]
        key = "\0".join(str(p) for p in parts)
        seen[key] = seen.get(key, 0) + 1
        f["fingerprint"] = hashlib.sha256(f"{key}\0{seen[key]}".encode()).hexdigest()[:32]


def load_baseline(path: Path):
    """Taban taramasındaki parmak izleri. Okunamazsa None: bütün bulgular yeni sayılır."""
    data = load_json(path)
    if not isinstance(data, dict) or not isinstance(data.get("findings"), list):
        print(f"[summarize] Taban çizgisi okunamadı, tüm bulgular yeni sayılıyor: {path}", file=sys.stderr)
        return None
    return {f.get("fingerprint") for f in data["findings"]}


# ------------------------------------------------------------------ bastırma
def ignore_problem(it) -> str | None:
    """Uygulanamayacak kaydın nedenini döner. Bu kayıtlar bulguyu bastırmaz, raporda listelenir."""
    ident = str(it["id"])
    if ident.upper().startswith("CWE-"):
        return "CWE ile toplu bastırma yapılamaz; kural veya açık kimliği verin"
    if not ident.strip("*?[]"):
        return "id yalnızca joker karakter olamaz"
    if not it.get("reason"):
        return "reason zorunlu"
    if not it.get("expires"):
        return "expires zorunlu"
    try:
        dt.date.fromisoformat(str(it["expires"]))
    except ValueError:
        return f"expires geçersiz: {it['expires']} (YYYY-MM-DD olmalı)"
    return None


def load_ignores(target: Path):
    path = next((p for p in (target / ".security-ignore.yml", target / ".security-ignore.yaml") if p.exists()), None)
    if not path:
        return [], []
    try:
        import yaml  # type: ignore
        items = yaml.safe_load(path.read_text(encoding="utf-8")) or []
    except ImportError:
        items, cur = [], None
        for raw in path.read_text(encoding="utf-8").splitlines():
            line = raw.split(" #")[0].rstrip()
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            m = re.match(r"^\s*(-\s+)?([\w-]+):\s*(.*)$", line)
            if not m:
                continue
            if m.group(1):
                cur = {}
                items.append(cur)
            if cur is not None:
                cur[m.group(2)] = m.group(3).strip().strip("'\"")
    today = dt.date.today()
    active, issues = [], []
    for it in items:
        if not isinstance(it, dict) or not it.get("id"):
            issues.append({"id": "?", "status": "geçersiz", "detail": "id zorunlu"})
            continue
        ident = str(it["id"])
        problem = ignore_problem(it)
        if problem:
            issues.append({"id": ident, "status": "geçersiz", "detail": problem})
            continue
        expires = dt.date.fromisoformat(str(it["expires"]))
        if expires < today:
            issues.append({"id": ident, "status": "süresi doldu", "detail": str(expires)})
            continue
        if (expires - today).days <= EXPIRY_WARNING_DAYS:
            issues.append({"id": ident, "status": "süresi doluyor", "detail": str(expires)})
        active.append(it)
    return active, issues


def is_ignored(f, ignores):
    for it in ignores:
        ident = str(it["id"])
        # Semgrep kural kimliği dizinle başlar (rules.semgrep.ad); yalnızca kural adı da eşleşir
        if (ident != f["rule_id"] and ident not in f["ids"] and not fnmatch.fnmatch(f["rule_id"], ident)
                and not f["rule_id"].endswith("." + ident)):
            continue
        # Birleşmiş kayıtta başka konum kapsam dışındaysa bastırma açığı orada da gizlerdi
        if it.get("path") and not all(fnmatch.fnmatch(loc, str(it["path"])) for loc in f.get("locations") or [f["file"]]):
            continue
        if it.get("tool") and it["tool"] != f["tool"]:
            continue
        return it.get("reason", "gerekçe yok")
    return None


# ------------------------------------------------------------------ çıktılar
def to_sarif(findings):
    level = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
    score = {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "2.0", "info": "0.0"}
    runs = []
    for tool in sorted({f["tool"] for f in findings}):
        rules, results = {}, []
        for f in (x for x in findings if x["tool"] == tool):
            rid = f["rule_id"] or "unknown"
            rules.setdefault(rid, {
                "id": rid, "shortDescription": {"text": f["title"][:120]},
                "helpUri": f["url"] or None,
                "properties": {"security-severity": score[f["severity"]], "tags": ["security"]},
            })
            loc = {"physicalLocation": {"artifactLocation": {"uri": f["file"] or "."}}}
            if f["line"]:
                loc["physicalLocation"]["region"] = {"startLine": int(f["line"])}
            others = [{"physicalLocation": {"artifactLocation": {"uri": p}}} for p in f.get("locations", []) if p != f["file"]]
            msg = f["title"] + (f" → düzeltilmiş sürüm: {f['fixed_version']}" if f["fixed_version"] else "")
            result = {"ruleId": rid, "level": level[f["severity"]], "message": {"text": msg}, "locations": [loc, *others]}
            if f.get("fingerprint"):
                result["partialFingerprints"] = {"securityToolkit/v1": f["fingerprint"]}
            results.append(result)
        for r in rules.values():
            if not r["helpUri"]:
                del r["helpUri"]
        runs.append({"tool": {"driver": {"name": tool, "rules": list(rules.values())}}, "results": results})
    return {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0", "runs": runs}


def md_escape(s: str) -> str:
    return str(s).replace("|", "\\|").replace("\n", " ")


def to_markdown(active, ignored, statuses, stacks, fail_on, failed, unresolved=(), incomplete=(), ignore_issues=(), baseline=False):
    counts = {s: sum(1 for f in active if f["severity"] == s) for s in SEVERITIES}
    lines = ["## 🔐 Güvenlik taraması", ""]
    verdict = "❌ **Eşik aşıldı**" if failed else "⚠️ **Tarama eksik**" if incomplete else "✅ **Eşik aşılmadı**"
    lines.append(f"{verdict} — başarısızlık eşiği: `{fail_on}` · yığınlar: {', '.join(stacks) or '—'}")
    lines.append("")
    lines.append(" · ".join(f"{EMOJI[s]} {s}: **{counts[s]}**" for s in SEVERITIES if s != "info"))
    if baseline:
        fresh = sum(1 for f in active if f["new"])
        lines.append(f"\nTaban dala göre **{fresh} yeni**, {len(active) - fresh} mevcut bulgu. Eşik yalnızca yeni bulgulara uygulanır.")
    if incomplete:
        names = ", ".join(f"{TOOL_NAMES.get(t, t)} ({st})" for t, st, _ in incomplete)
        lines.append(f"\n**Şu araçlar tam çalışmadı:** {names}. Bu sonuç temiz tarama sayılmaz.")
    if ignored:
        lines.append(f"\n_{len(ignored)} bulgu `.security-ignore.yml` ile bastırıldı._")
    if unresolved:
        lines.append(f"\n_{len(unresolved)} OSV bulgusu atlandı: pip-audit bu paketleri başka sürüme çözdü."
                     " Sürümleri kilit dosyasıyla sabitlemek kurulumu tekrarlanabilir kılar._")
    if ignore_issues:
        lines.append("\n**Bastırma dosyasında dikkat gerektiren kayıtlar:**\n")
        lines += [f"- `{md_escape(i['id'])}`: {i['status']} ({md_escape(i['detail'])})" for i in ignore_issues]
    lines += ["", "<details><summary>Araç durumu</summary>", "", "| Araç | Durum | Not |", "|---|---|---|"]
    icon = {"ok": "✅", "partial": "⚠️", "skipped": "⏭️", "missing": "➖", "error": "❌"}
    for tool, st, note in statuses:
        lines.append(f"| {TOOL_NAMES.get(tool, tool)} | {icon.get(st, st)} {st} | {md_escape(note)} |")
    lines += ["", "</details>", ""]
    if active:
        lines += ["| Derece | Araç | Bulgu | Konum | Düzeltme |", "|---|---|---|---|---|"]
        for f in sorted(active, key=lambda x: (RANK[x["severity"]], x["tool"], x["file"]))[:100]:
            others = [p for p in f.get("locations", []) if p != f["file"]]
            where = f["file"] + (f":{f['line']}" if f["line"] else "") + "".join(f", {p}" for p in others[:3])
            where += f" +{len(others) - 3} konum" if len(others) > 3 else ""
            fix = f"`{f['fixed_version']}`" if f["fixed_version"] else ""
            title = f"[{md_escape(f['title'][:110])}]({f['url']})" if f["url"] else md_escape(f["title"][:110])
            mark = "🆕 " if baseline and f["new"] else ""
            lines.append(f"| {mark}{EMOJI[f['severity']]} {f['severity']} | {f['tool']} | {title} | `{md_escape(where)}` | {fix} |")
        if len(active) > 100:
            lines.append(f"\n_…ve {len(active) - 100} bulgu daha; tamamı `findings.json` içinde._")
    elif incomplete:
        lines.append("Çalışan araçlarda bulgu yok, ama tarama eksik.")
    else:
        lines.append("Bulgu yok. 🎉")
    return "\n".join(lines) + "\n"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--reports", required=True)
    ap.add_argument("--target", default=".")
    ap.add_argument("--fail-on", default="high", choices=SEVERITIES[:-1] + ["none"])
    ap.add_argument("--allow-incomplete", action="store_true")
    ap.add_argument("--baseline", type=Path, help="Taban dalın findings.json dosyası; eşik yalnızca yeni bulgulara uygulanır")
    a = ap.parse_args()
    out, target = Path(a.reports), Path(a.target).resolve()

    findings, problems = [], {}
    parsers = [("gitleaks", parse_gitleaks), ("osv", parse_osv), ("bandit", parse_bandit),
               ("semgrep", parse_semgrep), ("trivy", parse_trivy), ("trivy-image", parse_trivy_image),
               ("zap", parse_zap), ("mobsf", parse_mobsf), ("supabase", parse_supabase), ("sbom", lambda data, target: [])]
    semgrep_note = ""
    for tool, fn in parsers:
        if (out / REPORT_FILES[tool]).exists():
            data, items = read_report(out / REPORT_FILES[tool], tool, fn, target, problems)
            findings += items
            if tool == "semgrep":
                semgrep_note = semgrep_partial_note(data, target)

    def source_of(report):
        src = Path(report).with_suffix(".source")
        return src.read_text(encoding="utf-8").strip() if src.exists() else ""

    for p in sorted(glob.glob(str(out / "osv-deno-*.json"))):
        findings += read_report(Path(p), "osv-deno", parse_osv, target, problems, source_of(p))[1]
    resolved = {}
    for p in sorted(glob.glob(str(out / "pip-audit-*.json"))):
        source = source_of(p)
        data, items = read_report(Path(p), "pip-audit", parse_pip_audit, target, problems, source)
        findings += items
        resolved[source] = {norm_pkg(d["name"]): d["version"] for d in (data or {}).get("dependencies", []) if d.get("version")}
    for p in sorted(glob.glob(str(out / "dotnet-*.json"))):
        findings += read_report(Path(p), "dotnet", parse_dotnet, target, problems)[1]

    for p in sorted(glob.glob(str(out / "schemathesis" / "*.xml"))):
        try:
            findings += list(parse_schemathesis(Path(p)))
        except ET.ParseError:
            problems["schemathesis"] = f"{Path(p).name}: rapor okunamadı"

    findings, unresolved = drop_unresolved_osv(findings, resolved)
    findings = dedupe(findings)
    ignores, ignore_issues = load_ignores(target)
    active, ignored = [], []
    for f in findings:
        reason = is_ignored(f, ignores)
        (ignored if reason else active).append({**f, "ignored_reason": reason} if reason else f)
    active = group_by_package(active)
    add_fingerprints(active)
    known = load_baseline(a.baseline) if a.baseline else None
    for f in active:
        f["new"] = known is None or f["fingerprint"] not in known

    statuses = []
    if (out / "_status.tsv").exists():
        for row in (out / "_status.tsv").read_text(encoding="utf-8").splitlines():
            parts = row.split("\t") + ["", "", ""]
            statuses.append(tuple(parts[:3]))
        if not statuses:
            statuses.append(("tarama", "error", "Seçilen araçların hiçbiri bu projede çalışmadı"))
    for tool, st, _ in statuses:
        # "ok" diyen aracın raporu yoksa da sonucu bilinmiyordur
        if st in ("ok", "partial") and tool in REPORT_FILES and not glob.glob(str(out / REPORT_FILES[tool])):
            problems.setdefault(tool, "rapor dosyası oluşmadı")
    seen = {t for t, _, _ in statuses}
    statuses = [(t, "error", problems[t]) if t in problems
                else (t, st, semgrep_note) if t == "semgrep" and st == "ok" else (t, st, n) for t, st, n in statuses]
    statuses += [(t, "error", note) for t, note in problems.items() if t not in seen]
    incomplete = [row for row in statuses if row[1] in INCOMPLETE_STATUSES]
    stacks = (out / "_stacks.txt").read_text().split() if (out / "_stacks.txt").exists() else []

    failed = a.fail_on != "none" and any(f["new"] and RANK[f["severity"]] <= RANK[a.fail_on] for f in active)
    counts = {s: sum(1 for f in active if f["severity"] == s) for s in SEVERITIES}

    (out / "findings.json").write_text(json.dumps({
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "target": str(target), "stacks": stacks, "fail_on": a.fail_on, "failed": failed,
        "complete": not incomplete, "baseline": known is not None, "counts": counts, "tools": [{"tool": t, "status": s, "note": n} for t, s, n in statuses],
        "findings": active, "ignored": ignored, "unresolved_osv": unresolved,
        "suppression_issues": ignore_issues,
    }, ensure_ascii=False, indent=2), encoding="utf-8")
    (out / "findings.sarif").write_text(json.dumps(to_sarif(active), indent=2), encoding="utf-8")
    md = to_markdown(active, ignored, statuses, stacks, a.fail_on, failed, unresolved, incomplete, ignore_issues, known is not None)
    (out / "summary.md").write_text(md, encoding="utf-8")
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as fh:
            fh.write(md)

    print(md)
    print(f"[summarize] Raporlar: {out}")
    # --fail-on none yalnızca raporlama modudur; eksiklik raporda görünür ama işi kırmaz
    if incomplete and a.fail_on != "none" and not a.allow_incomplete:
        sys.exit(EXIT_INCOMPLETE)
    sys.exit(EXIT_THRESHOLD if failed else 0)


if __name__ == "__main__":
    for stream in (sys.stdout, sys.stderr):  # Windows konsolunda emojiler ve yerel hata metinleri kilitlenmesin
        stream.reconfigure(encoding="utf-8", errors="replace")
    try:
        main()
    except Exception as exc:  # kilitlenme "eşik aşıldı" (1) ile karışmamalı
        print(f"[summarize] Özet oluşturulamadı: {type(exc).__name__}: {exc}", file=sys.stderr)
        sys.exit(EXIT_INCOMPLETE)
