#!/usr/bin/env python3
"""Araç çıktılarını ortak bir bulgu formatına çevirir, tekrarları ayıklar,
.security-ignore.yml ile bastırılanları düşer ve şunları yazar:

  findings.json   normalize bulgular (DefectDojo / skill / diğer araçlar için)
  findings.sarif  GitHub Code Scanning'e yüklenebilir SARIF 2.1.0
  summary.md      insan okuyabilir özet (PR yorumu ve iş özeti)

Yalnızca standart kütüphane kullanır.
"""
from __future__ import annotations

import argparse
import datetime as dt
import fnmatch
import glob
import json
import os
import re
import sys
from pathlib import Path

SEVERITIES = ["critical", "high", "medium", "low", "info"]
RANK = {s: i for i, s in enumerate(SEVERITIES)}
EMOJI = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}
TOOL_NAMES = {
    "gitleaks": "Gitleaks (sırlar)",
    "osv": "OSV-Scanner (bağımlılıklar)",
    "pip-audit": "pip-audit (Python bağımlılıkları)",
    "bandit": "Bandit (Python SAST)",
    "semgrep": "Semgrep (SAST)",
    "trivy": "Trivy (altyapı yapılandırması)",
    "dotnet": "dotnet (NuGet bağımlılıkları)",
}


def load_json(path: Path):
    try:
        text = path.read_text(encoding="utf-8").strip()
        return json.loads(text) if text else None
    except (OSError, json.JSONDecodeError) as exc:
        print(f"[summarize] {path.name} okunamadı: {exc}", file=sys.stderr)
        return None


def rel(path: str | None, target: Path) -> str:
    if not path:
        return ""
    p = Path(path)
    try:
        return str(p.resolve().relative_to(target)) if p.is_absolute() else str(p)
    except ValueError:
        return str(p)


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
def parse_gitleaks(data, target):
    for r in data or []:
        yield finding(
            "gitleaks", r.get("RuleID", "secret"), "critical",
            f"Sızdırılmış sır: {r.get('Description') or r.get('RuleID')}",
            file=rel(r.get("File"), target), line=r.get("StartLine"),
            ids=[r.get("Fingerprint")],
            detail=f"commit {r['Commit'][:10]}" if r.get("Commit") else "",
        )


def _osv_fixed(vulns, pkg_name):
    for v in vulns:
        for aff in v.get("affected", []):
            if aff.get("package", {}).get("name", "").lower() != pkg_name.lower():
                continue
            for rng in aff.get("ranges", []):
                for ev in rng.get("events", []):
                    if ev.get("fixed"):
                        return ev["fixed"]
    return ""


def parse_osv(data, target):
    for res in (data or {}).get("results", []):
        src = rel(res.get("source", {}).get("path"), target)
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


def dedupe(findings):
    """Aynı paket+açık birden çok araçtan gelirse tek kayda indirger, en yüksek dereceyi tutar."""
    out, index = [], {}
    for f in findings:
        f = {**f, "also_found_by": []}
        if not (f["package"] and f["ids"]):
            out.append(f)
            continue
        pkg = norm_pkg(f["package"])
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


# ------------------------------------------------------------------ bastırma
def load_ignores(target: Path):
    path = next((p for p in (target / ".security-ignore.yml", target / ".security-ignore.yaml") if p.exists()), None)
    if not path:
        return []
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
    active = []
    for it in items:
        if not isinstance(it, dict) or not it.get("id"):
            continue
        exp = it.get("expires")
        if exp:
            try:
                if dt.date.fromisoformat(str(exp)) < today:
                    print(f"[summarize] Süresi dolmuş bastırma yok sayıldı: {it['id']} ({exp})", file=sys.stderr)
                    continue
            except ValueError:
                pass
        active.append(it)
    return active


def is_ignored(f, ignores):
    for it in ignores:
        ident = str(it["id"])
        if ident != f["rule_id"] and ident not in f["ids"] and not fnmatch.fnmatch(f["rule_id"], ident):
            continue
        if it.get("path") and not fnmatch.fnmatch(f["file"], str(it["path"])):
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
            msg = f["title"] + (f" → düzeltilmiş sürüm: {f['fixed_version']}" if f["fixed_version"] else "")
            results.append({"ruleId": rid, "level": level[f["severity"]], "message": {"text": msg}, "locations": [loc]})
        for r in rules.values():
            if not r["helpUri"]:
                del r["helpUri"]
        runs.append({"tool": {"driver": {"name": tool, "rules": list(rules.values())}}, "results": results})
    return {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0", "runs": runs}


def md_escape(s: str) -> str:
    return str(s).replace("|", "\\|").replace("\n", " ")


def to_markdown(active, ignored, statuses, stacks, fail_on, failed):
    counts = {s: sum(1 for f in active if f["severity"] == s) for s in SEVERITIES}
    lines = ["## 🔐 Güvenlik taraması", ""]
    verdict = "❌ **Eşik aşıldı**" if failed else "✅ **Eşik aşılmadı**"
    lines.append(f"{verdict} — başarısızlık eşiği: `{fail_on}` · yığınlar: {', '.join(stacks) or '—'}")
    lines.append("")
    lines.append(" · ".join(f"{EMOJI[s]} {s}: **{counts[s]}**" for s in SEVERITIES if s != "info"))
    if ignored:
        lines.append(f"\n_{len(ignored)} bulgu `.security-ignore.yml` ile bastırıldı._")
    lines += ["", "<details><summary>Araç durumu</summary>", "", "| Araç | Durum | Not |", "|---|---|---|"]
    icon = {"ok": "✅", "partial": "⚠️", "skipped": "⏭️", "missing": "➖", "error": "❌"}
    for tool, st, note in statuses:
        lines.append(f"| {TOOL_NAMES.get(tool, tool)} | {icon.get(st, st)} {st} | {md_escape(note)} |")
    lines += ["", "</details>", ""]
    if active:
        lines += ["| Derece | Araç | Bulgu | Konum | Düzeltme |", "|---|---|---|---|---|"]
        for f in sorted(active, key=lambda x: (RANK[x["severity"]], x["tool"], x["file"]))[:100]:
            where = f["file"] + (f":{f['line']}" if f["line"] else "")
            fix = f"`{f['fixed_version']}`" if f["fixed_version"] else ""
            title = f"[{md_escape(f['title'][:110])}]({f['url']})" if f["url"] else md_escape(f["title"][:110])
            lines.append(f"| {EMOJI[f['severity']]} {f['severity']} | {f['tool']} | {title} | `{md_escape(where)}` | {fix} |")
        if len(active) > 100:
            lines.append(f"\n_…ve {len(active) - 100} bulgu daha; tamamı `findings.json` içinde._")
    else:
        lines.append("Bulgu yok. 🎉")
    return "\n".join(lines) + "\n"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--reports", required=True)
    ap.add_argument("--target", default=".")
    ap.add_argument("--fail-on", default="high", choices=SEVERITIES[:-1] + ["none"])
    a = ap.parse_args()
    out, target = Path(a.reports), Path(a.target).resolve()

    findings = []
    parsers = [("gitleaks.json", parse_gitleaks), ("osv.json", parse_osv), ("bandit.json", parse_bandit),
               ("semgrep.json", parse_semgrep), ("trivy.json", parse_trivy)]
    for name, fn in parsers:
        if (out / name).exists():
            findings += list(fn(load_json(out / name), target))
    for p in sorted(glob.glob(str(out / "pip-audit-*.json"))):
        src = Path(p).with_suffix(".source")
        findings += list(parse_pip_audit(load_json(Path(p)), target,
                                         src.read_text(encoding="utf-8").strip() if src.exists() else ""))
    for p in sorted(glob.glob(str(out / "dotnet-*.json"))):
        findings += list(parse_dotnet(load_json(Path(p)), target))

    findings = dedupe(findings)
    ignores = load_ignores(target)
    active, ignored = [], []
    for f in findings:
        reason = is_ignored(f, ignores)
        (ignored if reason else active).append({**f, "ignored_reason": reason} if reason else f)
    active = group_by_package(active)

    statuses = []
    if (out / "_status.tsv").exists():
        for row in (out / "_status.tsv").read_text(encoding="utf-8").splitlines():
            parts = row.split("\t") + ["", "", ""]
            statuses.append(tuple(parts[:3]))
    stacks = (out / "_stacks.txt").read_text().split() if (out / "_stacks.txt").exists() else []

    failed = a.fail_on != "none" and any(RANK[f["severity"]] <= RANK[a.fail_on] for f in active)
    counts = {s: sum(1 for f in active if f["severity"] == s) for s in SEVERITIES}

    (out / "findings.json").write_text(json.dumps({
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "target": str(target), "stacks": stacks, "fail_on": a.fail_on, "failed": failed,
        "counts": counts, "tools": [{"tool": t, "status": s, "note": n} for t, s, n in statuses],
        "findings": active, "ignored": ignored,
    }, ensure_ascii=False, indent=2), encoding="utf-8")
    (out / "findings.sarif").write_text(json.dumps(to_sarif(active), indent=2), encoding="utf-8")
    md = to_markdown(active, ignored, statuses, stacks, a.fail_on, failed)
    (out / "summary.md").write_text(md, encoding="utf-8")
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as fh:
            fh.write(md)

    print(md)
    print(f"[summarize] Raporlar: {out}")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
