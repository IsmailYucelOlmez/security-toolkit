#!/usr/bin/env python3
"""Supabase projesinde genel tarayıcıların göremediği yetki açıklarını arar.

  supabase_check.py <hedef> <çıktı.json> <supabase-dizini>...

Migration'lar dosya adı sırasıyla okunur ve son duruma bakılır: sonraki bir migration'da RLS'i açılan tablo bulgu
değildir. Edge Functions için config.toml'daki verify_jwt ayarı fonksiyonun kaynağıyla birlikte değerlendirilir.
Yalnızca standart kütüphane kullanır; SQL'i ayrıştırmaz, ifadeleri düzenli ifadeyle tanır.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

NAME = r'((?:"[^"]+"|\w+)(?:\.(?:"[^"]+"|\w+))?)'
CREATE_TABLE = re.compile(rf"^create (?:unlogged )?table (?:if not exists )?{NAME}")
TEMP_TABLE = re.compile(r"^create (?:global |local )?(?:temp|temporary) table")
ALTER_TABLE = re.compile(rf"^alter table (?:if exists )?(?:only )?{NAME}")
RENAME_TABLE = re.compile(rf"^alter table (?:if exists )?(?:only )?{NAME} rename to {NAME}")
DROP_TABLE = re.compile(r"^drop table (?:if exists )?(.+?)(?: cascade| restrict)?$")
CREATE_VIEW = re.compile(rf"^create (?:or replace )?(materialized )?view (?:if not exists )?{NAME}")
ALTER_VIEW = re.compile(rf"^alter (?:materialized )?view (?:if exists )?{NAME}")
DROP_VIEW = re.compile(r"^drop (?:materialized )?view (?:if exists )?(.+?)(?: cascade| restrict)?$")
CREATE_POLICY = re.compile(rf'^create policy ("[^"]+"|\S+) on {NAME}(.*)$')
DROP_POLICY = re.compile(rf'^drop policy (?:if exists )?("[^"]+"|\S+) on {NAME}')
CREATE_FUNCTION = re.compile(rf"^create (?:or replace )?function {NAME}")
ALTER_FUNCTION = re.compile(rf"^alter function {NAME}")
DROP_FUNCTION = re.compile(rf"^drop function (?:if exists )?{NAME}")
ALWAYS_TRUE = re.compile(r"\b(using|with check) \(\s*\(?\s*true\s*\)?\s*\)")

SERVICE_KEY = re.compile(r"SUPABASE_SERVICE_ROLE_KEY|SUPABASE_SECRET_KEY|sb_secret_")
# Çağıranı doğrulayan bir adımın izi; yokluğu açığın kanıtı değil, incelenmesi gereken bir işarettir
AUTH_CHECK = re.compile(r"auth\.getUser\(|auth\.getClaims\(|jwtVerify\(|verifyOtp\(|"
                        r"headers\.get\(\s*['\"](authorization|x-cron-secret|x-webhook-signature)['\"]", re.I)
IMPORT = re.compile(r"""from\s+['"](\.{1,2}/[^'"]+)['"]""")


def statements(sql: str):
    """(satır, ifade) üretir; yorumlar atlanır, $$ ve tırnak içindeki ; ifadeyi bölmez."""
    i, n, line, start, buf = 0, len(sql), 1, None, []
    while i < n:
        c = sql[i]
        if sql.startswith("--", i):
            j = sql.find("\n", i)
            i = n if j < 0 else j
            continue
        if sql.startswith("/*", i):
            j = sql.find("*/", i + 2)
            j = n if j < 0 else j + 2
            line += sql.count("\n", i, j)
            i = j
            continue
        if start is None and not c.isspace():
            start = line
        if c == "'":
            j = i + 1
            while j < n and not (sql[j] == "'" and not sql.startswith("''", j)):
                j += 2 if sql.startswith("''", j) else 1
            j = min(j + 1, n)
        elif c == "$" and (m := re.match(r"\$(\w*)\$", sql[i:])):
            tag = m.group(0)
            end = sql.find(tag, i + len(tag))
            j = n if end < 0 else end + len(tag)
        elif c == ";":
            if buf:
                yield start, " ".join("".join(buf).split()).lower()
            buf, start = [], None
            i += 1
            continue
        else:
            j = i + 1
        buf.append(sql[i:j])
        line += sql.count("\n", i, j)
        i = j
    if "".join(buf).strip():
        yield start, " ".join("".join(buf).split()).lower()


def public_name(raw: str) -> str:
    """Yalnızca API'ye açılan public şemadaki adı döner; başka şemadaysa boş."""
    parts = [p.strip('"') for p in raw.split(".")]
    if len(parts) == 2 and parts[0] != "public":
        return ""
    return parts[-1]


def table_key(raw: str) -> str:
    """public.x ile x aynı nesnedir; başka şemalar adıyla birlikte tutulur."""
    parts = [p.strip('"') for p in raw.split(".")]
    return parts[-1] if len(parts) == 1 or parts[0] == "public" else ".".join(parts)


def check_migrations(target: Path, sql_files: list[Path]):
    # Son durum önemli: sonradan kaldırılan politika veya düzeltilen fonksiyon bulgu değildir
    tables, views, policies, functions = {}, {}, {}, {}
    for path in sql_files:
        rel = path.relative_to(target).as_posix()
        for line, st in statements(path.read_text(encoding="utf-8", errors="replace")):
            loc = {"file": rel, "line": line}
            if TEMP_TABLE.match(st):
                continue
            if m := CREATE_TABLE.match(st):
                if name := public_name(m.group(1)):
                    tables[name] = {**loc, "rls": False, "disabled": None}
            elif m := RENAME_TABLE.match(st):
                old = public_name(m.group(1))
                if old in tables:
                    tables[public_name(m.group(2))] = tables.pop(old)
            elif m := ALTER_TABLE.match(st):
                t = tables.get(public_name(m.group(1)))
                if t and "enable row level security" in st:
                    t.update(rls=True, disabled=None)
                elif t and "disable row level security" in st:
                    t.update(rls=False, disabled=loc)
            elif m := DROP_TABLE.match(st):
                for raw in m.group(1).split(","):
                    name = public_name(raw.strip())
                    tables.pop(name, None)
                    policies = {k: v for k, v in policies.items() if k[0] != name}
            elif m := CREATE_VIEW.match(st):
                if name := public_name(m.group(2)):
                    views[name] = {**loc, "materialized": bool(m.group(1)), "invoker": "security_invoker" in st}
            elif m := ALTER_VIEW.match(st):
                v = views.get(public_name(m.group(1)))
                if v and re.search(r"security_invoker\s*=\s*(true|on)", st):
                    v["invoker"] = True
            elif m := DROP_VIEW.match(st):
                for raw in m.group(1).split(","):
                    views.pop(public_name(raw.strip()), None)
            elif m := CREATE_POLICY.match(st):
                key, rest = (table_key(m.group(2)), m.group(1).strip('"')), m.group(3)
                policies.pop(key, None)
                if t := ALWAYS_TRUE.search(rest):
                    cmd = (re.search(r"\bfor (all|select|insert|update|delete)\b", rest) or [None, "all"])[1]
                    if cmd == "select":
                        policies[key] = ("supabase-policy-always-true-select", "low",
                                         f"{key[0]} herkese okunur: \"{key[1]}\" `using (true)`. Amaçlandıysa bastırın", loc)
                    else:
                        policies[key] = ("supabase-policy-always-true-write", "high",
                                         f"{key[0]}: \"{key[1]}\" {cmd.upper()} için `{t.group(1)} (true)` ile her satıra izin veriyor",
                                         loc)
            elif m := DROP_POLICY.match(st):
                policies.pop((table_key(m.group(2)), m.group(1).strip('"')), None)
            elif m := CREATE_FUNCTION.match(st):
                name = table_key(m.group(1))
                functions.pop(name, None)
                if "security definer" in st and "search_path" not in st:
                    functions[name] = ("supabase-security-definer-search-path", "medium",
                                       f"{name}: `security definer` fonksiyonu `search_path` sabitlemiyor; "
                                       "şemaya nesne ekleyebilen biri fonksiyonun yetkisiyle kod çalıştırabilir", loc)
            elif m := ALTER_FUNCTION.match(st):
                if "search_path" in st or "security invoker" in st:
                    functions.pop(table_key(m.group(1)), None)
            elif m := DROP_FUNCTION.match(st):
                functions.pop(table_key(m.group(1)), None)
    out = list(policies.values()) + list(functions.values())
    for name, t in tables.items():
        if not t["rls"]:
            loc = t["disabled"] or {"file": t["file"], "line": t["line"]}
            how = "RLS kapatılmış" if t["disabled"] else "RLS açılmamış"
            out.append(("supabase-table-without-rls", "high",
                        f"public.{name}: {how}; anon anahtarı olan herkes Data API ile tabloyu okuyup yazabilir", loc))
    for name, v in views.items():
        if v["materialized"]:
            out.append(("supabase-materialized-view-public", "medium",
                        f"public.{name}: materialized view RLS uygulamaz ve Data API ile okunabilir", v))
        elif not v["invoker"]:
            out.append(("supabase-view-security-definer", "medium",
                        f"public.{name}: view `security_invoker` olmadan sahibinin yetkisiyle çalışır ve tabloların RLS'ini atlar", v))
    return out


def function_sources(fn_dir: Path) -> str:
    """Fonksiyon dizinindeki kaynaklar ve göreli import edilen paylaşılan dosyalar."""
    seen, todo, text = set(), [p for p in fn_dir.rglob("*") if p.suffix in (".ts", ".js", ".mjs", ".tsx")], []
    while todo:
        p = todo.pop().resolve()
        if p in seen or not p.is_file():
            continue
        seen.add(p)
        src = p.read_text(encoding="utf-8", errors="replace")
        text.append(src)
        todo += [p.parent / m.group(1) for m in IMPORT.finditer(src)]
    return "\n".join(text)


def function_settings(cfg_path: Path):
    """config.toml'dan {fonksiyon: (satır, verify_jwt)}; Python 3.10'da tomllib olmadığından satır satır okunur."""
    out, current = {}, None
    for i, raw in enumerate(cfg_path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if m := re.fullmatch(r'\[functions\.("?)([^"\]]+)\1\]', line):
            current = m.group(2)
            out[current] = (i, True)
        elif line.startswith("["):
            current = None
        elif current and (m := re.fullmatch(r"verify_jwt\s*=\s*(true|false)", line)):
            out[current] = (out[current][0], m.group(1) == "true")
    return out


def check_functions(target: Path, supa: Path):
    cfg_path = supa / "config.toml"
    if not cfg_path.exists():
        return [], 0
    out, count = [], 0
    for name, (line, verify_jwt) in function_settings(cfg_path).items():
        fn_dir = supa / "functions" / name
        if not fn_dir.is_dir():
            continue
        count += 1
        if verify_jwt:
            continue
        src = function_sources(fn_dir)
        if SERVICE_KEY.search(src) and not AUTH_CHECK.search(src):
            out.append(("supabase-function-unauthenticated-service-role", "high",
                        f"{name}: `verify_jwt = false` ve RLS'i atlayan anahtar kullanılıyor, ama kodda çağıranı "
                        "doğrulayan bir adım (auth.getUser, imza veya paylaşılan sır kontrolü) görünmüyor",
                        {"file": cfg_path.relative_to(target).as_posix(), "line": line}))
    return out, count


def main() -> int:
    if len(sys.argv) < 4:
        print(__doc__, file=sys.stderr)
        return 2
    target, out_path = Path(sys.argv[1]).resolve(), Path(sys.argv[2])
    results, migrations, functions = [], 0, 0
    for d in sys.argv[3:]:
        supa = Path(d).resolve()
        sql = sorted((supa / "migrations").glob("*.sql")) + sorted((supa / "schemas").glob("*.sql"))
        migrations += len(sql)
        results += check_migrations(target, sql)
        found, n = check_functions(target, supa)
        results += found
        functions += n
    out_path.write_text(json.dumps({
        "migrations": migrations, "functions": functions,
        "results": [{"rule_id": r, "severity": s, "title": t, "file": loc["file"], "line": loc["line"]}
                    for r, s, t, loc in results],
    }, ensure_ascii=False, indent=1), encoding="utf-8")
    print(migrations, functions)
    return 0


if __name__ == "__main__":
    sys.exit(main())
