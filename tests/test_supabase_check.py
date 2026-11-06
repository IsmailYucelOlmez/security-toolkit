"""python3 -m unittest discover tests"""
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = str(ROOT / "scripts" / "supabase_check.py")

INIT = """
-- yorumdaki ; ifadeyi bölmemeli
create table public.notes (id uuid primary key, owner uuid, body text default 'a;b');
create table if not exists "profiles" (id uuid primary key);
create table private.audit (id int);
create temp table scratch (id int);
create table public.cache (k text primary key, v jsonb);
alter table public.cache enable row level security;
create policy "cache_read" on public.cache for select to anon using (true);
create policy "cache_write" on public.cache for insert to anon with check (true);
create policy "cache_fix" on public.cache for update to anon using (true);
create policy "notes_own" on public.notes using (owner = auth.uid());

create or replace function public.leaky() returns void language plpgsql security definer as $$
begin
  perform 1; -- gövdedeki ; ifadeyi bölmemeli
end $$;
create function public.safe() returns void language sql security definer set search_path = '' as $$ select 1; $$;
create view public.v_notes as select * from public.notes;
create view public.v_ok with (security_invoker = true) as select 1;
create materialized view public.mv as select 1;
"""

LATER = """
alter table "public"."profiles" enable row level security;
drop policy if exists "cache_fix" on public.cache;
alter function public.leaky() set search_path = '';
"""

CONFIG = """
[functions.open]
verify_jwt = false

[functions.guarded]
# kendi doğrulamasını yapıyor
verify_jwt = false

[functions.default]
"""


class SupabaseCheckTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.supa = self.tmp / "supabase"
        (self.supa / "migrations").mkdir(parents=True)
        (self.supa / "migrations" / "20260101_init.sql").write_text(INIT, encoding="utf-8")

    def run_check(self):
        out = self.tmp / "supabase.json"
        proc = subprocess.run([sys.executable, SCRIPT, self.tmp, out, self.supa], capture_output=True, text=True,
                              encoding="utf-8")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        data = json.loads(out.read_text(encoding="utf-8"))
        return data, {(r["rule_id"], r["title"].split(":")[0].split(" ")[0]) for r in data["results"]}

    def test_first_migration(self):
        data, found = self.run_check()
        self.assertEqual(data["migrations"], 1)
        self.assertIn(("supabase-table-without-rls", "public.notes"), found)
        self.assertIn(("supabase-table-without-rls", "public.profiles"), found)
        self.assertNotIn(("supabase-table-without-rls", "public.cache"), found)
        self.assertFalse(any("audit" in t or "scratch" in t for _, t in found), "public dışı ve geçici tablolar")
        self.assertIn(("supabase-policy-always-true-select", "cache"), found)
        self.assertIn(("supabase-policy-always-true-write", "cache"), found)
        self.assertIn(("supabase-security-definer-search-path", "leaky"), found)
        self.assertNotIn(("supabase-security-definer-search-path", "safe"), found)
        self.assertIn(("supabase-view-security-definer", "public.v_notes"), found)
        self.assertNotIn(("supabase-view-security-definer", "public.v_ok"), found)
        self.assertIn(("supabase-materialized-view-public", "public.mv"), found)
        line = next(r["line"] for r in data["results"] if r["rule_id"] == "supabase-security-definer-search-path")
        self.assertEqual(line, 14)

    def test_later_migration_fixes_are_honored(self):
        (self.supa / "migrations" / "20260201_fix.sql").write_text(LATER, encoding="utf-8")
        _, found = self.run_check()
        self.assertNotIn(("supabase-table-without-rls", "public.profiles"), found)
        self.assertNotIn(("supabase-security-definer-search-path", "leaky"), found)
        writes = [r for r in json.loads((self.tmp / "supabase.json").read_text(encoding="utf-8"))["results"]
                  if r["rule_id"] == "supabase-policy-always-true-write"]
        self.assertEqual(len(writes), 1, "kaldırılan UPDATE politikası bulgu olmamalı")
        self.assertIn("INSERT", writes[0]["title"])

    def test_disabled_rls_is_reported_at_the_disabling_migration(self):
        (self.supa / "migrations" / "20260301_off.sql").write_text(
            "alter table public.cache disable row level security;\n", encoding="utf-8")
        data, _ = self.run_check()
        hit = next(r for r in data["results"] if r["rule_id"] == "supabase-table-without-rls" and "cache" in r["title"])
        self.assertEqual(hit["file"], "supabase/migrations/20260301_off.sql")
        self.assertIn("kapatılmış", hit["title"])

    def test_unauthenticated_function_with_service_key(self):
        (self.supa / "config.toml").write_text(CONFIG, encoding="utf-8")
        for name, src in {
            "open": 'const c = createClient(url, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!);\n',
            "guarded": 'import { check } from "../_shared/auth.ts";\nconst k = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");\n',
            "default": 'const k = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");\n',
        }.items():
            (self.supa / "functions" / name).mkdir(parents=True)
            (self.supa / "functions" / name / "index.ts").write_text(src, encoding="utf-8")
        (self.supa / "functions" / "_shared").mkdir()
        (self.supa / "functions" / "_shared" / "auth.ts").write_text(
            'export const check = (req) => req.headers.get("Authorization");\n', encoding="utf-8")
        data, _ = self.run_check()
        self.assertEqual(data["functions"], 3)
        hits = [r for r in data["results"] if r["rule_id"] == "supabase-function-unauthenticated-service-role"]
        self.assertEqual([(r["title"].split(":")[0], r["file"], r["line"]) for r in hits],
                         [("open", "supabase/config.toml", 2)])


if __name__ == "__main__":
    unittest.main()
