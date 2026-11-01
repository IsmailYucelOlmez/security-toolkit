#!/usr/bin/env bash
# Projenin yığınını algılar, ilgili güvenlik araçlarını çalıştırır ve sonuçları
# tek bir rapora (summary.md, findings.json, findings.sarif) toplar.
#
#   scripts/scan.sh [--path DIR] [--out DIR] [--fail-on high] [--diff-base REF]
#                   [--skip semgrep,trivy] [--only gitleaks,bandit]
#
#   --fail-on    critical | high | medium | low | none  (varsayılan: high)
#   --diff-base  Sadece REF..HEAD arasındaki commit'lerde sır ara (PR'lar için)
#
# Ortam değişkenleri:
#   SEMGREP_CONFIG   Semgrep kural seti (varsayılan: p/default). Ağ yoksa yalnızca yerel kurallar.
#   SECURITY_TOOLS_DIR  install-tools.sh kurulum dizini (PATH'e otomatik eklenir)
#
# Çıkış kodu: 0 = eşik üstü bulgu yok, 1 = eşik üstü bulgu var, 2 = kullanım hatası
set -uo pipefail

TOOLKIT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
TARGET="."
OUT=""
FAIL_ON="high"
DIFF_BASE=""
SKIP=""
ONLY=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --path) TARGET="$2"; shift ;;
    --out) OUT="$2"; shift ;;
    --fail-on) FAIL_ON="$2"; shift ;;
    --diff-base) DIFF_BASE="$2"; shift ;;
    --skip) SKIP="$2"; shift ;;
    --only) ONLY="$2"; shift ;;
    -h|--help) sed -n '2,17p' "$0"; exit 0 ;;
    *) echo "Bilinmeyen seçenek: $1" >&2; exit 2 ;;
  esac
  shift
done

TARGET="$(cd "$TARGET" && pwd)"
OUT="${OUT:-$TARGET/security-reports}"
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
export PATH="${SECURITY_TOOLS_DIR:-$HOME/.security-tools}/bin:$PATH"

STATUS_FILE="$OUT/_status.tsv"
: > "$STATUS_FILE"

log()     { echo -e "\033[1;34m[scan]\033[0m $*"; }
status()  { printf '%s\t%s\t%s\n' "$1" "$2" "${3:-}" >> "$STATUS_FILE"; }
enabled() {
  [[ -n "$ONLY" && ",$ONLY," != *",$1,"* ]] && return 1
  [[ ",$SKIP," == *",$1,"* ]] && return 1
  return 0
}
have()    { command -v "$1" >/dev/null 2>&1; }
semgrep_error() {
  python3 -c 'import json,sys
try: print(json.load(open(sys.argv[1]))["errors"][0]["message"].splitlines()[0][:200])
except Exception: print("ayrıntı için semgrep.log")' "$OUT/semgrep.json"
}

# Bağımlılık klasörleri ve üretilmiş kod taranmaz
PRUNE_DIRS=(.git .security-toolkit .security-tools .venv venv env node_modules build dist .dart_tool .pub-cache bin obj security-reports __pycache__ .tox .mypy_cache Pods)
find_files() {  # find_files <isim-deseni>...
  local prune=() first=1
  for d in "${PRUNE_DIRS[@]}"; do
    (( first )) || prune+=(-o); prune+=(-name "$d"); first=0
  done
  local names=() f=1
  for n in "$@"; do (( f )) || names+=(-o); names+=(-name "$n"); f=0; done
  find "$TARGET" \( -type d \( "${prune[@]}" \) -prune \) -o \( -type f \( "${names[@]}" \) -print \)
}

# ---------------------------------------------------------------- algılama
STACKS=()
[[ -n "$(find_files '*.py' | head -1)" ]]                          && STACKS+=(python)
[[ -n "$(find_files pubspec.yaml | head -1)" ]]                    && STACKS+=(flutter)
[[ -n "$(find_files '*.csproj' '*.sln' '*.slnx' | head -1)" ]]     && STACKS+=(dotnet)
[[ -n "$(find_files 'package.json' | head -1)" ]]                  && STACKS+=(node)
[[ -n "$(find_files 'Dockerfile' 'Dockerfile.*' '*.Dockerfile' '*.tf' | head -1)" ]] && STACKS+=(infra)
log "Hedef: $TARGET"
log "Algılanan yığınlar: ${STACKS[*]:-(yok)}"
printf '%s\n' "${STACKS[@]}" > "$OUT/_stacks.txt"
has_stack() { [[ " ${STACKS[*]} " == *" $1 "* ]]; }

# ---------------------------------------------------------------- gitleaks
if enabled gitleaks; then
  if have gitleaks; then
    log "gitleaks: sızdırılmış sırlar aranıyor"
    args=(--report-format json --report-path "$OUT/gitleaks.json" --exit-code 0 --no-banner --redact)
    if git -C "$TARGET" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
      [[ -n "$DIFF_BASE" ]] && args+=(--log-opts="$DIFF_BASE..HEAD")
      gitleaks git "$TARGET" "${args[@]}" >/dev/null 2>"$OUT/gitleaks.log"
    else
      gitleaks dir "$TARGET" "${args[@]}" >/dev/null 2>"$OUT/gitleaks.log"
    fi
    [[ $? -eq 0 ]] && status gitleaks ok || status gitleaks error "$(tail -1 "$OUT/gitleaks.log")"
  else status gitleaks missing "gitleaks kurulu değil"; fi
fi

# ---------------------------------------------------------------- osv-scanner (Python, Dart, NuGet, npm kilit dosyaları)
if enabled osv; then
  if have osv-scanner; then
    log "osv-scanner: bağımlılık açıkları"
    osv-scanner scan source -r --format json "$TARGET" > "$OUT/osv.json" 2>"$OUT/osv.log"
    rc=$?
    case $rc in
      0|1) status osv ok ;;
      128) status osv skipped "kilit dosyası bulunamadı"; rm -f "$OUT/osv.json" ;;
      *) status osv error "çıkış kodu $rc: $(tail -1 "$OUT/osv.log")" ;;
    esac
  else status osv missing "osv-scanner kurulu değil"; fi
fi

# ---------------------------------------------------------------- pip-audit (requirements*.txt)
if enabled pip-audit && has_stack python; then
  if have pip-audit; then
    mapfile -t reqs < <(find_files 'requirements*.txt' | grep -v requirements-tools.txt)
    if [[ ${#reqs[@]} -eq 0 ]]; then status pip-audit skipped "requirements dosyası yok (kilit dosyaları osv ile tarandı)"
    else
      i=0; ok=1
      for r in "${reqs[@]}"; do
        log "pip-audit: ${r#$TARGET/}"
        echo "${r#$TARGET/}" > "$OUT/pip-audit-$i.source"
        pip-audit -r "$r" --format json --output "$OUT/pip-audit-$i.json" --progress-spinner off >/dev/null 2>"$OUT/pip-audit-$i.log"
        [[ $? -le 1 ]] || ok=0
        i=$((i+1))
      done
      (( ok )) && status pip-audit ok || status pip-audit error "bazı dosyalar çözümlenemedi, pip-audit-*.log'a bakın"
    fi
  else status pip-audit missing "pip-audit kurulu değil"; fi
fi

# ---------------------------------------------------------------- bandit
if enabled bandit && has_stack python; then
  if have bandit; then
    log "bandit: Python statik analiz"
    excl=""; for d in "${PRUNE_DIRS[@]}" tests test; do excl+="*/$d/*,"; done
    bandit -r "$TARGET" -q -f json -o "$OUT/bandit.json" -x "${excl%,}" 2>"$OUT/bandit.log"
    [[ $? -le 1 ]] && status bandit ok || status bandit error "$(tail -1 "$OUT/bandit.log")"
  else status bandit missing "bandit kurulu değil"; fi
fi

# ---------------------------------------------------------------- semgrep
if enabled semgrep; then
  if have semgrep; then
    log "semgrep: çok dilli statik analiz"
    sg_args=(scan --json --output "$OUT/semgrep.json" --metrics=off --quiet --disable-version-check)
    for d in "${PRUNE_DIRS[@]}"; do sg_args+=(--exclude "$d"); done
    local_rules=(--config "$TOOLKIT_DIR/rules/semgrep")
    [[ -d "$TARGET/.semgrep" ]] && local_rules+=(--config "$TARGET/.semgrep")
    semgrep "${sg_args[@]}" --config "${SEMGREP_CONFIG:-p/default}" "${local_rules[@]}" "$TARGET" 2>"$OUT/semgrep.log"
    rc=$?
    if [[ $rc -gt 1 ]]; then
      log "semgrep: kural kayıt defterine ulaşılamadı, yalnızca yerel kurallarla tekrar deneniyor"
      semgrep "${sg_args[@]}" "${local_rules[@]}" "$TARGET" 2>>"$OUT/semgrep.log"
      rc=$?
      [[ $rc -le 1 ]] && status semgrep partial "kayıt defteri kuralları atlandı, yalnızca yerel kurallar çalıştı" || status semgrep error "$(semgrep_error)"
    else status semgrep ok; fi
  else status semgrep missing "semgrep kurulu değil"; fi
fi

# ---------------------------------------------------------------- trivy (Dockerfile, Terraform, Kubernetes yapılandırması)
if enabled trivy && has_stack infra; then
  if have trivy; then
    log "trivy: altyapı yapılandırması"
    trivy config --quiet --format json --output "$OUT/trivy.json" \
      --skip-dirs "**/node_modules" --skip-dirs "**/.venv" "$TARGET" 2>"$OUT/trivy.log"
    [[ $? -eq 0 ]] && status trivy ok || status trivy error "$(tail -1 "$OUT/trivy.log")"
  else status trivy missing "trivy kurulu değil"; fi
fi

# ---------------------------------------------------------------- dotnet (NuGet açıkları)
if enabled dotnet && has_stack dotnet; then
  if have dotnet; then
    mapfile -t sols < <(find_files '*.sln' '*.slnx')
    [[ ${#sols[@]} -eq 0 ]] && mapfile -t sols < <(find_files '*.csproj')
    i=0; ok=1
    for s in "${sols[@]}"; do
      log "dotnet: ${s#$TARGET/}"
      # Linux'ta WinForms/WPF projelerinin restore edilebilmesi için EnableWindowsTargeting
      if dotnet restore "$s" -p:EnableWindowsTargeting=true >"$OUT/dotnet-$i.log" 2>&1; then
        dotnet list "$s" package --vulnerable --include-transitive --format json > "$OUT/dotnet-$i.json" 2>>"$OUT/dotnet-$i.log" || ok=0
      else ok=0; fi
      i=$((i+1))
    done
    (( ok )) && status dotnet ok || status dotnet error "restore başarısız (packages.config kullanan eski projeler desteklenmez), dotnet-*.log'a bakın"
  else status dotnet missing "dotnet SDK kurulu değil"; fi
fi

# ---------------------------------------------------------------- özet
python3 "$TOOLKIT_DIR/scripts/summarize.py" --reports "$OUT" --target "$TARGET" --fail-on "$FAIL_ON"
