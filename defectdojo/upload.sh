#!/usr/bin/env bash
# Bir rapor klasöründeki tüm araç çıktılarını DefectDojo'ya yükler.
# reimport-scan kullanır: her araç için engagement içinde tek bir test tutulur, düzelen
# bulgular otomatik kapanır, tekrarlar birleştirilir.
#
#   DEFECTDOJO_URL=https://dojo.ornek.com DEFECTDOJO_TOKEN=xxx \
#   defectdojo/upload.sh security-reports --product rubricator --engagement CI
set -euo pipefail

DIR="${1:?Kullanım: upload.sh <rapor-klasörü> --product AD [--engagement AD] [--product-type AD]}"; shift
PRODUCT=""; ENGAGEMENT="CI"; PRODUCT_TYPE="${DD_PRODUCT_TYPE:-Research and Development}"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --product) PRODUCT="$2"; shift ;;
    --engagement) ENGAGEMENT="$2"; shift ;;
    --product-type) PRODUCT_TYPE="$2"; shift ;;
    *) echo "Bilinmeyen seçenek: $1" >&2; exit 2 ;;
  esac
  shift
done
: "${DEFECTDOJO_URL:?DEFECTDOJO_URL tanımlı değil}" "${DEFECTDOJO_TOKEN:?DEFECTDOJO_TOKEN tanımlı değil}"
[[ -n "$PRODUCT" ]] || { echo "--product zorunlu" >&2; exit 2; }

HERE="$(cd "$(dirname "$0")" && pwd)"
API="${DEFECTDOJO_URL%/}/api/v2/reimport-scan/"
failed=0

upload() {  # upload <dosya> <scan_type> <test_title>
  local file="$1" type="$2" title="$3"
  [[ -s "$file" ]] || return 0
  echo "[defectdojo] $title ← $(basename "$file")"
  if ! curl -sS --fail-with-body -X POST "$API" \
      -H "Authorization: Token $DEFECTDOJO_TOKEN" \
      -F "scan_type=$type" -F "file=@$file" -F "test_title=$title" \
      -F "product_name=$PRODUCT" -F "engagement_name=$ENGAGEMENT" -F "product_type_name=$PRODUCT_TYPE" \
      -F auto_create_context=true -F close_old_findings=true -F active=true -F verified=false \
      -F deduplication_on_engagement=true -F "commit_hash=${GITHUB_SHA:-}" -F "branch_tag=${GITHUB_REF_NAME:-}" \
      -o /dev/null; then
    echo "[defectdojo] HATA: $title yüklenemedi" >&2; failed=1
  fi
}

upload "$DIR/gitleaks.json"  "Gitleaks Scan"        "Gitleaks"
upload "$DIR/osv.json"       "OSV Scan"             "OSV-Scanner"
upload "$DIR/bandit.json"    "Bandit Scan"          "Bandit"
upload "$DIR/semgrep.json"   "Semgrep JSON Report"  "Semgrep"
upload "$DIR/trivy.json"     "Trivy Scan"           "Trivy"
for f in "$DIR"/pip-audit-*.json; do [[ -e "$f" ]] && upload "$f" "pip-audit Scan" "pip-audit $(cat "${f%.json}.source" 2>/dev/null || basename "$f")"; done
# Derin tarama çıktıları
upload "$DIR/zap.xml"        "ZAP Scan"             "OWASP ZAP"
upload "$DIR/mobsf.json"     "MobSF Scan"           "MobSF"
# DefectDojo'da ayrıştırıcısı olmayan araçlar (dotnet) normalize bulgulardan genel formata çevrilir
if [[ -f "$DIR/findings.json" ]]; then
  python3 "$HERE/to_generic.py" "$DIR/findings.json" --tools dotnet > "$DIR/_generic-dotnet.json"
  upload "$DIR/_generic-dotnet.json" "Generic Findings Import" "dotnet NuGet"
fi

exit $failed
