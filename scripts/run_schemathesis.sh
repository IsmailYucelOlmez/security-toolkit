#!/usr/bin/env bash
# Schemathesis'i çalıştırır ve özeti yazar.
#
# Ortam değişkenleri:
#   OPENAPI, MAX_TIME   şema adresi ve süre bütçesi (saniye)
#   BASE                isteğe bağlı taban adres
#   REPORT_DIR          rapor dizini (varsayılan deep-reports/schemathesis)
#   AUTH_HEADER_A       test kullanıcısının Authorization değeri
#   AUTH_HEADER_B       ikinci kullanıcı; verilirse IDOR kontrolü (object_level_authorization) açılır
#
# Çıkış kodu: 0 = yetki hatası yok, 1 = yetki hatası var veya tarama çalışamadı
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
PYTHON="${PYTHON:-python3}"
OUT="${REPORT_DIR:-deep-reports/schemathesis}"

global=()
args=("$OPENAPI" --checks all --max-time "$MAX_TIME" --wait-for-schema 60
      --report "junit,har" --report-dir "$OUT")
[[ -n "${BASE:-}" ]] && args+=(--url "$BASE")

peers=()
if [[ -n "${AUTH_HEADER_B:-}" ]]; then
  cfg="$(mktemp -d)"
  trap 'rm -rf "$cfg"' EXIT
  "$PYTHON" "$HERE/schemathesis_config.py" "$cfg" || exit 1
  global=(--config-file "$cfg/schemathesis.toml")
  peers=(--peers)
elif [[ -n "${AUTH_HEADER_A:-}" ]]; then
  args+=(-H "Authorization: $AUTH_HEADER_A")
fi

schemathesis "${global[@]}" run "${args[@]}"
rc=$?
echo "Schemathesis çıkış kodu: $rc"

"$PYTHON" "$HERE/schemathesis_report.py" "$OUT" "$rc" "${peers[@]}" >> "${GITHUB_STEP_SUMMARY:-/dev/stdout}"
