#!/usr/bin/env bash
# Strix'i çalıştırır ve sonucu özetler.
#
# Ortam değişkenleri:
#   MODE            tarama modu
#   TARGET_DIR      taranacak kaynak kod dizini
#   BASE            isteğe bağlı canlı hedef adresi
#   AUTH_HEADER_A   test kullanıcısının Authorization değeri
#   AUTH_HEADER_B   ikinci kullanıcı
#   STRIX_LLM, LLM_API_KEY  zorunlu
#
# Token'lar komut satırına değil geçici talimat dosyasına yazılır. Strix talimatı LLM sağlayıcısına
# gönderir ve strix_runs/ altına kaydeder; bu yüzden yalnızca staging hesabı ve kısa ömürlü token kullanın,
# artifact'ten önce scripts/redact_tokens.py çalıştırın.
#
# Çıkış kodu: 0 = tarama tamamlandı (bulgu olsa da), 1 = tarama çalışamadı
set -uo pipefail

SUMMARY="${GITHUB_STEP_SUMMARY:-/dev/stdout}"

if [[ -z "${STRIX_LLM:-}" || -z "${LLM_API_KEY:-}" ]]; then
  echo "::error::STRIX_LLM ve LLM_API_KEY secret'ları tanımlı değil."
  exit 1
fi

args=(-n -t "$TARGET_DIR" --scan-mode "$MODE")
[[ -n "${BASE:-}" ]] && args+=(-t "$BASE")

coverage="Canlı test yalnızca girişsiz yüzeyi kapsadı; girişli alanlar için temiz sonuç çıkarılamaz."
if [[ -n "${AUTH_HEADER_A:-}" ]]; then
  instructions="$(mktemp)"
  trap 'rm -f "$instructions"' EXIT
  chmod 600 "$instructions"
  {
    echo "Perform authenticated testing. Send this header for test user A: Authorization: $AUTH_HEADER_A"
    if [[ -n "${AUTH_HEADER_B:-}" ]]; then
      echo "Test user B: Authorization: $AUTH_HEADER_B"
      echo "Use both users to check whether one user can read or change objects owned by the other (IDOR)."
      coverage="Canlı test iki test kullanıcısıyla yapıldı."
    else
      coverage="Canlı test tek test kullanıcısıyla yapıldı; kullanıcılar arası erişim (IDOR) kanıtlanamaz."
    fi
  } > "$instructions"
  args+=(--instruction-file "$instructions")
fi
[[ -z "${BASE:-}" ]] && coverage="Canlı hedef verilmedi; yalnızca kaynak kod incelendi."

strix "${args[@]}"
rc=$?

{
  echo "## 🦉 Strix"
  echo
  case "$rc" in
    0) echo "Doğrulanmış açık bulunmadı." ;;
    2) echo "🔴 Strix doğrulanmış bulgu raporladı. Ayrıntılar \`deep-strix\` artifact'inde." ;;
    *) echo "🔴 **Tarama çalışamadı** (çıkış kodu $rc). Bu sonuç açık olmadığı anlamına gelmez." ;;
  esac
  echo
  echo "$coverage"
} >> "$SUMMARY"

[[ $rc -eq 0 || $rc -eq 2 ]] || exit 1
