#!/usr/bin/env bash
# scripts/tool-checksums.txt dosyasını üretir: install-tools.sh yalnızca buradaki sürüm ve özetleri kabul eder.
#
#   scripts/update-tool-checksums.sh <gitleaks-sürümü> <osv-scanner-sürümü> <trivy-sürümü>
#
# Özetler yayımcının kendi checksum dosyasından alınır. Yeni sürümü sürüm notlarını okuduktan sonra verin:
# bu betik sürümün güvenilir olduğunu değil, yalnızca sonradan değişmediğini garanti eder.
set -euo pipefail

[[ $# -eq 3 ]] || { sed -n '2,7p' "$0"; exit 2; }
gitleaks="${1#v}"; osv="${2#v}"; trivy="${3#v}"
out="$(dirname "$0")/tool-checksums.txt"
tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT

add() {  # add <araç> <sürüm> <checksum-url> <dosya>...
  local tool="$1" version="$2" url="$3" sums asset sha; shift 3
  sums="$(curl -fsSL --retry 3 "$url" | tr -d '\r')"
  for asset in "$@"; do
    sha="$(awk -v a="$asset" '{ f=$2; sub(/^[*.\/]+/, "", f); if (f == a) print $1 }' <<<"$sums")"
    [[ "$sha" =~ ^[0-9a-f]{64}$ ]] || { echo "$tool: $asset için özet bulunamadı" >&2; exit 1; }
    echo "$tool $version $asset $sha" >> "$tmp"
  done
}

{
  echo "# Üretildi: scripts/update-tool-checksums.sh. Elle değiştirmeyin."
  echo "# araç sürüm dosya sha256"
} > "$tmp"
add gitleaks "$gitleaks" "https://github.com/gitleaks/gitleaks/releases/download/v$gitleaks/gitleaks_${gitleaks}_checksums.txt" \
  "gitleaks_${gitleaks}_linux_x64.tar.gz" "gitleaks_${gitleaks}_linux_arm64.tar.gz" \
  "gitleaks_${gitleaks}_darwin_x64.tar.gz" "gitleaks_${gitleaks}_darwin_arm64.tar.gz" \
  "gitleaks_${gitleaks}_windows_x64.zip"
add osv-scanner "$osv" "https://github.com/google/osv-scanner/releases/download/v$osv/osv-scanner_SHA256SUMS" \
  osv-scanner_linux_amd64 osv-scanner_linux_arm64 osv-scanner_darwin_amd64 osv-scanner_darwin_arm64 \
  osv-scanner_windows_amd64.exe
add trivy "$trivy" "https://github.com/aquasecurity/trivy/releases/download/v$trivy/trivy_${trivy}_checksums.txt" \
  "trivy_${trivy}_Linux-64bit.tar.gz" "trivy_${trivy}_Linux-ARM64.tar.gz" \
  "trivy_${trivy}_macOS-64bit.tar.gz" "trivy_${trivy}_macOS-ARM64.tar.gz" \
  "trivy_${trivy}_windows-64bit.zip"
cp "$tmp" "$out"
echo "Yazıldı: $out"
