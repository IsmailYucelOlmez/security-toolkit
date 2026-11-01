#!/usr/bin/env bash
# Güvenlik tarama araçlarını tek bir dizine kurar.
#
#   scripts/install-tools.sh [--with-dotnet] [--only gitleaks,osv,trivy,python]
#
# Kurulum dizini: $SECURITY_TOOLS_DIR (varsayılan: ~/.security-tools)
# Sürüm sabitlemek için: GITLEAKS_VERSION=8.28.0 OSV_SCANNER_VERSION=2.2.4 TRIVY_VERSION=0.67.2
# (boş bırakılırsa GitHub'daki en son sürüm kullanılır)
set -euo pipefail

TOOLS_DIR="${SECURITY_TOOLS_DIR:-$HOME/.security-tools}"
BIN_DIR="$TOOLS_DIR/bin"
VENV_DIR="$TOOLS_DIR/venv"
WITH_DOTNET=0
ONLY="gitleaks,osv,trivy,python"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --with-dotnet) WITH_DOTNET=1 ;;
    --only) ONLY="$2"; shift ;;
    -h|--help) sed -n '2,9p' "$0"; exit 0 ;;
    *) echo "Bilinmeyen seçenek: $1" >&2; exit 2 ;;
  esac
  shift
done

want() { [[ ",$ONLY," == *",$1,"* ]]; }
log()  { echo "[install-tools] $*"; }

mkdir -p "$BIN_DIR"

OS="$(uname -s)"; ARCH="$(uname -m)"
case "$OS" in Linux) os=linux ;; Darwin) os=darwin ;; *) echo "Desteklenmeyen işletim sistemi: $OS" >&2; exit 1 ;; esac
case "$ARCH" in x86_64|amd64) arch=amd64 ;; arm64|aarch64) arch=arm64 ;; *) echo "Desteklenmeyen mimari: $ARCH" >&2; exit 1 ;; esac

# GitHub API kotasına takılmamak için /releases/latest yönlendirmesinden etiketi okur.
latest_tag() {
  curl -fsSLI -o /dev/null -w '%{url_effective}' "https://github.com/$1/releases/latest" | sed 's#.*/tag/##'
}

fetch() { curl -fsSL --retry 3 -o "$2" "$1"; }

install_gitleaks() {
  local v="${GITLEAKS_VERSION:-}"; [[ -z "$v" ]] && v="$(latest_tag gitleaks/gitleaks)"; v="${v#v}"
  local a; [[ $arch == amd64 ]] && a=x64 || a=arm64
  local tmp; tmp="$(mktemp -d)"
  fetch "https://github.com/gitleaks/gitleaks/releases/download/v${v}/gitleaks_${v}_${os}_${a}.tar.gz" "$tmp/g.tgz"
  tar -xzf "$tmp/g.tgz" -C "$tmp" gitleaks && install -m 0755 "$tmp/gitleaks" "$BIN_DIR/gitleaks"
  rm -rf "$tmp"; log "gitleaks $v"
}

install_osv() {
  local v="${OSV_SCANNER_VERSION:-}"; [[ -z "$v" ]] && v="$(latest_tag google/osv-scanner)"; v="${v#v}"
  fetch "https://github.com/google/osv-scanner/releases/download/v${v}/osv-scanner_${os}_${arch}" "$BIN_DIR/osv-scanner"
  chmod 0755 "$BIN_DIR/osv-scanner"; log "osv-scanner $v"
}

install_trivy() {
  local v="${TRIVY_VERSION:-}"; [[ -z "$v" ]] && v="$(latest_tag aquasecurity/trivy)"; v="${v#v}"
  local o a
  [[ $os == linux ]] && o=Linux || o=macOS
  [[ $arch == amd64 ]] && a=64bit || a=ARM64
  local tmp; tmp="$(mktemp -d)"
  fetch "https://github.com/aquasecurity/trivy/releases/download/v${v}/trivy_${v}_${o}-${a}.tar.gz" "$tmp/t.tgz"
  tar -xzf "$tmp/t.tgz" -C "$tmp" trivy && install -m 0755 "$tmp/trivy" "$BIN_DIR/trivy"
  rm -rf "$tmp"; log "trivy $v"
}

install_python_tools() {
  python3 -m venv "$VENV_DIR"
  "$VENV_DIR/bin/pip" install -q --upgrade pip
  # Sürümler requirements dosyasında sabit; Dependabot bu dosyayı günceller.
  "$VENV_DIR/bin/pip" install -q -r "$(dirname "$0")/requirements-tools.txt"
  for t in bandit pip-audit semgrep; do ln -sf "$VENV_DIR/bin/$t" "$BIN_DIR/$t"; done
  log "python araçları: $("$VENV_DIR/bin/bandit" --version 2>/dev/null | head -1), pip-audit, semgrep"
}

install_dotnet() {
  if command -v dotnet >/dev/null 2>&1; then log "dotnet zaten kurulu: $(dotnet --version)"; return; fi
  local tmp; tmp="$(mktemp -d)"
  fetch https://dot.net/v1/dotnet-install.sh "$tmp/dotnet-install.sh"
  bash "$tmp/dotnet-install.sh" --channel LTS --install-dir "$TOOLS_DIR/dotnet" >/dev/null
  ln -sf "$TOOLS_DIR/dotnet/dotnet" "$BIN_DIR/dotnet"
  rm -rf "$tmp"; log "dotnet $("$BIN_DIR/dotnet" --version)"
}

want gitleaks && install_gitleaks
want osv      && install_osv
want trivy    && install_trivy
want python   && install_python_tools
(( WITH_DOTNET )) && install_dotnet

# GitHub Actions içindeysek PATH'e kalıcı ekle
if [[ -n "${GITHUB_PATH:-}" ]]; then echo "$BIN_DIR" >> "$GITHUB_PATH"; fi
log "Tamamlandı. PATH'e ekleyin: export PATH=\"$BIN_DIR:\$PATH\""
