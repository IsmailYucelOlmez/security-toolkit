#!/usr/bin/env bash
# Güvenlik tarama araçlarını tek bir dizine kurar.
#
#   scripts/install-tools.sh [--with-dotnet] [--only gitleaks,osv,trivy,python]
#
# Kurulum dizini: $SECURITY_TOOLS_DIR (varsayılan: ~/.security-tools)
# Sürümler ve SHA-256 özetleri scripts/tool-checksums.txt dosyasındadır; özeti tutmayan dosya kurulmaz.
# Sürüm yükseltmek için: scripts/update-tool-checksums.sh
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
case "$OS" in Linux) os=linux ;; Darwin) os=darwin ;; MINGW*|MSYS*|CYGWIN*) os=windows ;; *) echo "Desteklenmeyen işletim sistemi: $OS" >&2; exit 1 ;; esac
case "$ARCH" in x86_64|amd64) arch=amd64 ;; arm64|aarch64) arch=arm64 ;; *) echo "Desteklenmeyen mimari: $ARCH" >&2; exit 1 ;; esac

fetch() { curl -fsSL --retry 3 -o "$2" "$1"; }

# Windows'ta python3 çoğunlukla yoktur veya Microsoft Store yönlendirmesidir
if python3 -c '' >/dev/null 2>&1; then PYTHON=python3; else PYTHON=python; fi

CHECKSUMS="$(dirname "$0")/tool-checksums.txt"
pinned_version() {
  local v; v="$(tr -d '\r' < "$CHECKSUMS" | awk -v t="$1" '$1 == t { print $2; exit }')"
  [[ -n "$v" ]] || { echo "$1 için $CHECKSUMS içinde sürüm yok" >&2; exit 1; }
  echo "$v"
}

# fetch_verified <url> <hedef>: dosya adını manifestte arar, özet tutmazsa dosyayı silip durur
fetch_verified() {
  local asset="${1##*/}" expected actual
  expected="$(tr -d '\r' < "$CHECKSUMS" | awk -v a="$asset" '$3 == a { print $4; exit }')"
  [[ -n "$expected" ]] || { echo "$asset için $CHECKSUMS içinde özet yok" >&2; exit 1; }
  fetch "$1" "$2"
  actual="$("$PYTHON" -c 'import hashlib, sys; print(hashlib.sha256(open(sys.argv[1], "rb").read()).hexdigest())' "$2")"
  if [[ "$actual" != "$expected" ]]; then
    rm -f "$2"
    echo "$asset özeti tutmuyor: beklenen $expected, gelen $actual" >&2
    exit 1
  fi
}

unzip_to() { "$PYTHON" -c 'import sys, zipfile; zipfile.ZipFile(sys.argv[1]).extractall(sys.argv[2])' "$1" "$2"; }

require_windows_amd64() {
  [[ $arch == amd64 ]] || { echo "$1 için Windows $arch sürümü desteklenmiyor" >&2; exit 1; }
}

install_gitleaks() {
  local v; v="$(pinned_version gitleaks)"
  local a; [[ $arch == amd64 ]] && a=x64 || a=arm64
  local tmp; tmp="$(mktemp -d)"
  if [[ $os == windows ]]; then
    require_windows_amd64 gitleaks
    fetch_verified "https://github.com/gitleaks/gitleaks/releases/download/v${v}/gitleaks_${v}_windows_x64.zip" "$tmp/g.zip"
    unzip_to "$tmp/g.zip" "$tmp" && cp "$tmp/gitleaks.exe" "$BIN_DIR/gitleaks.exe"
  else
    fetch_verified "https://github.com/gitleaks/gitleaks/releases/download/v${v}/gitleaks_${v}_${os}_${a}.tar.gz" "$tmp/g.tgz"
    tar -xzf "$tmp/g.tgz" -C "$tmp" gitleaks && install -m 0755 "$tmp/gitleaks" "$BIN_DIR/gitleaks"
  fi
  rm -rf "$tmp"; log "gitleaks $v"
}

install_osv() {
  local v; v="$(pinned_version osv-scanner)"
  if [[ $os == windows ]]; then
    require_windows_amd64 osv-scanner
    fetch_verified "https://github.com/google/osv-scanner/releases/download/v${v}/osv-scanner_windows_amd64.exe" "$BIN_DIR/osv-scanner.exe"
  else
    fetch_verified "https://github.com/google/osv-scanner/releases/download/v${v}/osv-scanner_${os}_${arch}" "$BIN_DIR/osv-scanner"
    chmod 0755 "$BIN_DIR/osv-scanner"
  fi
  log "osv-scanner $v"
}

install_trivy() {
  local v; v="$(pinned_version trivy)"
  local o a
  [[ $os == linux ]] && o=Linux || o=macOS
  [[ $arch == amd64 ]] && a=64bit || a=ARM64
  local tmp; tmp="$(mktemp -d)"
  if [[ $os == windows ]]; then
    require_windows_amd64 trivy
    fetch_verified "https://github.com/aquasecurity/trivy/releases/download/v${v}/trivy_${v}_windows-64bit.zip" "$tmp/t.zip"
    unzip_to "$tmp/t.zip" "$tmp" && cp "$tmp/trivy.exe" "$BIN_DIR/trivy.exe"
  else
    fetch_verified "https://github.com/aquasecurity/trivy/releases/download/v${v}/trivy_${v}_${o}-${a}.tar.gz" "$tmp/t.tgz"
    tar -xzf "$tmp/t.tgz" -C "$tmp" trivy && install -m 0755 "$tmp/trivy" "$BIN_DIR/trivy"
  fi
  rm -rf "$tmp"; log "trivy $v"
}

install_python_tools() {
  "$PYTHON" -m venv "$VENV_DIR"
  # Windows'ta sanal ortam Scripts altındadır; scan.sh bu dizini PATH'e ekler
  local venv_bin="$VENV_DIR/bin"; [[ $os == windows ]] && venv_bin="$VENV_DIR/Scripts"
  "$venv_bin/python" -m pip install -q --upgrade pip
  # Sürümler requirements dosyasında sabit; Dependabot bu dosyayı günceller.
  "$venv_bin/python" -m pip install -q -r "$(dirname "$0")/requirements-tools.txt"
  if [[ $os != windows ]]; then
    for t in bandit pip-audit semgrep; do ln -sf "$venv_bin/$t" "$BIN_DIR/$t"; done
  fi
  log "python araçları: $("$venv_bin/bandit" --version 2>/dev/null | head -1), pip-audit, semgrep"
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
