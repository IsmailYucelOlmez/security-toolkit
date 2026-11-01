#!/usr/bin/env bash
# /src'ye bağlanan projeyi tarar; raporları /src/security-reports'a yazar ve
# dosyaların sahipliğini proje klasörünün sahibine geri verir.
set -uo pipefail

if [[ ! -d /src ]] || [[ -z "$(ls -A /src 2>/dev/null)" ]]; then
  echo "Proje bağlanmamış. Kullanım: docker run --rm -v \"\$PWD:/src\" security-toolkit [seçenekler]" >&2
  exit 2
fi

/opt/security-toolkit/scripts/scan.sh --path /src --out /src/security-reports "$@"
rc=$?

owner="$(stat -c '%u:%g' /src)"
[[ "$owner" != "0:0" ]] && chown -R "$owner" /src/security-reports 2>/dev/null
exit $rc
