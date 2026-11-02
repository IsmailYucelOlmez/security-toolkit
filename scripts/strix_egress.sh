#!/usr/bin/env bash
# Strix sandbox konteynerlerinin ağ çıkışını DNS ve staging adresleriyle sınırlar. Hedef ajanı ele
# geçirirse sandbox'tan sır veya veri dışarı taşınmasın diye. LLM çağrıları konteynerin dışından
# yapıldığı için etkilenmez. Runner geçici olduğu için kurallar işle birlikte silinir.
#
# Ortam değişkeni: BASE (boşsa konteynerler yalnızca DNS'e erişir)
# Çıkış kodu: 0 = kurallar uygulandı, 1 = uygulanamadı
set -euo pipefail

ips=()
if [[ -n "${BASE:-}" ]]; then
  host="${BASE#*://}"; host="${host%%[/:]*}"
  mapfile -t ips < <(getent ahostsv4 "$host" | awk '{print $1}' | sort -u)
  if [[ ${#ips[@]} -eq 0 ]]; then
    echo "::error::$host çözümlenemedi; ağ kısıtı uygulanamadı."
    exit 1
  fi
fi

ipt() { sudo iptables "$@"; }
ipt -F DOCKER-USER
ipt -A DOCKER-USER -m conntrack --ctstate RELATED,ESTABLISHED -j RETURN
ipt -A DOCKER-USER -p udp --dport 53 -j RETURN
ipt -A DOCKER-USER -p tcp --dport 53 -j RETURN
for ip in "${ips[@]}"; do
  ipt -A DOCKER-USER -d "$ip" -j RETURN
done
ipt -A DOCKER-USER -j DROP
echo "Sandbox çıkışı sınırlandı: DNS ve ${#ips[@]} hedef adresi."
