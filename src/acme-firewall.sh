#!/usr/bin/env bash
# Nuvrion · release 1.0.0
set -Eeuo pipefail
export LC_ALL=C
# Only rules with this exact owned comment are removed. Never reset the firewall.
readonly OWN_COMMENT=Nuvrion-Vision-ACME-temporary
readonly LEASE=/run/nuvrion-vision-acme-open
# Та же блокировка, что у Traffic Control; держится только на время изменения.
umask 077
exec 9>/run/nuvrion-traffic-control.lock
flock -w 360 9
remove_own_rules() {
    local n rules numbers
    rules=$(ufw status numbered) || return 1
    numbers=$(awk -v comment="$OWN_COMMENT" '
      $0 ~ ("# " comment "[[:space:]]*$") {
        if(match($0,/\[[ ]*[0-9]+\]/)) {
          n=substr($0,RSTART,RLENGTH);gsub(/[^0-9]/,"",n);print n
        }
      }' <<< "$rules" | sort -rn) || return 1
    while IFS= read -r n; do
        [[ $n =~ ^[0-9]+$ ]] || continue
        ufw --force delete "$n" >/dev/null
    done <<< "$numbers"
}
traffic_control_present() {
    local tables
    tables=$(nft list tables) || return 2
    grep -Fxq 'table inet nuvrion_tc' <<< "$tables"
}
remove_own_traffic_control_rules() {
    local handle rules handles rc=0
    traffic_control_present || rc=$?
    [[ $rc != 1 ]] || return 0
    [[ $rc == 0 ]] || return 1
    rules=$(nft -a list chain inet nuvrion_tc ingress) || return 1
    handles=$(awk -v comment="$OWN_COMMENT" \
      'index($0,"comment \"" comment "\"") {for(i=1;i<=NF;i++) if($i=="handle") print $(i+1)}' <<< "$rules") || return 1
    while IFS= read -r handle; do
        [[ $handle =~ ^[0-9]+$ ]] || continue
        nft delete rule inet nuvrion_tc ingress handle "$handle"
    done <<< "$handles"
}
case "${1:-}" in
    open)
        ufw status | awk '/^Status: active$/ {ok=1} END {exit !ok}'
        remove_own_rules
        remove_own_traffic_control_rules
        # Traffic Control runs before UFW. Its temporary return lets the ACME
        # validator reach the UFW rule without weakening any other port.
        rc=0
        traffic_control_present || rc=$?
        [[ $rc != 2 ]] || exit 1
        [[ ! -L $LEASE ]] || exit 1
        date +%s > "$LEASE"
        if [[ $rc == 0 ]]; then
            nft insert rule inet nuvrion_tc ingress tcp dport 80 counter return comment "$OWN_COMMENT"
        fi
        ufw insert 1 allow 80/tcp comment "$OWN_COMMENT" >/dev/null
        ;;
    close)
        remove_own_rules
        remove_own_traffic_control_rules
        rm -f -- "$LEASE"
        ;;
    *) printf 'Использование: acme-firewall.sh {open|close}\n' >&2; exit 2;;
esac
