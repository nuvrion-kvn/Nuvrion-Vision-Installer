#!/usr/bin/env bash
# Nuvrion · release 1.0.0
set -Eeuo pipefail
export LC_ALL=C.UTF-8

readonly TABLE=nuvrion_privacy

start() {
    if ! nft list table inet "$TABLE" >/dev/null 2>&1; then
        nft add table inet "$TABLE"
    fi
    nft -f - <<'NFT'
flush table inet nuvrion_privacy

add chain inet nuvrion_privacy privacy_input { type filter hook input priority -20; policy accept; }

add rule inet nuvrion_privacy privacy_input ip protocol icmp icmp type echo-request counter drop comment "Nuvrion: block ICMP echo"
add rule inet nuvrion_privacy privacy_input ip protocol icmp icmp type timestamp-request counter drop comment "Nuvrion: block ICMP timestamp"
add rule inet nuvrion_privacy privacy_input meta l4proto ipv6-icmp icmpv6 type echo-request counter drop comment "Nuvrion: block ICMPv6 echo"
NFT
}

stop() {
    if nft list table inet "$TABLE" >/dev/null 2>&1; then
        nft delete table inet "$TABLE"
    fi
}

status() {
    nft list table inet "$TABLE"
}

case "${1:-start}" in
    start) start;;
    stop) stop;;
    restart) stop; start;;
    status) status;;
    *) printf 'Использование: %s {start|stop|restart|status}\n' "$0" >&2; exit 2;;
esac
