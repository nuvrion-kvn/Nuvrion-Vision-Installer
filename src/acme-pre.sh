#!/usr/bin/env bash
# Nuvrion · release 1.0.0
set -Eeuo pipefail
[[ -f /opt/remnanode/.nuvrion-managed ]] || exit 0
[[ -x /opt/remnanode/acme-firewall.sh ]] || {
    printf '  ✗ ОШИБКА: не найден обработчик firewall установленной ноды\n' >&2
    exit 1
}
exec /opt/remnanode/acme-firewall.sh open
