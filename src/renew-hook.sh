#!/usr/bin/env bash
# Nuvrion · release 1.0.0
set -Eeuo pipefail
BASE=/opt/remnanode
[[ -f $BASE/.nuvrion-managed ]] || exit 0
domain=$(python3 -c 'import json;print(json.load(open("/opt/remnanode/settings.json",encoding="utf-8"))["domain"])')
[[ ${RENEWED_LINEAGE:-} == "/etc/letsencrypt/live/$domain" ]] || exit 0
docker exec remnanode xray run -test -config /opt/nuvrion/profile.json
# A successful renewal triggers a short node restart; the panel restores active config.
docker restart remnanode >/dev/null
