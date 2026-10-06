#!/usr/bin/env bash
# Nuvrion · release 1.0.0
# ==============================================================================
# Nuvrion Auto Tuning
# Автоматическая оптимизация и защита Linux-серверов
#
# Автор и разработчик: Nuvrion
# GitHub: nuvrion-kvn
# Email: himik0011113@gmail.com
#
# Copyright (c) 2026 Nuvrion
# SPDX-License-Identifier: MIT
#
# Исходный код: https://github.com/nuvrion-kvn/Nuvrion-Auto-Tuning
# Лицензия применяется к оригинальному коду Nuvrion. Сторонние компоненты
# сохраняют собственные лицензии и авторские права.
# ==============================================================================
set -Eeuo pipefail
export LC_ALL=C.UTF-8

# ============================================================
# Nuvrion — адаптивная оптимизация сети v1.0.0
# Author: Nuvrion
# Debian / Ubuntu / Xray / Remnawave
#
# Основные env-флаги публичной версии:
#   NUVRION_SECURITY=0                    — отключить блок безопасности
#   NUVRION_INSTALL_SECURITY_PACKAGES=0   — не устанавливать пакеты автоматически
#   NUVRION_ENABLE_UFW=1|0                — включить/пропустить UFW без вопроса
#   NUVRION_PANEL_IPS="203.0.113.10"       — IP/CIDR панели Remnawave
#   NUVRION_PANEL_PORT=PORT               — явно задать порт API Remnawave Node
#   NUVRION_FIREWALL_PORTS="tcp:8443,udp:8443" — дополнительные разрешённые порты
#   NUVRION_HARDEN_SSH=1                  — key-only SSH, только при готовом authorized_keys
#   NUVRION_ALLOW_DOCKER_RESTART=1        — разрешить редкий fallback с restart Docker
#   NUVRION_SYSTEM_MAINTENANCE=0           — отключить NTP/fstrim/диск-аудит
#   NUVRION_INSTALL_ZRAM_PACKAGES=0        — не устанавливать недостающие компоненты ZRAM
#   NUVRION_POST_REBOOT_CHECK=0            — не планировать самопроверку после reboot
#   NUVRION_CERTIFICATES=0                  — отключить аудит/автонастройку сертификатов
#   NUVRION_CERTBOT_DRY_RUN=0               — не выполнять периодический certbot renew --dry-run
#   NUVRION_ASSUME_YES=1                    — пропустить стартовое подтверждение в автоматизации
# Скрипт НЕ создаёт и НЕ добавляет SSH-ключи.
# ============================================================

WARNINGS=0
CONFLICTS=0
SKIPPED=0

# ------------------------------------------------------------
# Оформление вывода
# Цвета используются только в интерактивном терминале.
# NO_COLOR=1 отключает ANSI-цвета для журналов/автоматизации.
# ------------------------------------------------------------
if [[ -t 1 && ! ${NO_COLOR+x} && ${TERM:-dumb} != dumb ]]; then
    C_RESET=$'\033[0m'
    C_BOLD=$'\033[1m'
    C_DIM=$'\033[2m'
    C_RED=$'\033[31m'
    C_GREEN=$'\033[32m'
    C_YELLOW=$'\033[33m'
    C_BLUE=$'\033[34m'
    C_MAGENTA=$'\033[35m'
    C_CYAN=$'\033[36m'
else
    C_RESET=''
    C_BOLD=''
    C_DIM=''
    C_RED=''
    C_GREEN=''
    C_YELLOW=''
    C_BLUE=''
    C_MAGENTA=''
    C_CYAN=''
fi

UI_LINE='────────────────────────────────────────────────────────────'

section() {
    printf '\n%s%s┌─ %s%s\n' "$C_BOLD" "$C_BLUE" "$*" "$C_RESET"
    printf '%s└%s%s\n' "$C_DIM" "$UI_LINE" "$C_RESET"
}

on_error() {
    local rc=$?
    printf '\n%s%s[ ОШИБКА ]%s строка %s: %s (код %s)\n' "$C_BOLD" "$C_RED" "$C_RESET" "$1" "$2" "$rc" >&2
    exit "$rc"
}
trap 'on_error "$LINENO" "$BASH_COMMAND"' ERR

warn() {
    printf '%s%s[ ВНИМАНИЕ ]%s %s\n' "$C_BOLD" "$C_YELLOW" "$C_RESET" "$*"
    WARNINGS=$((WARNINGS + 1))
}

conflict() {
    printf '%s%s[ КОНФЛИКТ ]%s %s\n' "$C_BOLD" "$C_RED" "$C_RESET" "$*"
    CONFLICTS=$((CONFLICTS + 1))
}

info() {
    printf '%s[ ИНФО ]%s %s\n' "$C_CYAN" "$C_RESET" "$*"
}

ok() {
    printf '%s%s[  OK  ]%s %s\n' "$C_BOLD" "$C_GREEN" "$C_RESET" "$*"
}

choice_hint_yes_no() {
    printf '%s%s  Д — да   ·   Н — нет (Enter)%s\n' "$C_BOLD" "$C_YELLOW" "$C_RESET"
}

choice_hint_yes_no_skip() {
    printf '%s%s  Д — да   ·   Н — нет   ·   П — пропустить (Enter)%s\n' "$C_BOLD" "$C_YELLOW" "$C_RESET"
}

choice_hint_skip() {
    printf '%s%s  П — пропустить этот этап%s\n' "$C_BOLD" "$C_YELLOW" "$C_RESET"
}

prompt_yes_no() {
    local text=$1 answer
    [[ -t 0 ]] || return 1
    printf '\n%s%s[?] %s%s\n' "$C_BOLD" "$C_YELLOW" "$text" "$C_RESET"
    choice_hint_yes_no
    while true; do
        printf '%s%sВаш выбор [Д/Н; Enter — Н]: %s' "$C_BOLD" "$C_YELLOW" "$C_RESET"
        IFS= read -r answer || return 1
        case "${answer,,}" in
            д|Д|да|ДА|Да|y|Y|yes|YES|Yes) return 0 ;;
            н|Н|нет|НЕТ|Нет|n|N|no|NO|No|'') return 1 ;;
            *) printf '%sВведите Д — да или Н — нет.%s\n' "$C_YELLOW" "$C_RESET" ;;
        esac
    done
}

prompt_choice_yes_no_skip() {
    local text=$1 answer
    [[ -t 0 ]] || return 3
    printf '\n%s%s[?] %s%s\n' "$C_BOLD" "$C_YELLOW" "$text" "$C_RESET"
    choice_hint_yes_no_skip
    while true; do
        printf '%s%sВаш выбор [Д/Н/П; Enter — П]: %s' "$C_BOLD" "$C_YELLOW" "$C_RESET"
        IFS= read -r answer || return 3
        case "${answer,,}" in
            д|Д|да|ДА|Да|y|Y|yes|YES|Yes) return 0 ;;
            н|Н|нет|НЕТ|Нет|n|N|no|NO|No) return 1 ;;
            п|П|пропустить|ПРОПУСТИТЬ|Пропустить|s|S|skip|SKIP|Skip|'') return 2 ;;
            *) printf '%sВведите Д — да, Н — нет или П — пропустить.%s\n' "$C_YELLOW" "$C_RESET" ;;
        esac
    done
}

show_intro() {
    printf '\n%s%s╭%s╮%s\n' "$C_BOLD" "$C_CYAN" "$UI_LINE" "$C_RESET"
    printf '%s%s│  Nuvrion · АДАПТИВНАЯ ОПТИМИЗАЦИЯ СЕРВЕРА · v1.0.0%s\n' "$C_BOLD" "$C_CYAN" "$C_RESET"
    printf '%s%s╰%s╯%s\n' "$C_BOLD" "$C_CYAN" "$UI_LINE" "$C_RESET"
    printf '\n%sЧто делает скрипт:%s\n' "$C_BOLD" "$C_RESET"
    printf '  ◆ Оптимизирует сеть: BBR/fq, TCP/UDP-буферы, backlog и conntrack.\n'
    printf '  ◆ Проверяет и восстанавливает ZRAM; при необходимости устанавливает компоненты.\n'
    printf '  ◆ Настраивает распределение сетевой нагрузки и лимиты Remnawave Node.\n'
    printf '  ◆ Усиливает безопасные sysctl-параметры и проверяет SSH, Fail2ban и firewall.\n'
    printf '  ◆ Проверяет защиту API панели Remnawave и чувствительные публичные порты.\n'
    printf '  ◆ Проверяет security-updates, NTP, TRIM, диск/inode и сертификаты.\n'
    printf '  ◆ Создаёт снимки состояния и планирует контроль после перезагрузки.\n'
    printf '\n%sПринцип работы:%s настройки рассчитываются по CPU/RAM; рабочие сторонние\n' "$C_BOLD" "$C_RESET"
    printf 'конфигурации не перезаписываются без необходимости. Некоторые недостающие\n'
    printf 'пакеты и systemd-компоненты могут быть установлены автоматически.\n'
    printf '\n%s%s%s\n' "$C_DIM" "$UI_LINE" "$C_RESET"
}

show_intro
if [[ ${NUVRION_ASSUME_YES:-0} != 1 && -t 0 ]]; then
    if ! prompt_yes_no "Продолжить установку скрипта?"; then
        printf '\n%s[ ОТМЕНЕНО ]%s Установка и применение настроек не выполнялись.\n' "$C_YELLOW" "$C_RESET"
        exit 0
    fi
elif [[ ${NUVRION_ASSUME_YES:-0} == 1 ]]; then
    info "Стартовое подтверждение пропущено: NUVRION_ASSUME_YES=1."
else
    info "Неинтерактивный запуск: стартовое подтверждение пропущено автоматически."
fi

need_cmd() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "ОШИБКА: не найдена обязательная команда: $1" >&2
        exit 1
    }
}

normalize_ws() {
    awk '{$1=$1; print}' <<<"${1:-}"
}

num_or_zero() {
    local v=${1:-0}
    if [[ $v =~ ^[0-9]+$ ]]; then
        printf '%s' "$v"
    else
        printf '0'
    fi
}

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
    echo "ОШИБКА: запустите скрипт от root" >&2
    exit 1
fi

for c in awk grep sort sysctl nproc uname mktemp basename cp mv rm mkdir chmod find tail date cat sleep; do
    need_cmd "$c"
done

SYSCTL_BIN=$(command -v sysctl)
MODPROBE_BIN=$(command -v modprobe || true)
SYSTEMCTL_BIN=$(command -v systemctl || true)
IP_BIN=$(command -v ip || true)
TC_BIN=$(command -v tc || true)
SS_BIN=$(command -v ss || true)
DOCKER_BIN=$(command -v docker || true)
DOCKERD_BIN=$(command -v dockerd || true)
PYTHON3_BIN=$(command -v python3 || true)
TIMEOUT_BIN=$(command -v timeout || true)
SWAPON_BIN=$(command -v swapon || true)
SWAPOFF_BIN=$(command -v swapoff || true)
MKSWAP_BIN=$(command -v mkswap || true)
APT_GET_BIN=$(command -v apt-get || true)
DPKG_QUERY_BIN=$(command -v dpkg-query || true)
UFW_BIN=$(command -v ufw || true)
NFT_BIN=$(command -v nft || true)
FAIL2BAN_CLIENT_BIN=$(command -v fail2ban-client || true)
SSHD_BIN=$(command -v sshd || true)
STAT_BIN=$(command -v stat || true)
CHOWN_BIN=$(command -v chown || true)
TIMEDATECTL_BIN=$(command -v timedatectl || true)
FSTRIM_BIN=$(command -v fstrim || true)
FINDMNT_BIN=$(command -v findmnt || true)
LSBLK_BIN=$(command -v lsblk || true)
DF_BIN=$(command -v df || true)
CERTBOT_BIN=$(command -v certbot || true)
OPENSSL_BIN=$(command -v openssl || true)
CRONTAB_BIN=$(command -v crontab || true)

# Публичный режим безопасности. Опциональные действия можно отключать env-флагами.
SECURITY_ENABLED=${NUVRION_SECURITY:-1}
INSTALL_SECURITY_PACKAGES=${NUVRION_INSTALL_SECURITY_PACKAGES:-1}
SYSTEM_MAINTENANCE=${NUVRION_SYSTEM_MAINTENANCE:-1}
INSTALL_ZRAM_PACKAGES=${NUVRION_INSTALL_ZRAM_PACKAGES:-1}
POST_REBOOT_ENABLED=${NUVRION_POST_REBOOT_CHECK:-1}
CERTIFICATE_AUTOMATION=${NUVRION_CERTIFICATES:-1}
CERTBOT_DRY_RUN=${NUVRION_CERTBOT_DRY_RUN:-1}
# Порт панели намеренно НЕ имеет значения по умолчанию. v1.0.0 определяет его
# по фактическим listener/firewall-правилам либо спрашивает пользователя.
# Это исключает старые/жёсткие списки портов и ошибочное предположение про 2222.
PANEL_PORT=""
PANEL_PORT_ENV=${NUVRION_PANEL_PORT:-}
if [[ -n $PANEL_PORT_ENV ]]; then
    if [[ $PANEL_PORT_ENV =~ ^[0-9]{1,5}$ ]]; then
        PANEL_PORT_ENV=$((10#$PANEL_PORT_ENV))
    fi
    if [[ ! $PANEL_PORT_ENV =~ ^[0-9]+$ ]] || (( PANEL_PORT_ENV < 1 || PANEL_PORT_ENV > 65535 )); then
        warn "NUVRION_PANEL_PORT=${PANEL_PORT_ENV} некорректен; автоматическая настройка панели не будет использовать это значение."
        PANEL_PORT_ENV=""
    fi
fi
PANEL_PORT_FILE=/etc/nuvrion-tuning/panel-port.conf
PANEL_IP_FILE=/etc/nuvrion-tuning/panel-ips.conf
PANEL_SETUP_SKIPPED=0
PANEL_IDENTITY_SOURCE="не определён"

CPU=$(nproc)
RAM_KB=$(awk '/MemTotal:/ {print $2; exit}' /proc/meminfo)
RAM_MB=$((RAM_KB / 1024))

if (( CPU < 1 || RAM_MB < 128 )); then
    echo "ОШИБКА: не удалось корректно определить CPU/RAM" >&2
    exit 1
fi

RUN_ID=$(date +%Y%m%d-%H%M%S)
STATE_DIR=/var/lib/nuvrion-tuning
SNAPSHOT_DIR="$STATE_DIR/snapshots"
BACKUP_DIR="$STATE_DIR/backups"
mkdir -p "$SNAPSHOT_DIR" "$BACKUP_DIR"
SNAPSHOT="$SNAPSHOT_DIR/pre-v1.0.0-${RUN_ID}.txt"

CONF=/etc/sysctl.d/99-zzzz-nuvrion-performance.conf
CONF_BASE=$(basename "$CONF")
OLD_CONFS=(
    /etc/sysctl.d/99-nuvrion-performance.conf
    /etc/sysctl.d/99-zz-nuvrion-performance.conf
    /etc/sysctl.d/99-zzz-nuvrion-performance.conf
)
OLD_SERVICE=/etc/systemd/system/nuvrion-conntrack.service
MODULES_CONF=/etc/modules-load.d/99-nuvrion-performance.conf
CONNTRACK_MODPROBE_CONF=/etc/modprobe.d/99-nuvrion-nf-conntrack.conf
AUTHORITATIVE_SERVICE=/etc/systemd/system/nuvrion-performance-sysctl.service

printf '\n%s%s%s\n' "$C_BOLD" "$C_CYAN" "$UI_LINE"
printf '  Nuvrion  ·  адаптивная оптимизация сети  ·  v1.0.0\n'
printf '%s%s\n' "$UI_LINE" "$C_RESET"
printf '  Автор       %sNuvrion%s\n' "$C_BOLD" "$C_RESET"
printf '  Сервер      %s vCPU · %s MB RAM\n' "$CPU" "$RAM_MB"
printf '  Ядро        %s\n' "$(uname -r)"
printf '  Запуск      %s\n' "$RUN_ID"
printf '%s%s%s\n\n' "$C_DIM" "$UI_LINE" "$C_RESET"

# ============================================================
# Адаптивный профиль
# ============================================================

if (( RAM_MB < 1536 )); then
    BUF=16777216
    CT_BASE=65536
    RAM_BACKLOG_CAP=16384
elif (( RAM_MB < 3072 )); then
    BUF=33554432
    CT_BASE=131072
    RAM_BACKLOG_CAP=32768
elif (( RAM_MB < 7168 )); then
    BUF=33554432
    CT_BASE=262144
    RAM_BACKLOG_CAP=65536
elif (( RAM_MB < 15360 )); then
    BUF=67108864
    CT_BASE=524288
    RAM_BACKLOG_CAP=131072
else
    BUF=67108864
    CT_BASE=1048576
    RAM_BACKLOG_CAP=131072
fi

if (( CPU <= 1 )); then
    CPU_BACKLOG=16384
elif (( CPU <= 3 )); then
    CPU_BACKLOG=32768
elif (( CPU <= 7 )); then
    CPU_BACKLOG=65536
else
    CPU_BACKLOG=131072
fi

if (( CPU_BACKLOG < RAM_BACKLOG_CAP )); then
    BACKLOG=$CPU_BACKLOG
else
    BACKLOG=$RAM_BACKLOG_CAP
fi
# ============================================================
# Kernel modules
# ============================================================

AVAILABLE_MODULES=()

if [[ -n $MODPROBE_BIN ]]; then
    for mod in nf_conntrack tcp_bbr sch_fq; do
        if "$MODPROBE_BIN" "$mod" >/dev/null 2>&1 || [[ -d "/sys/module/$mod" ]]; then
            AVAILABLE_MODULES+=("$mod")
        fi
    done
fi

mkdir -p /etc/modules-load.d /etc/modprobe.d /etc/sysctl.d

if ((${#AVAILABLE_MODULES[@]})); then
    printf '%s\n' "${AVAILABLE_MODULES[@]}" >"$MODULES_CONF"
    chmod 0644 "$MODULES_CONF"
else
    rm -f "$MODULES_CONF"
fi

# ============================================================
# BBR / qdisc selection
# ============================================================

AVAILABLE_CC=$(sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null || true)
CURRENT_CC=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || true)
[[ -n $CURRENT_CC ]] || CURRENT_CC=cubic

if grep -qw bbr <<<"$AVAILABLE_CC"; then
    CONGESTION=bbr
else
    CONGESTION=$CURRENT_CC
fi

CURRENT_QDISC=$(sysctl -n net.core.default_qdisc 2>/dev/null || true)
[[ -n $CURRENT_QDISC ]] || CURRENT_QDISC=fq_codel

if [[ -d /sys/module/sch_fq ]] || { [[ -n $MODPROBE_BIN ]] && "$MODPROBE_BIN" sch_fq >/dev/null 2>&1; }; then
    QDISC=fq
else
    QDISC=$CURRENT_QDISC
fi

# ============================================================
# Авторитетные значения производительности
# ============================================================
# В версии v1.0.0 старые тюнинги не используются как источник целевых значений.
# Профиль рассчитывается только из CPU/RAM и нормализует ранее применённые
# rmem/wmem/backlog/SYN-параметры. Исключения ниже оставлены только для
# системных потолков, которые безопаснее не уменьшать автоматически.

RMEM_MAX=$BUF
WMEM_MAX=$BUF
TCP_RMEM_MIN=4096
TCP_RMEM_DEF=131072
TCP_WMEM_MIN=4096
if (( RAM_MB < 1536 )); then
    TCP_WMEM_DEF=32768
else
    TCP_WMEM_DEF=65536
fi
UDP_RMEM_MIN=8192
UDP_WMEM_MIN=4096
SOMAXCONN=65535
SYN_BACKLOG=65535

# Semantic knobs: larger numeric values are NOT necessarily better.
# tcp_syncookies=2 means unconditional cookies (testing mode), so normalize to 1.
SYNC_TARGET=1

# tcp_mtu_probing=1 enables PLPMTUD only after black-hole detection;
# value 2 forces it for every connection, which is not a universal tuning choice.
MTU_PROBING=1

# Kernel ceilings: raise only when below target; otherwise do not claim ownership.
NR_OPEN_TARGET=1048576
CUR_NR_OPEN=$(num_or_zero "$(sysctl -n fs.nr_open 2>/dev/null || echo 0)")
MANAGE_NR_OPEN=0
NR_OPEN=$CUR_NR_OPEN
if (( CUR_NR_OPEN < NR_OPEN_TARGET )); then
    NR_OPEN=$NR_OPEN_TARGET
    MANAGE_NR_OPEN=1
elif [[ -f $CONF ]] && grep -Eq '^fs\.nr_open[[:space:]]*=' "$CONF"; then
    # Повторный запуск сохраняет уже принадлежащее нам автоприменение.
    MANAGE_NR_OPEN=1
fi

CUR_FILE_MAX=$(num_or_zero "$(sysctl -n fs.file-max 2>/dev/null || echo 0)")
# fs.nr_open is a per-process kernel ceiling while fs.file-max is system-wide.
# Keep the targets independent: never inflate file-max just because nr_open is large.
FILE_MAX_TARGET=1048576
MANAGE_FILE_MAX=0
FILE_MAX=$CUR_FILE_MAX
if (( CUR_FILE_MAX < FILE_MAX_TARGET )); then
    FILE_MAX=$FILE_MAX_TARGET
    MANAGE_FILE_MAX=1
elif [[ -f $CONF ]] && grep -Eq '^fs\.file-max[[:space:]]*=' "$CONF"; then
    MANAGE_FILE_MAX=1
fi

# ============================================================
# Безопасный baseline ядра
# ============================================================
# Здесь только параметры, которые не мешают обычному VPN/proxy routing.
# Намеренно НЕ включаем strict rp_filter, отключение IPv6, запрет userns,
# sysrq/kexec и другие параметры, способные нарушить маршрутизацию,
# контейнеры, отладку или аварийное восстановление универсального сервера.

declare -A SECURITY_SYSCTL_VALUES=()
SECURITY_SYSCTL_KEYS=()

add_security_sysctl_if_supported() {
    local key=$1 value=$2 path
    path="/proc/sys/${key//./\/}"
    [[ -e $path ]] || return 0
    SECURITY_SYSCTL_KEYS+=("$key")
    SECURITY_SYSCTL_VALUES["$key"]=$value
}

# Для параметров, где большее числовое значение означает более строгую защиту,
# никогда не ослабляем уже существующую конфигурацию. В профиль записывается
# максимум из безопасного минимума Nuvrion и текущего runtime-значения.
add_security_sysctl_min_if_supported() {
    local key=$1 minimum=$2 path current target
    path="/proc/sys/${key//./\/}"
    [[ -e $path ]] || return 0
    current=$(sysctl -n "$key" 2>/dev/null || true)
    target=$minimum
    if [[ $current =~ ^[0-9]+$ ]] && (( current > minimum )); then
        target=$current
    fi
    SECURITY_SYSCTL_KEYS+=("$key")
    SECURITY_SYSCTL_VALUES["$key"]=$target
}

if [[ $SECURITY_ENABLED == 1 ]]; then
    add_security_sysctl_if_supported net.ipv4.conf.all.accept_redirects 0
    add_security_sysctl_if_supported net.ipv4.conf.default.accept_redirects 0
    add_security_sysctl_if_supported net.ipv4.conf.all.secure_redirects 0
    add_security_sysctl_if_supported net.ipv4.conf.default.secure_redirects 0
    add_security_sysctl_if_supported net.ipv4.conf.all.send_redirects 0
    add_security_sysctl_if_supported net.ipv4.conf.default.send_redirects 0
    add_security_sysctl_if_supported net.ipv4.conf.all.accept_source_route 0
    add_security_sysctl_if_supported net.ipv4.conf.default.accept_source_route 0
    add_security_sysctl_if_supported net.ipv4.icmp_echo_ignore_broadcasts 1
    add_security_sysctl_if_supported net.ipv4.icmp_ignore_bogus_error_responses 1

    # IPv6 не отключаем. Если стек присутствует, запрещаем только ICMP redirects/source-route.
    add_security_sysctl_if_supported net.ipv6.conf.all.accept_redirects 0
    add_security_sysctl_if_supported net.ipv6.conf.default.accept_redirects 0
    add_security_sysctl_if_supported net.ipv6.conf.all.accept_source_route 0
    add_security_sysctl_if_supported net.ipv6.conf.default.accept_source_route 0

    add_security_sysctl_if_supported kernel.dmesg_restrict 1
    add_security_sysctl_if_supported kernel.kptr_restrict 2
    add_security_sysctl_if_supported fs.protected_hardlinks 1
    add_security_sysctl_if_supported fs.protected_symlinks 1
    # 1 — безопасный минимум; если сервер уже использует более строгий 2,
    # сохраняем 2 и никогда не понижаем уровень защиты.
    add_security_sysctl_min_if_supported fs.protected_fifos 1
    add_security_sysctl_min_if_supported fs.protected_regular 1
fi

# ============================================================
# Ephemeral port range + reservations
# ============================================================

# v1.0.0 deliberately normalizes the range instead of preserving an old lower
# endpoint such as 1024. 10240..65535 still leaves >55k ephemeral ports while
# keeping the common fixed-service area outside automatic allocation.
CUR_PORT_RANGE=$(normalize_ws "$(sysctl -n net.ipv4.ip_local_port_range 2>/dev/null || echo '32768 60999')")
read -r CUR_PORT_LOW CUR_PORT_HIGH <<<"$CUR_PORT_RANGE"
CUR_PORT_LOW=$(num_or_zero "$CUR_PORT_LOW")
CUR_PORT_HIGH=$(num_or_zero "$CUR_PORT_HIGH")

PORT_LOW=10240
PORT_HIGH=65535
UNPRIV_START=$(num_or_zero "$(sysctl -n net.ipv4.ip_unprivileged_port_start 2>/dev/null || echo 1024)")
if (( UNPRIV_START > PORT_LOW && UNPRIV_START < PORT_HIGH )); then
    PORT_LOW=$UNPRIV_START
fi

# Prefer opposite parity for the endpoints when possible.
if (( PORT_LOW % 2 != 0 && PORT_HIGH % 2 != 0 && PORT_LOW < PORT_HIGH )); then
    PORT_LOW=$((PORT_LOW + 1))
fi

if (( PORT_LOW >= PORT_HIGH )); then
    warn "Рассчитанный диапазон временных портов некорректен; сохранён текущий диапазон ${CUR_PORT_RANGE}"
    PORT_LOW=$CUR_PORT_LOW
    PORT_HIGH=$CUR_PORT_HIGH
fi

CUR_RESERVED=$(sysctl -n net.ipv4.ip_local_reserved_ports 2>/dev/null || true)
RESERVED_SUPPORTED=0
[[ -e /proc/sys/net/ipv4/ip_local_reserved_ports ]] && RESERVED_SUPPORTED=1

# v1.0.0 never treats every unconnected UDP socket from `ss -lun` as a fixed
# listener. Xray/QUIC can keep transient UDP source sockets there. TCP LISTEN
# sockets are safe to auto-detect; fixed UDP inbounds can be declared below.
FIXED_TCP_PORTS=()
if [[ -n $SS_BIN ]]; then
    mapfile -t FIXED_TCP_PORTS < <(
        "$SS_BIN" -H -ltn 2>/dev/null |
        awk -v low="$PORT_LOW" -v high="$PORT_HIGH" '
        {
            p=$4
            sub(/^.*:/,"",p)
            if (p ~ /^[0-9]+$/ && (p + 0) >= (low + 0) && (p + 0) <= (high + 0))
                print (p + 0)
        }' |
        sort -n -u
    )
fi

merge_reserved_ports() {
    local existing=$1
    shift || true
    local token start end p
    local -a tokens=()
    declare -A seen=()

    if [[ -n $existing ]]; then
        # Accept commas, spaces and newlines in manual specifications.
        existing=${existing//$'\n'/,}
        existing=${existing//$'\t'/,}
        existing=${existing// /,}
        IFS=',' read -r -a tokens <<<"$existing"
        for token in "${tokens[@]}"; do
            token=${token//[[:space:]]/}
            [[ -z $token ]] && continue

            if [[ $token =~ ^([0-9]+)-([0-9]+)$ ]]; then
                start=${BASH_REMATCH[1]}
                end=${BASH_REMATCH[2]}
                if (( start >= 1 && end <= 65535 && start <= end )); then
                    for ((p=start; p<=end; p++)); do seen[$p]=1; done
                fi
            elif [[ $token =~ ^[0-9]+$ ]] && (( token >= 1 && token <= 65535 )); then
                seen[$token]=1
            fi
        done
    fi

    for p in "$@"; do
        if [[ $p =~ ^[0-9]+$ ]] && (( p >= 1 && p <= 65535 )); then
            seen[$p]=1
        fi
    done

    ((${#seen[@]})) || return 0

    local -a sorted=()
    mapfile -t sorted < <(printf '%s\n' "${!seen[@]}" | sort -n)

    local range_start=${sorted[0]}
    local prev=${sorted[0]}
    local cur
    local out=""

    for cur in "${sorted[@]:1}"; do
        if (( cur == prev + 1 )); then
            prev=$cur
            continue
        fi

        if [[ -n $out ]]; then out+=","; fi
        if (( range_start == prev )); then out+="$range_start"; else out+="${range_start}-${prev}"; fi
        range_start=$cur
        prev=$cur
    done

    if [[ -n $out ]]; then out+=","; fi
    if (( range_start == prev )); then out+="$range_start"; else out+="${range_start}-${prev}"; fi

    printf '%s' "$out"
}

# Keep newly managed reservations only inside the active ephemeral range.
# The pre-Nuvrion baseline is preserved separately and is never silently
# rewritten, even if it contains historical reservations below PORT_LOW.
filter_port_spec_to_range() {
    local spec=${1:-}
    local token start end p
    local -a tokens=()
    declare -A seen=()

    spec=${spec//$'\n'/,}
    spec=${spec//$'\t'/,}
    spec=${spec// /,}
    IFS=',' read -r -a tokens <<<"$spec"

    for token in "${tokens[@]}"; do
        token=${token//[[:space:]]/}
        [[ -z $token ]] && continue

        if [[ $token =~ ^([0-9]+)-([0-9]+)$ ]]; then
            start=${BASH_REMATCH[1]}
            end=${BASH_REMATCH[2]}
            (( start < PORT_LOW )) && start=$PORT_LOW
            (( end > PORT_HIGH )) && end=$PORT_HIGH
            if (( start <= end )); then
                for ((p=start; p<=end; p++)); do seen[$p]=1; done
            fi
        elif [[ $token =~ ^[0-9]+$ ]]; then
            p=$token
            if (( p >= PORT_LOW && p <= PORT_HIGH )); then
                seen[$p]=1
            fi
        fi
    done

    ((${#seen[@]})) || return 0
    merge_reserved_ports "" "${!seen[@]}"
}

# Preserve the reservation set that existed before Nuvrion started managing
# it. On the first v1.0.0 run after v4, recover this baseline from the oldest
# pre-v4 snapshot. This removes ports that v4 accidentally learned from
# transient UDP sockets without deleting reservations that predated v4.
RESERVED_BASELINE_FILE="$STATE_DIR/reserved-baseline.txt"
BASE_RESERVED=""
BASELINE_SOURCE="current-runtime"
V4_RESERVED_RECONCILED=0

if [[ -f $RESERVED_BASELINE_FILE ]]; then
    BASE_RESERVED=$(cat "$RESERVED_BASELINE_FILE" 2>/dev/null || true)
    BASELINE_SOURCE="$RESERVED_BASELINE_FILE"
else
    OLD_V4_SNAPSHOT=""
    mapfile -t V4_SNAPSHOTS < <(find "$SNAPSHOT_DIR" -maxdepth 1 -type f -name 'pre-v4-*' -print 2>/dev/null | sort)
    if ((${#V4_SNAPSHOTS[@]})); then
        OLD_V4_SNAPSHOT=${V4_SNAPSHOTS[0]}
    fi

    PREVIOUS_PROFILE=""
    for candidate in \
        "$CONF" \
        /etc/sysctl.d/99-zz-nuvrion-performance.conf \
        /etc/sysctl.d/99-nuvrion-performance.conf; do
        if [[ -f $candidate ]]; then
            PREVIOUS_PROFILE=$candidate
            break
        fi
    done

    if [[ -n $PREVIOUS_PROFILE ]] && grep -Eq '(Nuvrion|Nuvrion) Adaptive Network Performance Profile v4' "$PREVIOUS_PROFILE" 2>/dev/null; then
        if [[ -n $OLD_V4_SNAPSHOT ]]; then
            line=$(grep -m1 -E '^net[./]ipv4[./]ip_local_reserved_ports[[:space:]]*=' "$OLD_V4_SNAPSHOT" 2>/dev/null || true)
            if [[ -n $line ]]; then
                BASE_RESERVED=${line#*=}
                BASE_RESERVED=${BASE_RESERVED#"${BASE_RESERVED%%[![:space:]]*}"}
                BASE_RESERVED=${BASE_RESERVED%"${BASE_RESERVED##*[![:space:]]}"}
                [[ $BASE_RESERVED == '<unavailable>' ]] && BASE_RESERVED=""
            fi
            BASELINE_SOURCE="$OLD_V4_SNAPSHOT"
            V4_RESERVED_RECONCILED=1
        else
            BASE_RESERVED=$CUR_RESERVED
            warn "Обнаружен профиль v4, но pre-v4 snapshot не найден; текущий список reserved ports сохранён без попытки угадывать устаревшие значения."
        fi
    else
        BASE_RESERVED=$CUR_RESERVED
    fi

    BASE_RESERVED=$(merge_reserved_ports "$BASE_RESERVED")
    printf '%s\n' "$BASE_RESERVED" >"$RESERVED_BASELINE_FILE"
    chmod 0600 "$RESERVED_BASELINE_FILE"
fi

# Explicit fixed UDP inbounds. This is intentionally opt-in because there is
# no generic, reliable way to distinguish a permanent UDP listener from an
# unconnected ephemeral source socket. File examples:
#   443
#   8443,2053
#   20000-20010
# Environment override/addition: NUVRION_UDP_PORTS="443,8443".
UDP_PORTS_FILE=/etc/nuvrion-tuning/fixed-udp-ports.conf
mkdir -p /etc/nuvrion-tuning
UDP_SPEC=""
if [[ -f $UDP_PORTS_FILE ]]; then
    UDP_SPEC=$(awk '
        {
            sub(/#.*/, "")
            gsub(/[[:space:]]+/, ",")
            gsub(/^,+|,+$/, "")
            if (length($0)) {
                if (out != "") out = out ","
                out = out $0
            }
        }
        END { print out }
    ' "$UDP_PORTS_FILE")
fi
if [[ -n ${NUVRION_UDP_PORTS:-} ]]; then
    if [[ -n $UDP_SPEC ]]; then UDP_SPEC+=","; fi
    UDP_SPEC+="${NUVRION_UDP_PORTS}"
    UDP_ENV_USED=1
else
    UDP_ENV_USED=0
fi
EXPLICIT_UDP_RESERVED_RAW=$(merge_reserved_ports "$UDP_SPEC")
EXPLICIT_UDP_RESERVED=$(filter_port_spec_to_range "$EXPLICIT_UDP_RESERVED_RAW")
UDP_OUT_OF_RANGE_IGNORED=0
if [[ -n $EXPLICIT_UDP_RESERVED_RAW && $EXPLICIT_UDP_RESERVED_RAW != "$EXPLICIT_UDP_RESERVED" ]]; then
    UDP_OUT_OF_RANGE_IGNORED=1
fi

# Build the authoritative v1.0.0 set from:
#   1) pre-Nuvrion baseline,
#   2) current fixed TCP LISTEN ports inside the ephemeral range,
#   3) explicitly declared fixed UDP inbounds.
RESERVED_INPUT=$BASE_RESERVED
if [[ -n $EXPLICIT_UDP_RESERVED ]]; then
    [[ -n $RESERVED_INPUT ]] && RESERVED_INPUT+=","
    RESERVED_INPUT+=$EXPLICIT_UDP_RESERVED
fi
MERGED_RESERVED=$(merge_reserved_ports "$RESERVED_INPUT" "${FIXED_TCP_PORTS[@]}")
MANAGE_RESERVED=$RESERVED_SUPPORTED

# ============================================================
# Таблица conntrack
# ============================================================

CONNTRACK_SUPPORTED=0
CONNTRACK=$CT_BASE
CT_BUCKETS=0
CT_COUNT_CURRENT=0

if [[ -e /proc/sys/net/netfilter/nf_conntrack_max ]]; then
    CONNTRACK_SUPPORTED=1

    # Старое значение nf_conntrack_max больше не наследуется. Но профиль не
    # должен опускать лимит ниже фактической нагрузки: если таблица уже сильно
    # заполнена, берём минимум 2x от текущего числа записей и округляем вверх.
    CT_COUNT_CURRENT=$(num_or_zero "$(sysctl -n net.netfilter.nf_conntrack_count 2>/dev/null || echo 0)")
    if (( CT_COUNT_CURRENT * 4 > CONNTRACK * 3 )); then
        CT_NEEDED=$((CT_COUNT_CURRENT * 2))
        CT_STEP=65536
        CONNTRACK=$((((CT_NEEDED + CT_STEP - 1) / CT_STEP) * CT_STEP))
        info "Conntrack скорректирован по текущей нагрузке: ${CONNTRACK} (активных записей ${CT_COUNT_CURRENT})"
    fi

    # Целевой размер hash table определяется профилем, а не старым тюнингом.
    # 262144 оставляем верхним практическим пределом автоматического профиля.
    CT_BUCKETS=$CONNTRACK
    (( CT_BUCKETS < 1024 )) && CT_BUCKETS=1024
    (( CT_BUCKETS > 262144 )) && CT_BUCKETS=262144

    # Для загружаемого nf_conntrack это задаёт hashsize при загрузке модуля.
    # Если уменьшение live-таблицы ядро отклонит, значение всё равно будет
    # сохранено и скрипт попросит перезагрузку.
    cat >"$CONNTRACK_MODPROBE_CONF" <<EOF
# Nuvrion — адаптивная оптимизация сети v1.0.0
# Author: Nuvrion
options nf_conntrack hashsize=${CT_BUCKETS}
EOF
    chmod 0644 "$CONNTRACK_MODPROBE_CONF"
fi

# ============================================================
# Управляемые параметры
# ============================================================

declare -A DESIRED=()
declare -A PENDING_REBOOT=()
PROFILE_REBOOT_REQUIRED=0
MANAGED_KEYS=(
    net.core.default_qdisc
    net.ipv4.tcp_congestion_control
    net.core.rmem_max
    net.core.wmem_max
    net.ipv4.tcp_rmem
    net.ipv4.tcp_wmem
    net.ipv4.udp_rmem_min
    net.ipv4.udp_wmem_min
    net.core.netdev_max_backlog
    net.core.somaxconn
    net.ipv4.tcp_max_syn_backlog
    net.ipv4.tcp_syncookies
    net.ipv4.tcp_slow_start_after_idle
    net.ipv4.tcp_mtu_probing
    net.ipv4.ip_local_port_range
)

if ((${#SECURITY_SYSCTL_KEYS[@]})); then
    MANAGED_KEYS+=("${SECURITY_SYSCTL_KEYS[@]}")
fi

if (( MANAGE_NR_OPEN )); then
    MANAGED_KEYS+=(fs.nr_open)
fi
if (( MANAGE_FILE_MAX )); then
    MANAGED_KEYS+=(fs.file-max)
fi

if (( CONNTRACK_SUPPORTED )); then
    MANAGED_KEYS+=(net.netfilter.nf_conntrack_max net.netfilter.nf_conntrack_buckets)
fi
if (( MANAGE_RESERVED )); then
    MANAGED_KEYS+=(net.ipv4.ip_local_reserved_ports)
fi

# ============================================================
# Формирование эффективного списка sysctl.d с учётом приоритета каталогов systemd
# ============================================================

build_active_sysctl_files() {
    ACTIVE_SYSCTL_FILES=()
    local -A chosen=()
    local -a bases=()
    local dir f base

    shopt -s nullglob
    for dir in /etc/sysctl.d /run/sysctl.d /usr/local/lib/sysctl.d /usr/lib/sysctl.d /lib/sysctl.d; do
        [[ -d $dir ]] || continue
        for f in "$dir"/*.conf; do
            base=$(basename "$f")
            if [[ -z ${chosen[$base]+x} ]]; then
                chosen[$base]=$f
            fi
        done
    done
    shopt -u nullglob

    ((${#chosen[@]})) || return 0
    mapfile -t bases < <(printf '%s\n' "${!chosen[@]}" | sort)
    for base in "${bases[@]}"; do
        ACTIVE_SYSCTL_FILES+=("${chosen[$base]}")
    done
}

# ============================================================
# Снимок состояния до изменений
# ============================================================

{
    echo "Nuvrion v1.0.0 — снимок до изменений"
    echo "Запуск: $RUN_ID"
    echo "Автор: Nuvrion"
    echo "Ядро: $(uname -r)"
    echo "CPU: $CPU"
    echo "RAM_MB: $RAM_MB"
    echo
    echo "=== УПРАВЛЯЕМЫЕ SYSCTL ==="
    for key in "${MANAGED_KEYS[@]}"; do
        printf '%s = %s\n' "$key" "$(sysctl -n "$key" 2>/dev/null || echo '<unavailable>')"
    done
    echo
    echo "=== QDISC ==="
    if [[ -n $TC_BIN ]]; then "$TC_BIN" qdisc show 2>/dev/null || true; fi
    echo
    echo "=== СЛУШАЮЩИЕ ПОРТЫ ==="
    if [[ -n $SS_BIN ]]; then "$SS_BIN" -lntup 2>/dev/null || true; fi
    echo
    echo "=== СУЩЕСТВУЮЩИЕ НАЗНАЧЕНИЯ SYSCTL ==="
} >"$SNAPSHOT"

# ============================================================
# Поиск существующих назначений перед применением
# ============================================================

build_active_sysctl_files
SYSCTL_FILES=("${ACTIVE_SYSCTL_FILES[@]}")
[[ -f /etc/sysctl.conf ]] && SYSCTL_FILES+=(/etc/sysctl.conf)

EXISTING_ASSIGNMENTS=0

for f in "${SYSCTL_FILES[@]}"; do
    [[ -f $f || -L $f ]] || continue
    if [[ -e $CONF ]] && [[ $f -ef $CONF ]]; then continue; fi

    for key in "${MANAGED_KEYS[@]}"; do
        escaped=${key//./\\.}
        slash=${key//./\/}
        key_re="(${escaped}|${slash})"
        while IFS= read -r hit; do
            [[ -z $hit ]] && continue
            printf '%s:%s\n' "$f" "$hit" >>"$SNAPSHOT"
            EXISTING_ASSIGNMENTS=$((EXISTING_ASSIGNMENTS + 1))
        done < <(grep -nE "^[[:space:]]*-?[[:space:]]*${key_re}[[:space:]]*=" "$f" 2>/dev/null || true)
    done
done

if (( EXISTING_ASSIGNMENTS > 0 )); then
    info "Найдено ${EXISTING_ASSIGNMENTS} старых назначений управляемых sysctl; снимок сохранён."
else
    ok "Старых назначений управляемых sysctl вне профиля Nuvrion v1.0.0 не найдено."
fi

# ============================================================
# Миграция устаревших механизмов Nuvrion
# ============================================================

for OLD_CONF in "${OLD_CONFS[@]}"; do
    [[ -f $OLD_CONF ]] || continue
    if [[ -e $CONF ]] && [[ $OLD_CONF -ef $CONF ]]; then
        continue
    fi
    cp -a "$OLD_CONF" "$BACKUP_DIR/$(basename "$OLD_CONF").${RUN_ID}"
    rm -f "$OLD_CONF"
    info "Удалён устаревший профиль Nuvrion: $OLD_CONF (резервная копия сохранена)"
done

if [[ -f $OLD_SERVICE ]]; then
    cp -a "$OLD_SERVICE" "$BACKUP_DIR/nuvrion-conntrack.service.${RUN_ID}"
    if [[ -n $SYSTEMCTL_BIN && -d /run/systemd/system ]]; then
        "$SYSTEMCTL_BIN" disable --now nuvrion-conntrack.service >/dev/null 2>&1 || true
    fi
    rm -f "$OLD_SERVICE"
    if [[ -n $SYSTEMCTL_BIN && -d /run/systemd/system ]]; then
        "$SYSTEMCTL_BIN" daemon-reload
    fi
    info "Удалён устаревший сервис conntrack Nuvrion; постоянные настройки теперь ведут modules-load/sysctl."
fi

OLD_GLOBAL_LIMITS=/etc/systemd/system.conf.d/99-nuvrion-limits.conf
if [[ -f $OLD_GLOBAL_LIMITS ]]; then
    UNKNOWN_LIMIT_LINES=$(grep -Ev '^[[:space:]]*($|#|\[Manager\]|DefaultLimitNOFILE=|DefaultLimitNPROC=)' "$OLD_GLOBAL_LIMITS" 2>/dev/null || true)
    if [[ -z $UNKNOWN_LIMIT_LINES ]]; then
        cp -a "$OLD_GLOBAL_LIMITS" "$BACKUP_DIR/99-nuvrion-limits.conf.${RUN_ID}"
        rm -f "$OLD_GLOBAL_LIMITS"
        info "Удалён устаревший глобальный файл лимитов systemd Nuvrion (резервная копия сохранена); daemon-reexec не выполнялся."
    else
        warn "В $OLD_GLOBAL_LIMITS есть неизвестные параметры; файл оставлен без изменений для ручной проверки."
    fi
fi

if [[ -f /etc/security/limits.d/99-nuvrion.conf ]]; then
    info "Найден /etc/security/limits.d/99-nuvrion.conf; v1.0.0 не изменяет PAM/login limits."
fi

# ============================================================
# Авторитетный режим: Nuvrion владеет управляемыми sysctl
# ============================================================
# v1.0.0 не переписывает все чужие /etc/sysctl.d/*.conf. Профиль Nuvrion
# имеет позднее имя и повторно применяется отдельным systemd unit после
# systemd-sysctl. Нейтрализуются только реально более поздние файлы и
# /etc/sysctl.conf. Изменения, которые v5.3/v5.4 успели внести в более ранние
# сторонние файлы, по возможности восстанавливаются автоматически.

declare -A MANAGED_SET=()
CLEANED_FILES=0
CLEANED_ASSIGNMENTS=0
RESTORED_FILES=0
RESTORED_ASSIGNMENTS=0

restore_legacy_neutralizations() {
    local f=$1 base tmp line restored=0 payload

    [[ -f $f && ! -L $f ]] || return 0
    base=$(basename "$f")
    [[ $base < $CONF_BASE ]] || return 0
    if [[ -e $CONF ]] && [[ $f -ef $CONF ]]; then return 0; fi

    tmp=$(mktemp)
    while IFS= read -r line || [[ -n $line ]]; do
        if [[ $line =~ ^#[[:space:]]*\[Nuvrion[[:space:]]+v5\.[34]\][[:space:]]+отключено:[[:space:]](.*)$ ]]; then
            payload=${BASH_REMATCH[1]}
            printf '%s\n' "$payload" >>"$tmp"
            restored=$((restored + 1))
        else
            printf '%s\n' "$line" >>"$tmp"
        fi
    done <"$f"

    if (( restored > 0 )); then
        cp -a "$f" "$BACKUP_DIR/restore-legacy-$(basename "$f").${RUN_ID}"
        cat "$tmp" >"$f"
        RESTORED_FILES=$((RESTORED_FILES + 1))
        RESTORED_ASSIGNMENTS=$((RESTORED_ASSIGNMENTS + restored))
        info "Восстановлено ${restored} назначений, ранее закомментированных Nuvrion, в $f"
    fi
    rm -f "$tmp"
}

neutralize_managed_assignments() {
    local f=$1 tmp line lhs normalized changed=0

    [[ -f $f ]] || return 0
    if [[ -e $CONF ]] && [[ $f -ef $CONF ]]; then return 0; fi

    # Не следуем по symlink: авторитетный service всё равно возвращает наши
    # runtime-значения после штатного systemd-sysctl.
    if [[ -L $f ]]; then
        info "Пропущена символическая ссылка: $f"
        return 0
    fi

    tmp=$(mktemp)
    while IFS= read -r line || [[ -n $line ]]; do
        normalized=$line
        normalized=${normalized#"${normalized%%[![:space:]]*}"}

        if [[ -z $normalized || $normalized == \#* || $normalized == \;* || $normalized != *"="* ]]; then
            printf '%s\n' "$line" >>"$tmp"
            continue
        fi

        lhs=${line%%=*}
        lhs=${lhs//[[:space:]]/}
        lhs=${lhs#-}
        lhs=${lhs//\//.}

        if [[ -n ${MANAGED_SET[$lhs]+x} ]]; then
            printf '# [Nuvrion v1.0.0] отключено: %s\n' "$line" >>"$tmp"
            changed=$((changed + 1))
        else
            printf '%s\n' "$line" >>"$tmp"
        fi
    done <"$f"

    if (( changed > 0 )); then
        cp -a "$f" "$BACKUP_DIR/authoritative-$(basename "$f").${RUN_ID}"
        cat "$tmp" >"$f"
        CLEANED_FILES=$((CLEANED_FILES + 1))
        CLEANED_ASSIGNMENTS=$((CLEANED_ASSIGNMENTS + changed))
        info "Нейтрализовано ${changed} реально более поздних назначений sysctl в $f"
    fi
    rm -f "$tmp"
}

# ============================================================
# Формирование целевой конфигурации
# ============================================================

if [[ -f $CONF ]]; then
    cp -a "$CONF" "$BACKUP_DIR/$(basename "$CONF").${RUN_ID}"
fi

TMP=$(mktemp)
VALID=$(mktemp)

cleanup_tmp() {
    rm -f "$TMP" "$VALID"
}
trap cleanup_tmp EXIT

cat >"$TMP" <<EOF
# ============================================================
# Nuvrion — адаптивный сетевой профиль v1.0.0
# Автор: Nuvrion
# Сформировано: $(date -Is)
# CPU: ${CPU}
# RAM: ${RAM_MB} MB
# ============================================================

# Управление перегрузкой / default qdisc
net.core.default_qdisc = ${QDISC}
net.ipv4.tcp_congestion_control = ${CONGESTION}

# Буферы сокетов
net.core.rmem_max = ${RMEM_MAX}
net.core.wmem_max = ${WMEM_MAX}
net.ipv4.tcp_rmem = ${TCP_RMEM_MIN} ${TCP_RMEM_DEF} ${RMEM_MAX}
net.ipv4.tcp_wmem = ${TCP_WMEM_MIN} ${TCP_WMEM_DEF} ${WMEM_MAX}

# Минимальные буферы UDP. udp_wmem_min нормализует старые версии профиля.
net.ipv4.udp_rmem_min = ${UDP_RMEM_MIN}
net.ipv4.udp_wmem_min = ${UDP_WMEM_MIN}

# Сетевые очереди
net.core.netdev_max_backlog = ${BACKLOG}
net.core.somaxconn = ${SOMAXCONN}
net.ipv4.tcp_max_syn_backlog = ${SYN_BACKLOG}

# Поведение TCP
net.ipv4.tcp_syncookies = ${SYNC_TARGET}
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_mtu_probing = ${MTU_PROBING}

# Безопасный baseline ядра. Без strict rp_filter и без отключения IPv6.
EOF
if ((${#SECURITY_SYSCTL_KEYS[@]})); then
    for key in "${SECURITY_SYSCTL_KEYS[@]}"; do
        printf '%s = %s\n' "$key" "${SECURITY_SYSCTL_VALUES[$key]}" >>"$TMP"
    done
fi
cat >>"$TMP" <<EOF

# Временные порты — нормализованы v1.0.0, старый нижний предел 1024 не наследуется.
net.ipv4.ip_local_port_range = ${PORT_LOW} ${PORT_HIGH}

EOF

if (( MANAGE_NR_OPEN )); then
    printf "\nfs.nr_open = %s\n" "$NR_OPEN" >>"$TMP"
fi
if (( MANAGE_FILE_MAX )); then
    printf "fs.file-max = %s\n" "$FILE_MAX" >>"$TMP"
fi

if (( MANAGE_RESERVED )); then
    cat >>"$TMP" <<EOF

# Сохраняем baseline, существовавший до Nuvrion. Новые TCP/UDP-резервы
# ограничиваются текущим диапазоном временных портов. Фиксированные UDP-порты
# никогда не определяются автоматически по общему выводу ss -lun.
net.ipv4.ip_local_reserved_ports = ${MERGED_RESERVED}
EOF
fi

if (( CONNTRACK_SUPPORTED )); then
    cat >>"$TMP" <<EOF

# Таблица conntrack
net.netfilter.nf_conntrack_max = ${CONNTRACK}
net.netfilter.nf_conntrack_buckets = ${CT_BUCKETS}
EOF
fi

# ============================================================
# Принудительное применение текущих значений
# ============================================================
# Текущие runtime-значения используются только для сравнения и отчёта.
# Они НЕ влияют на целевой профиль. Каждый поддерживаемый параметр
# безусловно записывается через sysctl -w, даже если уже совпадает.
# Таким образом ранее применённый тюнинг не может "победить" Nuvrion
# только потому, что он был загружен раньше или находится в другом файле.

FORCED_CHANGES=0
ALREADY_MATCHED=0

section "ПРИНУДИТЕЛЬНОЕ ПРИМЕНЕНИЕ ПРОФИЛЯ"

while IFS= read -r line || [[ -n $line ]]; do
    if [[ -z $line || $line =~ ^[[:space:]]*[#\;] ]]; then
        printf '%s\n' "$line" >>"$VALID"
        continue
    fi

    key=${line%%=*}
    key=${key//[[:space:]]/}
    value=${line#*=}
    value=${value#"${value%%[![:space:]]*}"}
    value=${value%"${value##*[![:space:]]}"}
    desired_value=$(normalize_ws "$value")
    before_value=$(normalize_ws "$(sysctl -n "$key" 2>/dev/null || echo '<недоступно>')")

    # Записываем значение всегда — даже когда оно уже совпадает.
    if "$SYSCTL_BIN" -w "${key}=${value}" >/dev/null 2>&1; then
        printf '%s\n' "$line" >>"$VALID"
        DESIRED["$key"]=$desired_value

        after_value=$(normalize_ws "$(sysctl -n "$key" 2>/dev/null || echo '<недоступно>')")
        if [[ $before_value == "$desired_value" ]]; then
            printf '%s%s[  OK  ]%s %-42s уже=%s\n' "$C_BOLD" "$C_GREEN" "$C_RESET" "$key" "$after_value"
            ALREADY_MATCHED=$((ALREADY_MATCHED + 1))
        else
            printf '%s%s[ ИЗМЕНЕНО ]%s %-34s %s -> %s\n' "$C_BOLD" "$C_MAGENTA" "$C_RESET" "$key" "$before_value" "$after_value"
            FORCED_CHANGES=$((FORCED_CHANGES + 1))
        fi
    elif [[ $key == net.netfilter.nf_conntrack_buckets && -e /proc/sys/net/netfilter/nf_conntrack_buckets ]]; then
        # Некоторые ядра разрешают увеличение hash table на лету, но отклоняют
        # уменьшение. Целевое значение всё равно сохраняем для следующей загрузки.
        printf '%s\n' "$line" >>"$VALID"
        DESIRED["$key"]=$desired_value
        PENDING_REBOOT["$key"]=1
        PROFILE_REBOOT_REQUIRED=1
        info "$key нельзя принудительно изменить на лету; цель ${value} сохранена и будет применена после перезагрузки"
    else
        warn "sysctl не поддерживается или отклонён ядром, пропущен: $key"
        SKIPPED=$((SKIPPED + 1))
    fi
done <"$TMP"

mv "$VALID" "$CONF"
chmod 0644 "$CONF"
rm -f "$TMP"
trap - EXIT

# Повторно применяем итоговый файл с диска.
if ! "$SYSCTL_BIN" -p "$CONF" >/dev/null 2>&1; then
    if (( PROFILE_REBOOT_REQUIRED )); then
        info "Часть профиля (conntrack hash table) ожидает перезагрузку; остальные параметры применены."
    else
        warn "Повторное применение $CONF вернуло ошибку; проверьте сообщения выше."
    fi
fi

# ============================================================
# Отключение старых назначений после успешной валидации профиля
# ============================================================
# Владеем только теми ключами, которые реально приняты ядром или явно
# сохранены для применения после перезагрузки. Это не даёт удалить рабочую старую
# настройку в случае, если новый параметр на конкретном ядре не поддерживается.
MANAGED_SET=()
for key in "${!DESIRED[@]}"; do
    MANAGED_SET["$key"]=1
done

section "НОРМАЛИЗАЦИЯ СТАРЫХ SYSCTL-НАСТРОЕК"
# Сначала возвращаем строки сторонних ранних файлов, которые v5.3/v5.4
# закомментировали слишком агрессивно. Они безопасны, потому что наш профиль
# сортируется позже и дополнительно закрепляется systemd unit.
shopt -s nullglob
for f in /etc/sysctl.d/*.conf; do
    restore_legacy_neutralizations "$f"
done
shopt -u nullglob

# /etc/sysctl.conf и только файлы, сортирующиеся ПОСЛЕ профиля Nuvrion,
# действительно способны переопределить его при sysctl --system/systemd-sysctl.
neutralize_managed_assignments /etc/sysctl.conf
shopt -s nullglob
for f in /etc/sysctl.d/*.conf; do
    base=$(basename "$f")
    if [[ $base > $CONF_BASE ]]; then
        neutralize_managed_assignments "$f"
    fi
done
shopt -u nullglob

if (( RESTORED_ASSIGNMENTS > 0 )); then
    ok "Восстановлено ранее затронутых сторонних назначений: ${RESTORED_ASSIGNMENTS} строк в ${RESTORED_FILES} файлах"
fi
if (( CLEANED_ASSIGNMENTS > 0 )); then
    ok "Отключены только реально более поздние назначения: ${CLEANED_ASSIGNMENTS} строк в ${CLEANED_FILES} файлах"
else
    ok "Более поздних конфликтующих назначений в /etc не найдено"
fi
info "Runtime-значения задаются Nuvrion принудительно; ранние сторонние conffiles не переписываются."

# На случай, если старый файл был только что нейтрализован, ещё раз применяем
# авторитетный профиль, чтобы итоговое live-состояние точно совпадало с ним.
if ! "$SYSCTL_BIN" -p "$CONF" >/dev/null 2>&1; then
    if (( PROFILE_REBOOT_REQUIRED )); then
        info "Профиль применён частично; conntrack hash table ожидает reboot."
    else
        warn "Контрольное применение $CONF после очистки вернуло ошибку."
    fi
fi

# ============================================================
# Авторитетное применение после systemd-sysctl при каждой загрузке
# ============================================================
# Конфигурационные файлы других программ больше не определяют итоговое
# runtime-состояние наших параметров: после штатного systemd-sysctl
# Nuvrion принудительно применяет свой профиль ещё раз перед запуском
# Docker/Remnawave/Xray.

AUTHORITATIVE_BOOT=0

if [[ -n $SYSTEMCTL_BIN && -d /run/systemd/system ]]; then
    cat >"$AUTHORITATIVE_SERVICE" <<EOF
[Unit]
Description=Nuvrion — авторитетный профиль sysctl
After=systemd-modules-load.service systemd-sysctl.service
Before=docker.service containerd.service remnanode.service xray.service
ConditionPathExists=${CONF}

[Service]
Type=oneshot
ExecStart=-${SYSCTL_BIN} -e -p ${CONF}
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
    chmod 0644 "$AUTHORITATIVE_SERVICE"
    "$SYSTEMCTL_BIN" daemon-reload
    if "$SYSTEMCTL_BIN" enable nuvrion-performance-sysctl.service >/dev/null 2>&1; then
        AUTHORITATIVE_BOOT=1
        ok "Принудительное автоприменение профиля Nuvrion после systemd-sysctl включено"
    else
        warn "Не удалось включить nuvrion-performance-sysctl.service; остаётся постоянный профиль sysctl.d"
    fi
else
    info "systemd не обнаружен; используется только постоянный профиль sysctl.d"
fi

# ============================================================
# Ограничение истории резервных копий и снимков
# ============================================================

mapfile -t OLD_SNAPS < <(find "$SNAPSHOT_DIR" -maxdepth 1 -type f -name 'pre-v1.0.0-*' -printf '%T@ %p\n' 2>/dev/null | sort -nr | awk 'NR>10 {print $2}')
if ((${#OLD_SNAPS[@]})); then rm -f "${OLD_SNAPS[@]}"; fi

mapfile -t OLD_BACKUPS < <(find "$BACKUP_DIR" -maxdepth 1 -type f -printf '%T@ %p\n' 2>/dev/null | sort -nr | awk 'NR>15 {print $2}')
if ((${#OLD_BACKUPS[@]})); then rm -f "${OLD_BACKUPS[@]}"; fi

# ============================================================
# Финальная проверка конфликтов при загрузке
# Файлы /etc уже нейтрализованы авторитетным режимом; здесь проверяются остальные источники.
# ============================================================

section "ПРОВЕРКА КОНФЛИКТОВ SYSCTL"

build_active_sysctl_files
POST_FILES=("${ACTIVE_SYSCTL_FILES[@]}")

declare -A LATE_VALUE=()
declare -A LATE_SOURCE=()

for f in "${POST_FILES[@]}"; do
    [[ -f $f || -L $f ]] || continue
    if [[ -e $CONF ]] && [[ $f -ef $CONF ]]; then continue; fi

    base=$(basename "$f")

    if [[ $base > $CONF_BASE ]]; then
        for key in "${!DESIRED[@]}"; do
            escaped=${key//./\\.}
            slash=${key//./\/}
            key_re="(${escaped}|${slash})"
            hit=$(grep -nE "^[[:space:]]*-?[[:space:]]*${key_re}[[:space:]]*=" "$f" 2>/dev/null | tail -n1 || true)
            [[ -z $hit ]] && continue

            assignment=${hit#*:}
            rhs=${assignment#*=}
            rhs=${rhs#"${rhs%%[![:space:]]*}"}
            rhs=${rhs%"${rhs##*[![:space:]]}"}

            # Files are already in effective lexicographic order, so later hits replace earlier hits.
            LATE_VALUE["$key"]=$(normalize_ws "$rhs")
            LATE_SOURCE["$key"]="$f:${hit%%:*}"
        done
    fi
done

for key in "${!LATE_VALUE[@]}"; do
    if [[ $(normalize_ws "${LATE_VALUE[$key]}") != $(normalize_ws "${DESIRED[$key]}") ]]; then
        if (( AUTHORITATIVE_BOOT )); then
            info "$key встречается позже в ${LATE_SOURCE[$key]} -> ${LATE_VALUE[$key]}, но Nuvrion принудительно вернёт ${DESIRED[$key]} после systemd-sysctl"
        else
            conflict "$key будет переопределён при загрузке файлом ${LATE_SOURCE[$key]} -> ${LATE_VALUE[$key]}"
        fi
    else
        info "$key повторяется позже с тем же значением в ${LATE_SOURCE[$key]}"
    fi
done

# /etc/sysctl.conf is special: procps 'sysctl --system' reads it last,
# while systemd-sysctl itself does not read it directly.
if [[ -f /etc/sysctl.conf ]]; then
    LEGACY_HITS=0
    LEGACY_DIFFERENT=0
    for key in "${!DESIRED[@]}"; do
        escaped=${key//./\\.}
        slash=${key//./\/}
        key_re="(${escaped}|${slash})"
        hit=$(grep -nE "^[[:space:]]*-?[[:space:]]*${key_re}[[:space:]]*=" /etc/sysctl.conf 2>/dev/null | tail -n1 || true)
        [[ -z $hit ]] && continue
        LEGACY_HITS=$((LEGACY_HITS + 1))
        assignment=${hit#*:}
        rhs=${assignment#*=}
        rhs=${rhs#"${rhs%%[![:space:]]*}"}
        rhs=${rhs%"${rhs##*[![:space:]]}"}
        if [[ $(normalize_ws "$rhs") != $(normalize_ws "${DESIRED[$key]}") ]]; then
            LEGACY_DIFFERENT=$((LEGACY_DIFFERENT + 1))
        fi
    done
    if (( LEGACY_DIFFERENT > 0 )); then
        if (( AUTHORITATIVE_BOOT )); then
            info "/etc/sysctl.conf содержит ${LEGACY_DIFFERENT} отличающихся параметров, но Nuvrion повторно применит свой профиль после systemd-sysctl; файл не переписывается через symlink/чужое управление."
        else
            warn "/etc/sysctl.conf содержит ${LEGACY_DIFFERENT} отличающихся управляемых параметров; без авторитетного systemd unit они могут повлиять на загрузку."
        fi
    elif (( LEGACY_HITS > 0 )); then
        info "/etc/sysctl.conf повторяет ${LEGACY_HITS} управляемых параметров с совместимыми значениями."
    fi
fi

if (( CONFLICTS == 0 )); then
    ok "Более поздние файлы sysctl.d не переопределяют профиль v1.0.0."
fi

# ============================================================
# Проверка фактических значений
# ============================================================

section "ПРОВЕРКА ЦЕЛЕВЫХ ЗНАЧЕНИЙ"
VERIFY_FAIL=0

for key in "${!DESIRED[@]}"; do
    desired=$(normalize_ws "${DESIRED[$key]}")
    actual=$(normalize_ws "$(sysctl -n "$key" 2>/dev/null || echo '<unavailable>')")

    if [[ $actual == "$desired" ]]; then
        printf '%s%s[  OK  ]%s %-42s %s\n' "$C_BOLD" "$C_GREEN" "$C_RESET" "$key" "$actual"
    elif [[ -n ${PENDING_REBOOT[$key]+x} ]]; then
        printf '[REBOOT] %-38s сейчас=%s после reboot=%s\n' "$key" "$actual" "$desired"
    else
        printf '%s%s[ ОШИБКА ]%s %-36s нужно=%s фактически=%s\n' "$C_BOLD" "$C_RED" "$C_RESET" "$key" "$desired" "$actual"
        VERIFY_FAIL=$((VERIFY_FAIL + 1))
    fi
done

if (( VERIFY_FAIL > 0 )); then
    CONFLICTS=$((CONFLICTS + VERIFY_FAIL))
fi

# ============================================================
# Диагностика параметров, которые нельзя менять вслепую
# ============================================================

section "ДИАГНОСТИКА ПОСЛЕ ПРИМЕНЕНИЯ"

if [[ $(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || true) == bbr ]]; then
    ok "BBR активен"
else
    warn "BBR недоступен; сохранён congestion control: $(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo unknown)"
fi

if [[ $(sysctl -n net.core.default_qdisc 2>/dev/null || true) == fq ]]; then
    ok "default_qdisc=fq"
else
    warn "fq недоступен; сохранён текущий default qdisc"
fi

DEFAULT_IF=""
if [[ -n $IP_BIN ]]; then
    DEFAULT_IF=$("$IP_BIN" -4 route show default 2>/dev/null | awk 'NR==1 {print $5}' || true)
fi

if [[ -n $DEFAULT_IF && -n $TC_BIN ]]; then
    echo "Текущий qdisc на ${DEFAULT_IF}:"
    "$TC_BIN" qdisc show dev "$DEFAULT_IF" 2>/dev/null || true
    info "Корневой qdisc показан для диагностики; v1.0.0 не заменяет mq/fq_codel вслепую на работающем интерфейсе."
fi

# Preserve foreign higher ceilings, but flag extreme values for review instead of silently blessing them.
if (( CONNTRACK_SUPPORTED )); then
    ACTUAL_CT=$(num_or_zero "$(sysctl -n net.netfilter.nf_conntrack_max 2>/dev/null || echo 0)")
    ACTUAL_BUCKETS=$(num_or_zero "$(sysctl -n net.netfilter.nf_conntrack_buckets 2>/dev/null || echo 0)")
    CT_COUNT=$(num_or_zero "$(sysctl -n net.netfilter.nf_conntrack_count 2>/dev/null || echo 0)")

    if (( ACTUAL_CT >= CT_BASE )); then
        ok "conntrack_max=${ACTUAL_CT}"
    else
        warn "conntrack_max=${ACTUAL_CT} ниже адаптивной базы ${CT_BASE}"
    fi
    echo "Conntrack buckets: текущие=${ACTUAL_BUCKETS}, цель=${CT_BUCKETS}, активные=${CT_COUNT}"

    if (( ACTUAL_BUCKETS >= CT_BUCKETS )); then
        ok "Размер hash buckets conntrack подходит"
    else
        warn "Conntrack buckets остались ниже цели; ядро отклонило изменение на лету или оно недоступно."
    fi
fi

if (( MANAGE_RESERVED )); then
    echo "Зарезервированные порты: $(sysctl -n net.ipv4.ip_local_reserved_ports 2>/dev/null || true)"
    echo "Базовый список резервов: ${BASE_RESERVED:-<пусто>} (${BASELINE_SOURCE})"
    if ((${#FIXED_TCP_PORTS[@]})); then
        echo "Автоматически найденные TCP LISTEN-порты во временном диапазоне: ${FIXED_TCP_PORTS[*]}"
    else
        info "TCP LISTEN-порты внутри временного диапазона не обнаружены."
    fi
    if [[ -n $EXPLICIT_UDP_RESERVED ]]; then
        echo "Явно заданные UDP-резервы во временном диапазоне: ${EXPLICIT_UDP_RESERVED}"
        ok "Источник явных UDP-резервов принят"
        if (( UDP_ENV_USED )); then
            info "NUVRION_UDP_PORTS действует только на этот запуск; для постоянной настройки используйте ${UDP_PORTS_FILE}."
        fi
    else
        info "Фиксированные UDP-порты во временном диапазоне не заданы; v1.0.0 не определяет их по ss -lun."
    fi
    if (( UDP_OUT_OF_RANGE_IGNORED )); then
        info "Явные UDP-порты вне ${PORT_LOW}-${PORT_HIGH} не резервировались: временный allocator их не использует."
    fi
    if (( V4_RESERVED_RECONCILED )); then
        if [[ $(normalize_ws "$CUR_RESERVED") != $(normalize_ws "$MERGED_RESERVED") ]]; then
            ok "Резервы v4 восстановлены по pre-v4 baseline; случайные UDP-порты не перенесены"
        else
            info "Базовый список резервов v4 восстановлен; устаревших резервов для удаления нет"
        fi
    fi
    ok "Политика зарезервированных портов применена и проверена"
else
    info "ip_local_reserved_ports недоступен в этом ядре; настройка резервов пропущена."
fi
info "TCP LISTEN-порты определяются на момент запуска; после добавления/смены высоких TCP inbound запустите v1.0.0 повторно."
info "Для фиксированных UDP inbound >= ${PORT_LOW} добавьте порты в ${UDP_PORTS_FILE} (или NUVRION_UDP_PORTS) и повторите v1.0.0."

TCP_MEM=$(sysctl -n net.ipv4.tcp_mem 2>/dev/null || true)
[[ -n $TCP_MEM ]] && echo "tcp_mem (авто ядра): $(normalize_ws "$TCP_MEM")"
UDP_MEM=$(sysctl -n net.ipv4.udp_mem 2>/dev/null || true)
[[ -n $UDP_MEM ]] && echo "udp_mem (авто ядра): $(normalize_ws "$UDP_MEM")"
OPTMEM_MAX=$(sysctl -n net.core.optmem_max 2>/dev/null || true)
[[ -n $OPTMEM_MAX ]] && echo "optmem_max (диагностика): ${OPTMEM_MAX}"
info "tcp_mem/udp_mem оставлены на авторасчёте ядра; optmem_max выводится только для диагностики."

# ============================================================
# ZRAM + безопасные VM-настройки
# ============================================================
# Логика:
#   1) проверить, есть ли реально активный /dev/zram* swap;
#   2) если обнаружена известная внешняя конфигурация, но ZRAM не работает —
#      попытаться восстановить её, не перезаписывая пользовательские настройки;
#   3) если ZRAM не настроен — установить недостающие базовые компоненты,
#      загрузить модуль и создать аварийный compressed swap Nuvrion;
#   4) после любых действий повторно проверить фактический swapon.
# Размер собственного ZRAM: 25% RAM, минимум 128 MB, максимум 2048 MB,
# priority=100. Рабочий внешний ZRAM никогда не перезаписывается.

section "ZRAM И БЕЗОПАСНЫЕ VM-НАСТРОЙКИ"

ZRAM_REPAIRED=0
ZRAM_MANAGED_BY_NUVRION=0
ZRAM_STATUS="не проверен"
ZRAM_SIZE_MB=0
ZRAM_SETUP=/usr/local/sbin/nuvrion-zram-setup.sh
ZRAM_SERVICE=/etc/systemd/system/nuvrion-zram.service
ZRAM_VM_CONF=/etc/sysctl.d/99-zzzy-nuvrion-zram.conf
ZRAM_ACTIVE_DEV=""

refresh_zram_bins() {
    MODPROBE_BIN=$(command -v modprobe || true)
    SWAPON_BIN=$(command -v swapon || true)
    SWAPOFF_BIN=$(command -v swapoff || true)
    MKSWAP_BIN=$(command -v mkswap || true)
    FINDMNT_BIN=$(command -v findmnt || true)
    SYSTEMCTL_BIN=$(command -v systemctl || true)
}

get_active_zram() {
    local dev
    [[ -n $SWAPON_BIN ]] || return 0
    while IFS= read -r dev; do
        [[ $dev == /dev/zram* ]] && { printf '%s' "$dev"; return 0; }
    done < <("$SWAPON_BIN" --show=NAME --noheadings --raw 2>/dev/null || true)
    return 0
}

get_zram_size_mb() {
    local dev=${1:-} bytes=0 name
    [[ $dev == /dev/zram* ]] || { printf '0'; return 0; }
    name=${dev##*/}
    [[ -r /sys/block/$name/disksize ]] || { printf '0'; return 0; }
    bytes=$(cat "/sys/block/$name/disksize" 2>/dev/null || echo 0)
    bytes=$(num_or_zero "$bytes")
    printf '%s' "$((bytes / 1024 / 1024))"
}

get_zram_priority() {
    local dev=${1:-}
    [[ -n $SWAPON_BIN && -n $dev ]] || return 0
    "$SWAPON_BIN" --show=NAME,PRIO --noheadings --raw 2>/dev/null \
        | awk -v d="$dev" '$1==d {print $2; exit}'
}

has_generator_zram_config() {
    [[ -e /etc/systemd/zram-generator.conf ]] && return 0
    compgen -G '/etc/systemd/zram-generator.conf.d/*.conf' >/dev/null 2>&1 && return 0
    return 1
}

has_zramswap_config() {
    [[ -e /etc/default/zramswap ]]
}

has_custom_external_zram_service() {
    local f
    shopt -s nullglob
    for f in /etc/systemd/system/zram*.service /etc/systemd/system/*zram*.service /etc/systemd/system/zramswap.service; do
        if [[ -e $f && $f != "$ZRAM_SERVICE" ]]; then
            shopt -u nullglob
            return 0
        fi
    done
    shopt -u nullglob
    return 1
}

has_external_zram_manager() {
    has_generator_zram_config || has_zramswap_config || has_custom_external_zram_service
}

has_persistent_sysctl_assignment_elsewhere() {
    local key=$1 exclude=${2:-} f escaped slash key_re
    escaped=${key//./\\.}
    slash=${key//./\/}
    key_re="(${escaped}|${slash})"
    shopt -s nullglob
    for f in /etc/sysctl.d/*.conf /etc/sysctl.conf; do
        [[ -e $f ]] || continue
        if [[ -n $exclude && -e $exclude && $f -ef $exclude ]]; then continue; fi
        if grep -Eq "^[[:space:]]*-?[[:space:]]*${key_re}[[:space:]]*=" "$f" 2>/dev/null; then
            shopt -u nullglob
            return 0
        fi
    done
    shopt -u nullglob
    return 1
}

# ---- ZRAM: ограниченные по времени вызовы (исправление зависаний) ----
ZRAM_APT_LOG="$STATE_DIR/zram-apt-${RUN_ID}.log"
ZRAM_APT_UPDATED=0
ZRAM_DEFERRED=0
ZRAM_DEFERRED_READY=0
ZRAM_PENDING_KERNEL=""
ZRAM_APT_BLOCKED=0
ZRAM_SERVICE_LOG="$STATE_DIR/zram-service-${RUN_ID}.log"

# Не запускаем потенциально блокирующую команду без ограничителя времени.
zram_timeout() {
    local secs=$1; shift
    if [[ -n $TIMEOUT_BIN ]]; then
        "$TIMEOUT_BIN" --kill-after=15 "$secs" "$@"
    else
        warn "timeout отсутствует — операция ZRAM пропущена: $*" >&2
        return 127
    fi
}

zram_systemctl() {
    [[ -n $SYSTEMCTL_BIN ]] || return 1
    zram_timeout 120 "$SYSTEMCTL_BIN" --no-ask-password "$@" </dev/null >>"$ZRAM_SERVICE_LOG" 2>&1
}

zram_restart_unit() {
    local unit=$1 rc
    if zram_systemctl restart "$unit"; then return 0; else rc=$?; fi
    if (( rc == 124 || rc == 137 )); then
        # timeout завершает клиент systemctl, но не задание в PID 1.
        # Отменяем запуск запросом stop и не ставим повторный start в очередь.
        warn "Ожидание $unit истекло; запрашиваю остановку. Журнал: $ZRAM_SERVICE_LOG"
        zram_systemctl --no-block stop "$unit" || warn "Не удалось запросить остановку $unit; проверьте systemctl status."
    else
        warn "Не удалось запустить $unit (код $rc). Журнал: $ZRAM_SERVICE_LOG"
    fi
    return "$rc"
}

zram_modprobe() {
    [[ -n $MODPROBE_BIN ]] || return 1
    zram_timeout 30 "$MODPROBE_BIN" zram num_devices=1 </dev/null >/dev/null 2>&1 \
        || zram_timeout 30 "$MODPROBE_BIN" zram </dev/null >/dev/null 2>&1
}

zram_apt() {
    # NEEDRESTART_MODE=l: needrestart только сообщает и НЕ перезапускает службы
    # посреди тюнинга (при mode=a после свежего обновления системы он
    # перезапускал службы и мог подвешивать установку).
    (( ZRAM_APT_BLOCKED == 0 )) || return 125
    local rc
    if zram_timeout 900 env DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=l \
        NEEDRESTART_SUSPEND=1 APT_LISTCHANGES_FRONTEND=none UCF_FORCE_CONFFOLD=1 \
        "$APT_GET_BIN" -q \
        -o DPkg::Lock::Timeout=300 \
        -o Acquire::Retries=2 \
        -o Acquire::http::Timeout=30 -o Acquire::https::Timeout=30 \
        -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold \
        "$@" </dev/null >>"$ZRAM_APT_LOG" 2>&1; then
        return 0
    else
        rc=$?
    fi
    if (( rc == 124 || rc == 137 )); then
        ZRAM_APT_BLOCKED=1
        warn "APT превысил лимит времени; новые установки ZRAM отменены. Проверьте состояние dpkg и журнал $ZRAM_APT_LOG."
    fi
    return "$rc"
}

zram_pkg_installed() {
    [[ -n $DPKG_QUERY_BIN ]] || return 1
    # shellcheck disable=SC2016
    [[ $(zram_timeout 15 "$DPKG_QUERY_BIN" -W -f='${Status}' "$1" 2>/dev/null || true) == 'install ok installed' ]]
}

zram_pkg_has_candidate() {
    local cand policy rc
    # Сначала читаем весь вывод: ранний exit awk закрывал pipe и мог
    # завершить apt-cache по SIGPIPE; pipefail объявлял доступный пакет отсутствующим.
    if policy=$(LC_ALL=C zram_timeout 30 apt-cache policy "$1" 2>>"$ZRAM_APT_LOG"); then
        cand=$(awk '/^[[:space:]]*Candidate:/ && !seen {value=$2; seen=1} END {print value}' <<<"$policy")
        [[ -n $cand && $cand != '(none)' ]] && return 0
        printf '\napt-cache policy %s: кандидат не найден\n%s\n' "$1" "$policy" >>"$ZRAM_APT_LOG"
    else
        rc=$?
        printf '\napt-cache policy %s: код %s\n%s\n' "$1" "$rc" "$policy" >>"$ZRAM_APT_LOG"
    fi
    return 1
}

apt_install_zram_packages() {
    local -a pkgs=() missing=()
    local p rc
    pkgs=("$@")
    ((${#pkgs[@]})) || return 0
    (( ZRAM_APT_BLOCKED == 0 )) || return 1
    [[ ${INSTALL_ZRAM_PACKAGES:-1} == 1 ]] || {
        info "Автоустановка компонентов ZRAM отключена NUVRION_INSTALL_ZRAM_PACKAGES=0."
        return 1
    }
    [[ -n $APT_GET_BIN ]] || {
        warn "apt-get недоступен: нельзя автоматически установить ${pkgs[*]}."
        return 1
    }
    for p in "${pkgs[@]}"; do
        zram_pkg_installed "$p" || missing+=("$p")
    done
    ((${#missing[@]})) || { refresh_zram_bins; return 0; }

    # Индекс APT обновляем не более одного раза и только если пакета нет в индексе.
    for p in "${missing[@]}"; do
        if ! zram_pkg_has_candidate "$p" && (( ZRAM_APT_UPDATED == 0 )); then
            ZRAM_APT_UPDATED=1
            info "Проверка индекса APT не подтвердила пакет $p — обновляю индекс (до 15 мин, журнал: $ZRAM_APT_LOG)."
            zram_apt update || warn "apt-get update завершился с ошибкой/по таймауту; подробности: $ZRAM_APT_LOG"
            (( ZRAM_APT_BLOCKED == 0 )) || return 1
        fi
        if ! zram_pkg_has_candidate "$p"; then
            # apt-cache — предварительная проверка, а не основание запрещать
            # установку. Окончательный результат и причину отказа даёт apt-get.
            info "apt-cache не подтвердил наличие $p; пакет проверит установка APT. Журнал: $ZRAM_APT_LOG"
        fi
    done

    info "Устанавливаю компоненты ZRAM: ${missing[*]} (может занять несколько минут, журнал: $ZRAM_APT_LOG)"
    if zram_apt install -y --no-install-recommends --no-remove "${missing[@]}"; then
        refresh_zram_bins
        ok "Компоненты ZRAM установлены: ${missing[*]}"
        return 0
    else
        rc=$?
    fi
    if (( rc == 124 || rc == 137 )); then
        warn "Установка ${missing[*]} прервана по таймауту; причина указана в журнале: $ZRAM_APT_LOG"
    else
        warn "Не удалось установить компоненты ZRAM: ${missing[*]} (код $rc). Журнал: $ZRAM_APT_LOG"
    fi
    refresh_zram_bins
    return 1
}

ensure_zram_userspace_tools() {
    [[ -n $TIMEOUT_BIN ]] || { warn "timeout отсутствует — автоматическая настройка ZRAM пропущена."; return 1; }
    local -a pkgs=()
    [[ -n $MODPROBE_BIN ]] || pkgs+=(kmod)
    if [[ -z $SWAPON_BIN || -z $SWAPOFF_BIN || -z $MKSWAP_BIN ]]; then
        pkgs+=(util-linux)
    fi
    if ((${#pkgs[@]})); then
        apt_install_zram_packages "${pkgs[@]}" || true
    fi
    refresh_zram_bins

    [[ -n $MODPROBE_BIN ]] || { warn "modprobe отсутствует — ZRAM нельзя загрузить."; return 1; }
    [[ -n $SWAPON_BIN ]] || { warn "swapon отсутствует — ZRAM нельзя активировать как swap."; return 1; }
    [[ -n $SWAPOFF_BIN ]] || { warn "swapoff отсутствует — восстановление ZRAM небезопасно."; return 1; }
    [[ -n $MKSWAP_BIN ]] || { warn "mkswap отсутствует — ZRAM нельзя подготовить как swap."; return 1; }
    return 0
}

zram_module_present() {
    [[ -d /sys/block/zram0 || -d /sys/class/zram-control ]]
}

zram_latest_bootable_kernel() {
    local d cur flavor best=''
    cur=$(uname -r)
    # Ubuntu ABI/flavour must match; do not prepare an unrelated aws/lowlatency
    # kernel or infer a usable kernel from reboot-required alone.
    [[ $cur =~ ^[0-9]+\.[0-9]+\.[0-9]+-[0-9]+-([[:alnum:]_.+-]+)$ ]] || return 1
    flavor=${BASH_REMATCH[1]}
    for d in /lib/modules/*/; do
        d=${d%/}; d=${d##*/}
        [[ $d != "$cur" ]] || continue
        [[ $d =~ ^[0-9]+\.[0-9]+\.[0-9]+-[0-9]+-([[:alnum:]_.+-]+)$ ]] || continue
        [[ ${BASH_REMATCH[1]} == "$flavor" ]] || continue
        [[ $(printf '%s\n' "$cur" "$d" | sort -V | tail -n 1) == "$d" ]] || continue
        [[ -f /boot/vmlinuz-$d || -f /lib/modules/$d/vmlinuz ]] || continue
        if [[ -z $best || $(printf '%s\n' "$best" "$d" | sort -V | tail -n 1) == "$d" ]]; then best=$d; fi
    done
    [[ -n $best ]] || return 1
    printf '%s\n' "$best"
}

# Only the newest bootable kernel of the same flavour may be deferred to.
# Its module must exist even if APT reported a successful installation.
zram_in_newer_kernel() {
    local d module
    ZRAM_PENDING_KERNEL=""
    d=$(zram_latest_bootable_kernel) || return 1
    for module in /lib/modules/"$d"/kernel/drivers/block/zram/zram.ko*; do
        [[ -f $module ]] || continue
        ZRAM_PENDING_KERNEL=$d
        return 0
    done
    return 1
}

ensure_zram_kernel_module() {
    ZRAM_DEFERRED=0
    zram_module_present && return 0
    [[ -n $MODPROBE_BIN ]] || return 1

    if zram_modprobe; then
        local i
        for i in 1 2 3 4 5 6 7 8 9 10; do
            zram_module_present && return 0
            sleep 0.5
        done
    fi

    # Установлено новое ядро, а работает старое: не ставим linux-modules-extra
    # под уходящее ядро (100+ МБ, пересборка initramfs, минуты «тишины»).
    # ZRAM включится автоматически после перезагрузки в новое ядро.
    if zram_in_newer_kernel; then
        info "ZRAM недоступен в текущем ядре $(uname -r); найдено более новое ядро $ZRAM_PENDING_KERNEL с модулем ZRAM."
        ZRAM_DEFERRED=1
        return 1
    fi

    # На Ubuntu generic модуль zram может находиться в linux-modules-extra.
    local os_id="" next_kernel=""
    if [[ -r /etc/os-release ]]; then
        os_id=$(awk -F= '$1=="ID" {gsub(/"/,"",$2); print $2; exit}' /etc/os-release 2>/dev/null || true)
    fi
    if [[ $os_id == ubuntu && ${INSTALL_ZRAM_PACKAGES:-1} == 1 ]]; then
        next_kernel=$(zram_latest_bootable_kernel) || next_kernel=''
        if [[ -n $next_kernel ]]; then
            info "Подготавливаю ZRAM для установленного нового ядра $next_kernel; требуется linux-modules-extra."
            if apt_install_zram_packages "linux-modules-extra-$next_kernel"; then
                if zram_in_newer_kernel; then
                    ZRAM_DEFERRED=1
                    return 1
                fi
                warn "APT завершён, но модуль ZRAM нового ядра $next_kernel не найден; отложенный запуск не подтверждён."
            fi
            # No retry against the retiring kernel after a failed install or
            # APT timeout; never advertise reboot as a guaranteed repair.
            return 1
        fi
        if apt_install_zram_packages "linux-modules-extra-$(uname -r)"; then
            zram_modprobe || true
            zram_module_present && return 0
        fi
    fi

    return 1
}
# ---- конец блока исправлений ----

zram_device_has_non_swap_use() {
    local dev=${1:-/dev/zram0}
    if [[ -n $FINDMNT_BIN ]] && "$FINDMNT_BIN" -rn -S "$dev" >/dev/null 2>&1; then
        return 0
    fi
    return 1
}

repair_known_external_zram() {
    local attempted=0 active unit f

    [[ -n $SYSTEMCTL_BIN && -d /run/systemd/system ]] || return 1
    ensure_zram_userspace_tools || return 1

    # Внешний менеджер тоже зависит от рабочего kernel-модуля. На Ubuntu
    # после смены ядра zram.ko может отсутствовать до установки
    # linux-modules-extra-$(uname -r). Сначала восстанавливаем модуль, затем
    # уже перезапускаем существующий менеджер, не меняя его конфигурацию.
    if ! ensure_zram_kernel_module; then
        if (( ZRAM_DEFERRED )); then
            warn "Для внешнего ZRAM требуется загрузка ядра $ZRAM_PENDING_KERNEL и повторная проверка менеджера."
            return 1
        fi
        warn "Модуль zram недоступен для ядра $(uname -r); внешний менеджер ZRAM запустить нельзя."
        return 1
    fi

    # zram-tools / zramswap
    if has_zramswap_config; then
        attempted=1
        if ! zram_systemctl cat zramswap.service; then
            apt_install_zram_packages zram-tools || true
        fi
        zram_systemctl daemon-reload || true
        if zram_systemctl cat zramswap.service; then
            zram_systemctl reset-failed zramswap.service || true
            zram_systemctl enable zramswap.service || true
            zram_restart_unit zramswap.service || return 1
            sleep 1
            active=$(get_active_zram)
            if [[ -n $active ]]; then
                ZRAM_REPAIRED=1
                ZRAM_STATUS="восстановлен внешний zramswap (${active})"
                ok "ZRAM восстановлен через zramswap.service: ${active}"
                return 0
            fi
        fi
    fi

    # systemd-zram-generator
    if has_generator_zram_config; then
        attempted=1
        if [[ ! -x /usr/lib/systemd/system-generators/zram-generator \
              && ! -x /lib/systemd/system-generators/zram-generator ]]; then
            apt_install_zram_packages systemd-zram-generator || true
        fi
        zram_systemctl daemon-reload || true
        zram_systemctl reset-failed 'systemd-zram-setup@zram0.service' || true
        # Swap-юнит запускает setup как зависимость и затем включает swap.
        zram_restart_unit dev-zram0.swap || return 1
        sleep 1
        active=$(get_active_zram)
        if [[ -n $active ]]; then
            ZRAM_REPAIRED=1
            ZRAM_STATUS="восстановлен systemd-zram-generator (${active})"
            ok "ZRAM восстановлен через systemd-zram-generator: ${active}"
            return 0
        fi
    fi

    # Пользовательский systemd-сервис: не переписываем его, только пытаемся
    # запустить уже существующую единицу и проверяем фактический результат.
    shopt -s nullglob
    for f in /etc/systemd/system/*zram*.service; do
        [[ -e $f && $f != "$ZRAM_SERVICE" ]] || continue
        attempted=1
        unit=$(basename "$f")
        zram_systemctl reset-failed "$unit" || true
        if ! zram_restart_unit "$unit"; then
            shopt -u nullglob
            return 1
        fi
        sleep 1
        active=$(get_active_zram)
        if [[ -n $active ]]; then
            shopt -u nullglob
            ZRAM_REPAIRED=1
            ZRAM_STATUS="восстановлен внешним сервисом ${unit} (${active})"
            ok "ZRAM восстановлен через ${unit}: ${active}"
            return 0
        fi
    done
    shopt -u nullglob

    (( attempted )) && return 1
    return 1
}

create_or_repair_nuvrion_zram() {
    ZRAM_DEFERRED_READY=0
    ZRAM_SIZE_MB=$((RAM_MB / 4))
    (( ZRAM_SIZE_MB < 128 )) && ZRAM_SIZE_MB=128
    (( ZRAM_SIZE_MB > 2048 )) && ZRAM_SIZE_MB=2048

    [[ -n $SYSTEMCTL_BIN && -d /run/systemd/system ]] || {
        warn "systemd недоступен — постоянный ZRAM Nuvrion создать нельзя."
        return 1
    }
    ensure_zram_userspace_tools || return 1
    if ! ensure_zram_kernel_module; then
        if (( ZRAM_DEFERRED )); then
            write_nuvrion_zram_units || return 1
            if zram_systemctl daemon-reload && zram_systemctl enable nuvrion-zram.service; then
                local pending_tmp
                pending_tmp=$(mktemp "$STATE_DIR/zram-pending-kernel.XXXXXX") || return 1
                if ! printf '%s\n' "$ZRAM_PENDING_KERNEL" > "$pending_tmp" \
                   || ! chmod 0600 "$pending_tmp" \
                   || ! mv -f "$pending_tmp" "$STATE_DIR/zram-pending-kernel"; then
                    rm -f "$pending_tmp"
                    return 1
                fi
                ZRAM_DEFERRED_READY=1
                ZRAM_STATUS="запуск отложен: загрузитесь в ядро $ZRAM_PENDING_KERNEL и проверьте swap"
                info "nuvrion-zram.service включён; попытка запуска ZRAM запланирована при следующей загрузке. Требуется ядро $ZRAM_PENDING_KERNEL."
                return 0
            fi
            ZRAM_STATUS="не удалось включить отложенный запуск ZRAM"
        fi
        warn "Модуль zram недоступен для ядра $(uname -r); ZRAM не создан."
        return 1
    fi

    if [[ -e /dev/zram0 ]] && zram_device_has_non_swap_use /dev/zram0; then
        warn "/dev/zram0 используется не как swap; автоматическое восстановление пропущено, чтобы не повредить данные."
        return 1
    fi

    write_nuvrion_zram_units || return 1

    zram_systemctl daemon-reload || return 1
    zram_systemctl reset-failed nuvrion-zram.service || true
    # enable --now не перезапускает active (exited), даже если swap уже пропал.
    # restart ограничен TimeoutStartSec в юните и timeout здесь.
    if zram_systemctl enable nuvrion-zram.service \
       && zram_restart_unit nuvrion-zram.service; then
        sleep 1
        ZRAM_ACTIVE_DEV=$(get_active_zram)
        if [[ -n $ZRAM_ACTIVE_DEV ]]; then
            ZRAM_MANAGED_BY_NUVRION=1
            ZRAM_STATUS="Nuvrion ${ZRAM_SIZE_MB} MB (${ZRAM_ACTIVE_DEV})"
            ok "ZRAM создан/восстановлен: ${ZRAM_ACTIVE_DEV}, ${ZRAM_SIZE_MB} MB, priority=100"
            return 0
        fi
    fi

    warn "nuvrion-zram.service не подтвердил активный /dev/zram* swap (см. journalctl -u nuvrion-zram)."
    ZRAM_STATUS="сервис Nuvrion не смог активировать swap"
    return 1
}

write_nuvrion_zram_units() {
    mkdir -p /usr/local/sbin || return 1
    cat >"$ZRAM_SETUP" <<EOF || return 1
#!/usr/bin/env bash
set -euo pipefail
MODPROBE_BIN='${MODPROBE_BIN}'
SWAPON_BIN='${SWAPON_BIN}'
MKSWAP_BIN='${MKSWAP_BIN}'
TIMEOUT_BIN='${TIMEOUT_BIN}'
SIZE_MB='${ZRAM_SIZE_MB}'

active_zram() {
    "\$SWAPON_BIN" --show=NAME --noheadings --raw 2>/dev/null | grep -Em1 '^/dev/zram[0-9]+$' || true
}

if [[ -n \$(active_zram) ]]; then
    exit 0
fi

"\$TIMEOUT_BIN" --kill-after=5 15 "\$MODPROBE_BIN" zram num_devices=1 >/dev/null 2>&1 || "\$TIMEOUT_BIN" --kill-after=5 15 "\$MODPROBE_BIN" zram >/dev/null 2>&1
# Узел /dev/zram0 может появиться не сразу после modprobe.
for _ in \$(seq 1 20); do
    [[ -e /sys/block/zram0/disksize || -r /sys/class/zram-control/hot_add ]] && break
    sleep 0.25
done

# Обычно модуль создаёт zram0. Если он был удалён через hot_remove,
# восстанавливаем устройство через zram-control.
if [[ ! -e /sys/block/zram0/disksize && -r /sys/class/zram-control/hot_add ]]; then
    id=\$(cat /sys/class/zram-control/hot_add 2>/dev/null || true)
    if [[ \$id =~ ^[0-9]+$ && -e /sys/block/zram\$id/disksize ]]; then
        DEV="/dev/zram\$id"
        SYS="/sys/block/zram\$id"
    fi
fi

DEV=\${DEV:-/dev/zram0}
SYS=\${SYS:-/sys/block/zram0}
for _ in \$(seq 1 20); do
    [[ -b \$DEV && -e \$SYS/disksize ]] && break
    sleep 0.25
done
[[ -b \$DEV && -e \$SYS/disksize ]] || exit 1

# Никогда не сбрасываем zram, который используется как файловая система.
if command -v findmnt >/dev/null 2>&1 && findmnt -rn -S "\$DEV" >/dev/null 2>&1; then
    exit 2
fi

current=\$(cat "\$SYS/disksize" 2>/dev/null || echo 0)
if [[ \$current =~ ^[0-9]+$ ]] && (( current > 0 )); then
    # Отсутствие mount/swap не доказывает, что чужое блочное устройство пусто.
    # Уже инициализированный ZRAM не сбрасываем и не форматируем: пытаемся
    # включить существующий swap, а при другой сигнатуре оставляем данные.
    "\$TIMEOUT_BIN" --kill-after=5 15 "\$SWAPON_BIN" --priority 100 "\$DEV"
    [[ -n \$(active_zram) ]] || exit 4
    exit 0
fi

if [[ -w \$SYS/comp_algorithm ]]; then
    algs=\$(cat "\$SYS/comp_algorithm" 2>/dev/null || true)
    if grep -qw zstd <<<"\$algs"; then
        echo zstd >"\$SYS/comp_algorithm"
    elif grep -qw lz4 <<<"\$algs"; then
        echo lz4 >"\$SYS/comp_algorithm"
    fi
fi

echo \$((SIZE_MB * 1024 * 1024)) >"\$SYS/disksize"
"\$TIMEOUT_BIN" --kill-after=5 15 "\$MKSWAP_BIN" -f "\$DEV" >/dev/null
"\$TIMEOUT_BIN" --kill-after=5 15 "\$SWAPON_BIN" --priority 100 "\$DEV"

active=\$(active_zram)
[[ -n \$active ]] || exit 4
EOF
    chmod 0755 "$ZRAM_SETUP" || return 1

    cat >"$ZRAM_SERVICE" <<EOF || return 1
[Unit]
Description=Nuvrion — проверка и восстановление ZRAM
After=systemd-modules-load.service

[Service]
Type=oneshot
ExecStart=${ZRAM_SETUP}
RemainAfterExit=yes
TimeoutStartSec=90
TimeoutStopSec=15

[Install]
WantedBy=multi-user.target
EOF
    chmod 0644 "$ZRAM_SERVICE"
}

# Шаг 1. Фактическая проверка, а не наличие конфиг-файла.
# Для чтения состояния нужен только swapon. Остальные инструменты ставятся
# лишь если ZRAM действительно придётся создавать или ремонтировать.
refresh_zram_bins
if [[ -z $SWAPON_BIN ]]; then
    apt_install_zram_packages util-linux || true
    refresh_zram_bins
fi
ZRAM_ACTIVE_DEV=$(get_active_zram)

if [[ -n $ZRAM_ACTIVE_DEV ]]; then
    ZRAM_SIZE_MB=$(get_zram_size_mb "$ZRAM_ACTIVE_DEV")
    ZRAM_PRIO=$(get_zram_priority "$ZRAM_ACTIVE_DEV")
    if (( ZRAM_SIZE_MB > 0 )); then
        rm -f "$STATE_DIR/zram-pending-kernel" || warn "Не удалось удалить старый статус отложенного ZRAM."
        if [[ -f $ZRAM_SERVICE && -n $SYSTEMCTL_BIN ]] \
           && zram_systemctl is-active --quiet nuvrion-zram.service \
           && ! has_external_zram_manager; then
            ZRAM_MANAGED_BY_NUVRION=1
            ZRAM_STATUS="Nuvrion активен (${ZRAM_ACTIVE_DEV}, ${ZRAM_SIZE_MB} MB)"
        else
            ZRAM_STATUS="активен (${ZRAM_ACTIVE_DEV}, ${ZRAM_SIZE_MB} MB)"
        fi
        ok "ZRAM исправен: ${ZRAM_ACTIVE_DEV}, ${ZRAM_SIZE_MB} MB${ZRAM_PRIO:+, priority=${ZRAM_PRIO}}"
    else
        warn "${ZRAM_ACTIVE_DEV} присутствует в swapon, но disksize=0; состояние некорректно."
        ZRAM_ACTIVE_DEV=""
        ZRAM_STATUS="обнаружен некорректный активный ZRAM"
    fi
fi

# Шаг 2. Есть конфигурация, но ZRAM не активен — пытаемся починить её.
if [[ -z $ZRAM_ACTIVE_DEV ]] && has_external_zram_manager; then
    info "Конфигурация ZRAM найдена, но активного swap нет — выполняю восстановление."
    if repair_known_external_zram; then
        ZRAM_ACTIVE_DEV=$(get_active_zram)
        ZRAM_SIZE_MB=$(get_zram_size_mb "$ZRAM_ACTIVE_DEV")
    else
        ZRAM_STATUS="внешняя конфигурация обнаружена, восстановление не удалось"
        warn "Внешняя конфигурация ZRAM есть, но восстановить активный swap не удалось; пользовательские файлы не перезаписаны."
    fi
fi

# Шаг 3. Если внешнего менеджера нет, создаём/ремонтируем собственный ZRAM.
if [[ -z $ZRAM_ACTIVE_DEV ]] && ! has_external_zram_manager; then
    info "Рабочий ZRAM не найден — создаю или восстанавливаю конфигурацию Nuvrion."
    create_or_repair_nuvrion_zram || true
    ZRAM_ACTIVE_DEV=$(get_active_zram)
    if [[ -n $ZRAM_ACTIVE_DEV ]]; then
        ZRAM_SIZE_MB=$(get_zram_size_mb "$ZRAM_ACTIVE_DEV")
    fi
fi

# Шаг 4. Финальная проверка блока ZRAM сразу после установки/ремонта.
ZRAM_ACTIVE_DEV=$(get_active_zram)
if [[ -n $ZRAM_ACTIVE_DEV ]]; then
    ZRAM_SIZE_MB=$(get_zram_size_mb "$ZRAM_ACTIVE_DEV")
    ZRAM_PRIO=$(get_zram_priority "$ZRAM_ACTIVE_DEV")
    if (( ZRAM_SIZE_MB > 0 )); then
        ok "Повторная проверка ZRAM пройдена: ${ZRAM_ACTIVE_DEV}, ${ZRAM_SIZE_MB} MB${ZRAM_PRIO:+, priority=${ZRAM_PRIO}}"
        if (( ZRAM_REPAIRED )); then
            ZRAM_STATUS="восстановлен и проверен (${ZRAM_ACTIVE_DEV}, ${ZRAM_SIZE_MB} MB)"
        elif (( ZRAM_MANAGED_BY_NUVRION )); then
            ZRAM_STATUS="Nuvrion активен и проверен (${ZRAM_ACTIVE_DEV}, ${ZRAM_SIZE_MB} MB)"
        elif [[ $ZRAM_STATUS == "не проверен" ]]; then
            ZRAM_STATUS="активен и проверен (${ZRAM_ACTIVE_DEV}, ${ZRAM_SIZE_MB} MB)"
        fi
    else
        warn "ZRAM виден в swapon, но итоговая проверка размера не пройдена."
        ZRAM_STATUS="активен, но проверка disksize не пройдена"
    fi
else
    if (( ZRAM_DEFERRED_READY )); then
        info "$ZRAM_STATUS"
    else
        warn "Итоговая проверка: активный ZRAM не обнаружен."
    fi
    [[ $ZRAM_STATUS != "не проверен" ]] || ZRAM_STATUS="не активен"
fi

# Для собственного ZRAM разумны swappiness=100 и page-cluster=0, но только если
# пользователь не задавал эти параметры сам. Внешний ZRAM не получает наши VM-настройки.
if [[ -n $ZRAM_ACTIVE_DEV && $ZRAM_MANAGED_BY_NUVRION -eq 1 ]]; then
    ZRAM_VM_LINES=()
    for spec in 'vm.swappiness|100|60' 'vm.page-cluster|0|3'; do
        IFS='|' read -r vm_key vm_target vm_default <<<"$spec"
        vm_cur=$(normalize_ws "$(sysctl -n "$vm_key" 2>/dev/null || true)")
        [[ -n $vm_cur ]] || continue

        if has_persistent_sysctl_assignment_elsewhere "$vm_key" "$ZRAM_VM_CONF"; then
            info "$vm_key уже настроен в другом sysctl-файле; Nuvrion его не меняет."
            continue
        fi

        if [[ -f $ZRAM_VM_CONF ]] && grep -Eq "^[[:space:]]*${vm_key//./\\.}[[:space:]]*=" "$ZRAM_VM_CONF" 2>/dev/null; then
            ZRAM_VM_LINES+=("${vm_key} = ${vm_target}")
        elif [[ $vm_cur != "$vm_default" ]]; then
            info "$vm_key уже имеет нестандартное runtime-значение ${vm_cur}; существующая настройка не изменяется."
            continue
        else
            ZRAM_VM_LINES+=("${vm_key} = ${vm_target}")
        fi
    done

    if ((${#ZRAM_VM_LINES[@]})); then
        {
            echo '# Nuvrion v1.0.0 — безопасные VM-параметры для собственного ZRAM'
            printf '%s\n' "${ZRAM_VM_LINES[@]}"
        } >"$ZRAM_VM_CONF"
        chmod 0644 "$ZRAM_VM_CONF"
        for line in "${ZRAM_VM_LINES[@]}"; do
            vm_key=${line%%=*}; vm_key=${vm_key//[[:space:]]/}
            vm_val=${line#*=}; vm_val=${vm_val//[[:space:]]/}
            "$SYSCTL_BIN" -w "${vm_key}=${vm_val}" >/dev/null 2>&1 || warn "Не удалось применить $vm_key=$vm_val"
        done
        ok "Безопасные VM-настройки собственного ZRAM применены без перезаписи пользовательских параметров"
    elif [[ -f $ZRAM_VM_CONF ]]; then
        cp -a "$ZRAM_VM_CONF" "$BACKUP_DIR/$(basename "$ZRAM_VM_CONF").${RUN_ID}"
        rm -f "$ZRAM_VM_CONF"
        info "Собственный VM-профиль ZRAM удалён: параметры управляются другой настройкой."
    fi
else
    if [[ -n $ZRAM_ACTIVE_DEV ]]; then
        info "ZRAM управляется внешним механизмом; VM-параметры Nuvrion не навязываются."
    fi
    # Если раньше ZRAM был нашим, а теперь перешёл под внешний менеджер, не оставляем
    # собственные VM-параметры висеть как скрытое наследие.
    if [[ -f $ZRAM_VM_CONF && $ZRAM_MANAGED_BY_NUVRION -eq 0 ]]; then
        cp -a "$ZRAM_VM_CONF" "$BACKUP_DIR/$(basename "$ZRAM_VM_CONF").${RUN_ID}"
        rm -f "$ZRAM_VM_CONF"
        info "Старый VM-профиль Nuvrion для ZRAM сохранён в backup и удалён."
    fi
fi

# ============================================================
# Безопасное распределение сетевой обработки по ядрам (RPS)
# ============================================================
# RPS включается только когда: CPU > 1, RX-очередей меньше ядер и RPS ещё
# нигде не настроен. Если найдена существующая RPS-настройка — не трогаем.

section "ОПТИМИЗАЦИЯ РАСПРЕДЕЛЕНИЯ ПО ЯДРАМ"

RPS_STATUS="не требуется"
RPS_SERVICE=/etc/systemd/system/nuvrion-rps.service
RPS_SETUP=/usr/local/sbin/nuvrion-rps-setup.sh
PRIMARY_IF=""

if [[ -n $IP_BIN ]]; then
    PRIMARY_IF=$($IP_BIN -o route show default 2>/dev/null | awk '{print $5; exit}' || true)
fi

rps_value_nonzero() {
    local v=${1:-}
    v=${v//,/}
    v=${v//0/}
    [[ -n $v ]]
}

RPS_EXISTING=0
RXQ_COUNT=0
RXQS=()
if [[ -n $PRIMARY_IF && -d /sys/class/net/$PRIMARY_IF/queues ]]; then
    shopt -s nullglob
    RXQS=("/sys/class/net/$PRIMARY_IF/queues/rx-"*)
    shopt -u nullglob
    RXQ_COUNT=${#RXQS[@]}
    for q in "${RXQS[@]}"; do
        if [[ -r $q/rps_cpus ]] && rps_value_nonzero "$(cat "$q/rps_cpus" 2>/dev/null || true)"; then
            RPS_EXISTING=1
            break
        fi
    done
    RPS_GLOBAL=$(num_or_zero "$(sysctl -n net.core.rps_sock_flow_entries 2>/dev/null || echo 0)")
    (( RPS_GLOBAL > 0 )) && RPS_EXISTING=1
fi

if (( CPU <= 1 )); then
    RPS_STATUS="1 vCPU — не требуется"
    ok "RPS не требуется: доступен один vCPU"
elif [[ -z $PRIMARY_IF || $RXQ_COUNT -eq 0 ]]; then
    RPS_STATUS="интерфейс/очереди не определены"
    info "RPS пропущен: не удалось определить RX-очереди основного интерфейса."
elif (( RPS_EXISTING )); then
    RPS_STATUS="уже настроен"
    ok "RPS уже настроен; существующие значения не изменяются"
elif (( RXQ_COUNT >= CPU )); then
    RPS_STATUS="hardware multiqueue ${RXQ_COUNT} RX / ${CPU} CPU"
    ok "RPS не нужен: RX-очередей (${RXQ_COUNT}) не меньше числа vCPU (${CPU})"
elif [[ -n $SYSTEMCTL_BIN && -d /run/systemd/system ]]; then
    RPS_MASK=""
    if [[ -n $PYTHON3_BIN ]]; then
        RPS_MASK=$($PYTHON3_BIN - "$CPU" <<'PYMASK'
import sys
n=int(sys.argv[1])
value=(1<<n)-1
groups=[]
while value:
    groups.append(f"{value & 0xffffffff:08x}")
    value >>= 32
print(",".join(reversed(groups)) if groups else "0")
PYMASK
        )
    elif (( CPU <= 31 )); then
        printf -v RPS_MASK '%x' "$(( (1 << CPU) - 1 ))"
    fi

    if [[ -z $RPS_MASK ]]; then
        RPS_STATUS="маска CPU не рассчитана"
        info "RPS пропущен: не удалось безопасно рассчитать CPU mask."
    else
        RPS_FLOW_GLOBAL=32768
        RPS_FLOW_PERQ=$((RPS_FLOW_GLOBAL / RXQ_COUNT))
        (( RPS_FLOW_PERQ < 4096 )) && RPS_FLOW_PERQ=4096
        (( RPS_FLOW_PERQ > 32768 )) && RPS_FLOW_PERQ=32768

        mkdir -p /usr/local/sbin
        cat >"$RPS_SETUP" <<EOF
#!/usr/bin/env bash
set -euo pipefail
IP_BIN='${IP_BIN}'
SYSCTL_BIN='${SYSCTL_BIN}'
MASK='${RPS_MASK}'
FLOW_GLOBAL='${RPS_FLOW_GLOBAL}'
FLOW_PERQ='${RPS_FLOW_PERQ}'

iface=\$("\$IP_BIN" -o route show default 2>/dev/null | awk '{print \$5; exit}' || true)
[[ -n \$iface && -d /sys/class/net/\$iface/queues ]] || exit 0
shopt -s nullglob
queues=(/sys/class/net/\$iface/queues/rx-*)
shopt -u nullglob
((\${#queues[@]})) || exit 0

# Не перетираем RPS, если другой механизм уже успел его настроить.
global=\$("\$SYSCTL_BIN" -n net.core.rps_sock_flow_entries 2>/dev/null || echo 0)
[[ \$global =~ ^[0-9]+$ ]] || global=0
if (( global > 0 )); then exit 0; fi
for q in "\${queues[@]}"; do
    v=\$(cat "\$q/rps_cpus" 2>/dev/null || true)
    t=\${v//,/}; t=\${t//0/}
    [[ -n \$t ]] && exit 0
done

"\$SYSCTL_BIN" -w net.core.rps_sock_flow_entries="\$FLOW_GLOBAL" >/dev/null 2>&1 || true
for q in "\${queues[@]}"; do
    [[ -w \$q/rps_cpus ]] && echo "\$MASK" >"\$q/rps_cpus"
    if [[ -w \$q/rps_flow_cnt ]]; then
        cur=\$(cat "\$q/rps_flow_cnt" 2>/dev/null || echo 0)
        [[ \$cur =~ ^[0-9]+$ ]] || cur=0
        (( cur == 0 )) && echo "\$FLOW_PERQ" >"\$q/rps_flow_cnt"
    fi
done
EOF
        chmod 0755 "$RPS_SETUP"

        cat >"$RPS_SERVICE" <<EOF
[Unit]
Description=Nuvrion — RPS для распределения сетевой обработки по ядрам
After=network.target

[Service]
Type=oneshot
ExecStart=${RPS_SETUP}
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
        chmod 0644 "$RPS_SERVICE"
        "$SYSTEMCTL_BIN" daemon-reload
        if "$SYSTEMCTL_BIN" enable --now nuvrion-rps.service >/dev/null 2>&1; then
            RPS_STATUS="Nuvrion mask=${RPS_MASK}, RX=${RXQ_COUNT}"
            ok "RPS включён для ${PRIMARY_IF}: ${RXQ_COUNT} RX-очередь(и), CPU mask=${RPS_MASK}"
        else
            RPS_STATUS="не удалось включить"
            warn "Не удалось включить nuvrion-rps.service; существующие сетевые параметры не затронуты."
        fi
    fi
fi

# irqbalance не устанавливаем и не включаем насильно: на VPS его отсутствие может
# быть осознанным решением провайдера. Если он уже работает — просто подтверждаем.
if [[ -n $SYSTEMCTL_BIN && $CPU -gt 1 ]] && "$SYSTEMCTL_BIN" is-active --quiet irqbalance.service 2>/dev/null; then
    ok "irqbalance уже активен; существующая настройка не изменяется"
else
    info "irqbalance не активен или недоступен; Nuvrion не меняет его автоматически."
fi

# ============================================================
# Проверка и автоматическое исправление NOFILE рабочей нагрузки
# ============================================================
# Nuvrion не меняет глобальный systemd DefaultLimitNOFILE.
# Для Docker сначала используется точечный Compose override для remnanode
# и контейнер ПЕРЕСОЗДАЁТСЯ, потому что новый ulimit нельзя применить к уже
# запущенному процессу. Если контейнер не управляется Compose, используется
# Docker daemon default-ulimits используется только при явном
# NUVRION_ALLOW_DOCKER_RESTART=1; после такого изменения Docker daemon
# обязательно перезапускается.
# Для нативных xray/remnanode systemd units создаётся отдельный drop-in и
# перезапускается только соответствующий сервис.

section "ПРОВЕРКА И ИСПРАВЛЕНИЕ ЛИМИТОВ НАГРУЗКИ"

NOFILE_TARGET=1048576
WORKLOAD_FOUND=0
LIMIT_CHANGES=0
DOCKER_RESTARTED=0
DOCKER_CONTAINER_RECREATED=0
SYSTEMD_SERVICES_RESTARTED=0
LIMIT_FIX_ERRORS=0
LIMIT_RESTART_NOTICE=0

nofile_pair_ok() {
    local pair=${1:-}
    local soft hard

    [[ $pair == */* ]] || return 1
    soft=${pair%%/*}
    hard=${pair##*/}

    local limit
    for limit in "$soft" "$hard"; do
        [[ $limit == unlimited || $limit == infinity ]] && continue
        [[ $limit =~ ^[0-9]+$ ]] || return 1
        (( limit >= NOFILE_TARGET )) || return 1
    done
    return 0
}

get_remnanode_nofile() {
    # Подстановки выполняются внутри контейнера, не на хосте.
    # shellcheck disable=SC2016
    if [[ -n $TIMEOUT_BIN ]]; then
        "$TIMEOUT_BIN" 5 "$DOCKER_BIN" exec remnanode sh -c \
            'printf "%s/%s" "$(ulimit -Sn 2>/dev/null)" "$(ulimit -Hn 2>/dev/null)"' \
            2>/dev/null || true
    else
        "$DOCKER_BIN" exec remnanode sh -c \
            'printf "%s/%s" "$(ulimit -Sn 2>/dev/null)" "$(ulimit -Hn 2>/dev/null)"' \
            2>/dev/null || true
    fi
}

wait_docker_ready() {
    local i
    for ((i=1; i<=30; i++)); do
        if "$DOCKER_BIN" info >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    return 1
}

wait_remnanode_running() {
    local i state
    for ((i=1; i<=30; i++)); do
        state=$("$DOCKER_BIN" inspect --type container -f '{{.State.Running}}' remnanode 2>/dev/null || true)
        [[ $state == true ]] && return 0
        sleep 1
    done
    return 1
}

# Создаёт точечный Compose override и пересоздаёт только remnanode.
# Оригинальные compose-файлы не переписываются.
fix_remnanode_nofile_via_compose() {
    local workdir config_files service project override_dir override_file
    local f
    local -a cfgs=()
    local -a cmd=()

    "$DOCKER_BIN" compose version >/dev/null 2>&1 || return 2

    workdir=$("$DOCKER_BIN" inspect --type container -f '{{index .Config.Labels "com.docker.compose.project.working_dir"}}' remnanode 2>/dev/null || true)
    config_files=$("$DOCKER_BIN" inspect --type container -f '{{index .Config.Labels "com.docker.compose.project.config_files"}}' remnanode 2>/dev/null || true)
    service=$("$DOCKER_BIN" inspect --type container -f '{{index .Config.Labels "com.docker.compose.service"}}' remnanode 2>/dev/null || true)
    project=$("$DOCKER_BIN" inspect --type container -f '{{index .Config.Labels "com.docker.compose.project"}}' remnanode 2>/dev/null || true)

    [[ -n $workdir && -d $workdir && -n $config_files && -n $service ]] || return 2
    [[ $service =~ ^[A-Za-z0-9_.-]+$ ]] || return 2

    IFS=',' read -r -a cfgs <<<"$config_files"
    ((${#cfgs[@]})) || return 2

    override_dir="$STATE_DIR/docker"
    mkdir -p "$override_dir"
    override_file="$override_dir/${project:-remnanode}-nofile.override.yml"

    cat >"$override_file" <<EOF
# Nuvrion v1.0.0 — авторитетный NOFILE для Remnawave Node
# Автор: Nuvrion
services:
  "${service}":
    ulimits:
      nofile:
        soft: ${NOFILE_TARGET}
        hard: ${NOFILE_TARGET}
EOF
    chmod 0600 "$override_file"

    cmd=("$DOCKER_BIN" compose)
    for f in "${cfgs[@]}"; do
        [[ -n $f ]] || continue
        if [[ $f != /* ]]; then
            f="$workdir/$f"
        fi
        [[ -f $f ]] || {
            warn "Compose-файл из метаданных remnanode не найден: $f"
            return 1
        }
        cmd+=(-f "$f")
    done
    cmd+=(-f "$override_file")

    # Сначала проверяем итоговую Compose-конфигурацию, затем пересоздаём только
    # remnanode. Именно recreate, а не простой docker restart, применяет новый
    # HostConfig.Ulimits к контейнеру.
    if ! (
        cd "$workdir"
        "${cmd[@]}" config >/dev/null
    ); then
        warn "Не удалось проверить Compose-конфигурацию с NOFILE override."
        return 1
    fi

    info "NOFILE remnanode будет исправлен через Docker Compose; контейнер будет пересоздан."
    if ! (
        cd "$workdir"
        "${cmd[@]}" up -d --no-deps --force-recreate --no-build --pull never "$service"
    ); then
        warn "Не удалось пересоздать remnanode через Docker Compose."
        return 1
    fi

    DOCKER_CONTAINER_RECREATED=$((DOCKER_CONTAINER_RECREATED + 1))
    LIMIT_CHANGES=$((LIMIT_CHANGES + 1))
    LIMIT_RESTART_NOTICE=1

    if ! wait_remnanode_running; then
        warn "remnanode не перешёл в состояние running после пересоздания."
        return 1
    fi

    ok "remnanode пересоздан после изменения Docker ulimit"
    return 0
}

# Резервный путь для Docker-контейнера без Compose-метаданных.
# Меняем только default-ulimits.nofile, не уничтожая другие daemon.json keys.
fix_docker_default_nofile() {
    local daemon_json=/etc/docker/daemon.json
    if [[ ${NUVRION_ALLOW_DOCKER_RESTART:-0} != 1 ]]; then
        warn "Глобальный restart Docker запрещён по умолчанию. Для явного разрешения используйте NUVRION_ALLOW_DOCKER_RESTART=1."
        return 2
    fi
    local tmp backup existed=0 result was_running

    [[ -n $SYSTEMCTL_BIN && -d /run/systemd/system ]] || return 2
    [[ -n $PYTHON3_BIN ]] || return 2

    if "$SYSTEMCTL_BIN" cat docker.service 2>/dev/null | grep -Eq -- '--default-ulimit([=[:space:]]|$)'; then
        warn "docker.service уже задаёт --default-ulimit через командную строку; daemon.json не изменяется, чтобы не создать конфликт запуска dockerd."
        return 2
    fi

    mkdir -p /etc/docker
    tmp=$(mktemp)
    backup="$BACKUP_DIR/daemon.json.${RUN_ID}"

    if [[ -f $daemon_json ]]; then
        existed=1
        cp -a "$daemon_json" "$backup"
    fi

    if ! result=$("$PYTHON3_BIN" - "$daemon_json" "$tmp" "$NOFILE_TARGET" <<'PY'
import json
import os
import sys

src, dst, target_s = sys.argv[1], sys.argv[2], sys.argv[3]
target = int(target_s)

data = {}
if os.path.exists(src) and os.path.getsize(src) > 0:
    with open(src, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, dict):
        raise SystemExit("daemon.json: корневой JSON должен быть объектом")

default_ulimits = data.setdefault("default-ulimits", {})
if not isinstance(default_ulimits, dict):
    raise SystemExit("daemon.json: default-ulimits должен быть объектом")

old = default_ulimits.get("nofile")
wanted = {"Name": "nofile", "Soft": target, "Hard": target}
changed = old != wanted
default_ulimits["nofile"] = wanted

with open(dst, "w", encoding="utf-8") as fh:
    json.dump(data, fh, ensure_ascii=False, indent=2, sort_keys=True)
    fh.write("\n")

print("changed" if changed else "same")
PY
    ); then
        rm -f "$tmp"
        warn "Не удалось безопасно обработать /etc/docker/daemon.json."
        return 1
    fi

    if [[ $result == same ]]; then
        rm -f "$tmp"
        return 0
    fi

    if [[ -n $DOCKERD_BIN ]]; then
        if ! "$DOCKERD_BIN" --validate --config-file "$tmp" >/dev/null 2>&1; then
            rm -f "$tmp"
            warn "Новый /etc/docker/daemon.json не прошёл dockerd --validate; Docker не изменён."
            return 1
        fi
    fi

    was_running=$("$DOCKER_BIN" inspect --type container -f '{{.State.Running}}' remnanode 2>/dev/null || true)

    mv "$tmp" "$daemon_json"
    chmod 0644 "$daemon_json"
    LIMIT_CHANGES=$((LIMIT_CHANGES + 1))
    LIMIT_RESTART_NOTICE=1
    info "В Docker daemon.json установлен default nofile=${NOFILE_TARGET}:${NOFILE_TARGET}."

    # Пользовательское требование: после изменения конфигурации Docker
    # обязательно перезапускаем Docker daemon.
    if ! "$SYSTEMCTL_BIN" restart docker.service; then
        warn "Docker не перезапустился после изменения daemon.json; выполняется откат."
        if (( existed )); then
            cp -a "$backup" "$daemon_json"
        else
            rm -f "$daemon_json"
        fi
        "$SYSTEMCTL_BIN" restart docker.service >/dev/null 2>&1 || true
        return 1
    fi

    DOCKER_RESTARTED=$((DOCKER_RESTARTED + 1))
    if ! wait_docker_ready; then
        warn "Docker daemon не стал готов после перезапуска."
        return 1
    fi
    ok "Docker daemon перезапущен после изменения лимитов"

    # Если remnanode работал до рестарта, гарантируем его возврат в running,
    # даже если у контейнера нет автоматической restart policy.
    if [[ $was_running == true ]]; then
        if [[ $("$DOCKER_BIN" inspect --type container -f '{{.State.Running}}' remnanode 2>/dev/null || true) != true ]]; then
            "$DOCKER_BIN" start remnanode >/dev/null 2>&1 || true
        fi
        if ! wait_remnanode_running; then
            warn "remnanode не запустился после перезапуска Docker."
            return 1
        fi
    fi

    return 0
}

if [[ -n $DOCKER_BIN ]] && "$DOCKER_BIN" inspect --type container remnanode >/dev/null 2>&1; then
    WORKLOAD_FOUND=1
    RUNNING=$("$DOCKER_BIN" inspect --type container -f '{{.State.Running}}' remnanode 2>/dev/null || true)
    NOFILE=""

    if [[ $RUNNING != true ]]; then
        warn "remnanode существует, но не запущен; NOFILE не проверяется и автоматически не изменяется."
    else
        NOFILE=$(get_remnanode_nofile)
        echo "remnanode NOFILE soft/hard: ${NOFILE:-неизвестно}"

        if [[ -z $NOFILE || $NOFILE != */* ]]; then
            warn "Не удалось достоверно прочитать NOFILE из работающего remnanode; автоправка пропущена, Docker не перезапускается."
        elif nofile_pair_ok "$NOFILE"; then
            ok "remnanode NOFILE >= ${NOFILE_TARGET}"
        else
            info "remnanode NOFILE ниже ${NOFILE_TARGET}; Nuvrion пытается исправить только точечно."

            COMPOSE_RC=0
            fix_remnanode_nofile_via_compose || COMPOSE_RC=$?

            if (( COMPOSE_RC == 2 )); then
                if [[ ${NUVRION_ALLOW_DOCKER_RESTART:-0} == 1 ]]; then
                    info "Compose-метаданные недоступны; явно разрешён fallback через Docker default-ulimits и restart docker.service."
                    DAEMON_RC=0
                    fix_docker_default_nofile || DAEMON_RC=$?
                    if (( DAEMON_RC != 0 )); then
                        LIMIT_FIX_ERRORS=$((LIMIT_FIX_ERRORS + 1))
                        warn "Docker default-ulimits не удалось применить."
                    fi
                else
                    LIMIT_FIX_ERRORS=$((LIMIT_FIX_ERRORS + 1))
                    warn "Compose-метаданные недоступны. Глобальный restart Docker не выполняется без NUVRION_ALLOW_DOCKER_RESTART=1."
                fi
            elif (( COMPOSE_RC != 0 )); then
                LIMIT_FIX_ERRORS=$((LIMIT_FIX_ERRORS + 1))
                warn "Точечное исправление NOFILE через Docker Compose завершилось ошибкой; restart всего Docker не выполняется автоматически."
            fi

            NOFILE_AFTER=$(get_remnanode_nofile)
            echo "remnanode NOFILE после попытки исправления: ${NOFILE_AFTER:-неизвестно}"
            if [[ -n $NOFILE_AFTER && $NOFILE_AFTER == */* ]] && nofile_pair_ok "$NOFILE_AFTER"; then
                ok "remnanode NOFILE успешно установлен >= ${NOFILE_TARGET}"
            else
                warn "remnanode NOFILE не подтверждён на уровне ${NOFILE_TARGET}; см. сообщения выше."
            fi
        fi
    fi
fi

# ============================================================
# Проверка network namespace Docker
# ============================================================

if [[ -n $DOCKER_BIN ]] && "$DOCKER_BIN" inspect --type container remnanode >/dev/null 2>&1; then
    NETWORK_MODE=$("$DOCKER_BIN" inspect --type container -f '{{.HostConfig.NetworkMode}}' remnanode 2>/dev/null || echo unknown)
    echo "Сетевой режим remnanode: ${NETWORK_MODE}"

    if [[ $NETWORK_MODE == host ]]; then
        ok "remnanode использует network namespace хоста"
    else
        warn "remnanode не использует host networking; sysctl хоста могут не действовать внутри его network namespace."
    fi

    CONTAINER_KEYS=(
        net.core.rmem_max
        net.core.wmem_max
        net.core.somaxconn
        net.ipv4.tcp_congestion_control
        net.ipv4.tcp_rmem
        net.ipv4.tcp_wmem
        net.ipv4.tcp_max_syn_backlog
        net.ipv4.tcp_syncookies
        net.ipv4.tcp_slow_start_after_idle
        net.ipv4.tcp_mtu_probing
        net.ipv4.ip_local_port_range
        net.ipv4.udp_rmem_min
        net.ipv4.udp_wmem_min
    )

    if (( MANAGE_RESERVED )); then
        CONTAINER_KEYS+=(net.ipv4.ip_local_reserved_ports)
    fi

    NETNS_MISMATCH=0
    for key in "${CONTAINER_KEYS[@]}"; do
        path="/proc/sys/${key//./\/}"
        cval=$("$DOCKER_BIN" exec remnanode cat "$path" 2>/dev/null || true)
        [[ -z $cval ]] && continue
        cval=$(normalize_ws "$cval")

        if [[ -n ${DESIRED[$key]+x} ]]; then
            expected=$(normalize_ws "${DESIRED[$key]}")
        else
            expected=$(normalize_ws "$(sysctl -n "$key" 2>/dev/null || true)")
        fi

        if [[ -n $expected && $cval != "$expected" ]]; then
            printf '%s%s[ ОШИБКА ]%s remnanode netns %-26s нужно=%s фактически=%s\n' "$C_BOLD" "$C_RED" "$C_RESET" "$key" "$expected" "$cval"
            NETNS_MISMATCH=$((NETNS_MISMATCH + 1))
        fi
    done

    if (( NETNS_MISMATCH > 0 )); then
        conflict "В network namespace remnanode отличаются ${NETNS_MISMATCH} настроенных параметров; используйте network_mode: host или задайте эквивалентные sysctl контейнера."
    else
        ok "remnanode видит критические сетевые параметры профиля"
    fi
fi

if [[ -n $SYSTEMCTL_BIN && -d /run/systemd/system ]]; then
    SYSTEMD_DROPINS_CHANGED=0
    CHANGED_SYSTEMD_SERVICES=()

    for svc in xray.service remnanode.service; do
        if "$SYSTEMCTL_BIN" cat "$svc" >/dev/null 2>&1; then
            WORKLOAD_FOUND=1
            LIMIT=$("$SYSTEMCTL_BIN" show "$svc" -p LimitNOFILE --value 2>/dev/null || echo 0)
            echo "$svc LimitNOFILE: $LIMIT"

            if [[ $LIMIT == infinity || $LIMIT == unlimited ]]; then
                ok "$svc NOFILE без ограничения"
            elif [[ $LIMIT =~ ^[0-9]+$ ]] && (( LIMIT >= NOFILE_TARGET )); then
                ok "$svc NOFILE >= ${NOFILE_TARGET}"
            else
                dropin_dir="/etc/systemd/system/${svc}.d"
                dropin="${dropin_dir}/90-nuvrion-nofile.conf"
                mkdir -p "$dropin_dir"

                if [[ -f $dropin ]]; then
                    cp -a "$dropin" "$BACKUP_DIR/$(basename "$svc")-90-nuvrion-nofile.conf.${RUN_ID}"
                fi

                cat >"$dropin" <<EOF
[Service]
LimitNOFILE=${NOFILE_TARGET}
EOF
                chmod 0644 "$dropin"
                SYSTEMD_DROPINS_CHANGED=$((SYSTEMD_DROPINS_CHANGED + 1))
                CHANGED_SYSTEMD_SERVICES+=("$svc")
                LIMIT_CHANGES=$((LIMIT_CHANGES + 1))
                LIMIT_RESTART_NOTICE=1
                info "$svc: создан отдельный drop-in LimitNOFILE=${NOFILE_TARGET}"
            fi
        fi
    done

    if (( SYSTEMD_DROPINS_CHANGED > 0 )); then
        "$SYSTEMCTL_BIN" daemon-reload

        for svc in "${CHANGED_SYSTEMD_SERVICES[@]}"; do
            if "$SYSTEMCTL_BIN" is-active --quiet "$svc"; then
                info "$svc: для применения нового NOFILE сервис будет перезапущен."
                if "$SYSTEMCTL_BIN" restart "$svc"; then
                    SYSTEMD_SERVICES_RESTARTED=$((SYSTEMD_SERVICES_RESTARTED + 1))
                    ok "$svc перезапущен после изменения лимита"
                else
                    LIMIT_FIX_ERRORS=$((LIMIT_FIX_ERRORS + 1))
                    conflict "Не удалось перезапустить $svc после изменения LimitNOFILE."
                fi
            else
                info "$svc сейчас не запущен; новый LimitNOFILE применится при следующем старте."
            fi

            LIMIT=$("$SYSTEMCTL_BIN" show "$svc" -p LimitNOFILE --value 2>/dev/null || echo 0)
            if [[ $LIMIT == infinity || $LIMIT == unlimited ]] || { [[ $LIMIT =~ ^[0-9]+$ ]] && (( LIMIT >= NOFILE_TARGET )); }; then
                ok "$svc LimitNOFILE после исправления: $LIMIT"
            else
                LIMIT_FIX_ERRORS=$((LIMIT_FIX_ERRORS + 1))
                conflict "$svc LimitNOFILE после исправления остаётся ниже ${NOFILE_TARGET}: $LIMIT"
            fi
        done
    fi
fi

if (( WORKLOAD_FOUND == 0 )); then
    info "remnanode/Xray не обнаружены; потолок ядра настроен, per-service NOFILE менять не требуется."
fi

# ============================================================
# Безопасность публичной ноды
# ============================================================
# Добавление/генерация SSH-ключей здесь намеренно отсутствует. Это отдельная
# административная операция. SSH hardening может быть включён только явно и
# только если подходящий authorized_keys уже существует.

section "БЕЗОПАСНОСТЬ СЕРВЕРА"

FAIL2BAN_STATUS="не проверен"
UPDATES_STATUS="не проверены"
FIREWALL_STATUS="не проверен"
PANEL_FIREWALL_STATUS="не определена"
FIREWALL_CHANGED=0
SSH_SECURITY_STATUS="не проверен"
PUBLIC_DANGEROUS_PORTS=""
SECURITY_FILES_STATUS="не проверены"
APT_CACHE_UPDATED=0

# ------------------------------------------------------------
# Вспомогательные функции пакетов
# ------------------------------------------------------------
package_installed() {
    local pkg=$1
    [[ -n $DPKG_QUERY_BIN ]] || return 1
    # Шаблон раскрывается dpkg-query, а не Bash.
    # shellcheck disable=SC2016
    "$DPKG_QUERY_BIN" -W -f='${Status}' "$pkg" 2>/dev/null | grep -q '^install ok installed$'
}

ensure_apt_cache() {
    (( APT_CACHE_UPDATED == 0 )) || return 0
    [[ -n $APT_GET_BIN ]] || return 1
    info "Обновляется индекс APT для установки недостающих компонентов безопасности..."
    if DEBIAN_FRONTEND=noninteractive "$APT_GET_BIN" update -qq; then
        APT_CACHE_UPDATED=1
        return 0
    fi
    warn "Не удалось обновить индекс APT; автоматическая установка пакетов безопасности может быть пропущена."
    return 1
}

ensure_package() {
    local pkg=$1
    if package_installed "$pkg"; then
        return 0
    fi
    if [[ $INSTALL_SECURITY_PACKAGES != 1 ]]; then
        info "Пакет $pkg не установлен; автодобавление отключено NUVRION_INSTALL_SECURITY_PACKAGES=0."
        return 1
    fi
    [[ -n $APT_GET_BIN ]] || {
        info "apt-get недоступен; пакет $pkg автоматически не устанавливается."
        return 1
    }
    ensure_apt_cache || return 1
    info "Устанавливается пакет безопасности: $pkg"
    if DEBIAN_FRONTEND=noninteractive "$APT_GET_BIN" install -y -qq --no-install-recommends "$pkg"; then
        ok "Пакет $pkg установлен"
        return 0
    fi
    warn "Не удалось установить пакет $pkg."
    return 1
}

# ------------------------------------------------------------
# SSH: только аудит; ключи не создаём и не добавляем
# ------------------------------------------------------------
get_sshd_ports() {
    local -a ports=()
    local p
    # Сохраняем порт текущего сеанса при socket activation и нестандартном SSH.
    if [[ ${SSH_CONNECTION:-} =~ [[:space:]]([0-9]+)$ ]]; then
        ports+=("${BASH_REMATCH[1]}")
    fi

    if [[ -n $SSHD_BIN ]]; then
        while IFS= read -r p; do
            [[ $p =~ ^[0-9]+$ ]] && ports+=("$p")
        done < <("$SSHD_BIN" -T 2>/dev/null | awk '$1=="port" {print $2}' || true)
    fi

    if [[ -n $SS_BIN ]]; then
        while IFS= read -r p; do
            [[ $p =~ ^[0-9]+$ ]] && ports+=("$p")
        done < <(
            "$SS_BIN" -H -ltnp 2>/dev/null |
            awk '/users:\(\("sshd"/ {
                a=$4; sub(/^.*:/,"",a); if (a ~ /^[0-9]+$/) print a
            }' || true
        )
    fi

    if ((${#ports[@]} == 0)); then
        ports=(22)
    fi
    printf '%s\n' "${ports[@]}" | sort -n -u
}

mapfile -t SSH_PORTS < <(get_sshd_ports)
SSH_PORT_CSV=$(IFS=,; echo "${SSH_PORTS[*]}")

if [[ -n $SSHD_BIN ]]; then
    SSHD_EFFECTIVE=$("$SSHD_BIN" -T 2>/dev/null || true)
    SSH_PASSWORD=$(awk '$1=="passwordauthentication" {print $2; exit}' <<<"$SSHD_EFFECTIVE")
    SSH_ROOT=$(awk '$1=="permitrootlogin" {print $2; exit}' <<<"$SSHD_EFFECTIVE")
    SSH_PUBKEY=$(awk '$1=="pubkeyauthentication" {print $2; exit}' <<<"$SSHD_EFFECTIVE")

    if [[ $SSH_PASSWORD == no && $SSH_PUBKEY == yes && ( $SSH_ROOT == prohibit-password || $SSH_ROOT == forced-commands-only || $SSH_ROOT == no ) ]]; then
        SSH_SECURITY_STATUS="key-only уже настроен"
        ok "SSH уже использует безопасный key-only режим"
    else
        SSH_SECURITY_STATUS="аудит: password=${SSH_PASSWORD:-?}, root=${SSH_ROOT:-?}, pubkey=${SSH_PUBKEY:-?}"
        info "SSH-аутентификация не изменяется автоматически. Текущее: PasswordAuthentication=${SSH_PASSWORD:-?}, PermitRootLogin=${SSH_ROOT:-?}, PubkeyAuthentication=${SSH_PUBKEY:-?}."

        if [[ ${NUVRION_HARDEN_SSH:-0} == 1 ]]; then
            SSH_DROPIN=/etc/ssh/sshd_config.d/99-nuvrion-hardening.conf
            ROOT_KEYS=/root/.ssh/authorized_keys
            SSH_DROPIN_BACKUP=""
            if [[ ! -s $ROOT_KEYS ]]; then
                warn "NUVRION_HARDEN_SSH=1, но /root/.ssh/authorized_keys пуст или отсутствует; SSH hardening пропущен во избежание потери доступа."
            else
                mkdir -p /etc/ssh/sshd_config.d
                if [[ -f $SSH_DROPIN ]]; then
                    SSH_DROPIN_BACKUP="$BACKUP_DIR/99-nuvrion-hardening.conf.${RUN_ID}"
                    cp -a "$SSH_DROPIN" "$SSH_DROPIN_BACKUP"
                fi
                cat >"$SSH_DROPIN" <<'EOFSSH'
# Nuvrion — безопасная SSH-аутентификация. Ключи этим скриптом не создаются.
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitEmptyPasswords no
PermitRootLogin prohibit-password
EOFSSH
                chmod 0644 "$SSH_DROPIN"
                if "$SSHD_BIN" -t >/dev/null 2>&1; then
                    if [[ -n $SYSTEMCTL_BIN && -d /run/systemd/system ]]; then
                        if "$SYSTEMCTL_BIN" reload ssh.service >/dev/null 2>&1 || "$SYSTEMCTL_BIN" reload sshd.service >/dev/null 2>&1; then
                            SSH_SECURITY_STATUS="key-only включён"
                            ok "SSH hardening применён через drop-in; SSH-сервис перечитан без restart"
                        else
                            warn "SSH-конфигурация валидна, но reload сервиса не удался; изменения вступят в силу при следующем reload/restart."
                        fi
                    else
                        SSH_SECURITY_STATUS="key-only записан, reload не выполнен"
                        info "SSH drop-in создан; systemd недоступен, автоматический reload не выполнен."
                    fi
                else
                    if [[ -n $SSH_DROPIN_BACKUP && -f $SSH_DROPIN_BACKUP ]]; then
                        cp -a "$SSH_DROPIN_BACKUP" "$SSH_DROPIN"
                    else
                        rm -f "$SSH_DROPIN"
                    fi
                    warn "Новый SSH drop-in не прошёл sshd -t; предыдущая конфигурация восстановлена."
                fi
            fi
        else
            info "Nuvrion не добавляет SSH-ключи. Для отдельного включения key-only после подготовки ключа используйте NUVRION_HARDEN_SSH=1."
        fi
    fi
else
    SSH_SECURITY_STATUS="sshd не обнаружен"
    info "sshd не обнаружен; SSH hardening не требуется."
fi

# ------------------------------------------------------------
# Fail2ban для SSH
# ------------------------------------------------------------
if [[ $SECURITY_ENABLED == 1 && -n $SSHD_BIN ]]; then
    if [[ -z $FAIL2BAN_CLIENT_BIN ]]; then
        ensure_package fail2ban || true
        FAIL2BAN_CLIENT_BIN=$(command -v fail2ban-client || true)
    fi

    if [[ -n $FAIL2BAN_CLIENT_BIN ]]; then
        # Сначала пытаемся использовать уже существующую конфигурацию пользователя.
        if "$FAIL2BAN_CLIENT_BIN" -t >/dev/null 2>&1; then
            if [[ -n $SYSTEMCTL_BIN && -d /run/systemd/system ]]; then
                "$SYSTEMCTL_BIN" enable --now fail2ban.service >/dev/null 2>&1 || true
            fi
        fi

        if "$FAIL2BAN_CLIENT_BIN" status sshd >/dev/null 2>&1; then
            FAIL2BAN_STATUS="sshd уже защищён"
            ok "Fail2ban: существующий jail sshd активен; настройки пользователя не изменяются"
        else
            F2B_CONF=/etc/fail2ban/jail.d/99-nuvrion-sshd.conf
            F2B_BACKUP=""
            mkdir -p /etc/fail2ban/jail.d
            if [[ -f $F2B_CONF ]]; then
                F2B_BACKUP="$BACKUP_DIR/99-nuvrion-sshd.conf.${RUN_ID}"
                cp -a "$F2B_CONF" "$F2B_BACKUP"
            fi
            cat >"$F2B_CONF" <<EOF
# Nuvrion — защита SSH
[sshd]
enabled = true
port = ${SSH_PORT_CSV:-22}
maxretry = 5
findtime = 600
bantime = 86400
EOF
            chmod 0644 "$F2B_CONF"

            if "$FAIL2BAN_CLIENT_BIN" -t >/dev/null 2>&1; then
                if [[ -n $SYSTEMCTL_BIN && -d /run/systemd/system ]] && "$SYSTEMCTL_BIN" enable --now fail2ban.service >/dev/null 2>&1; then
                    "$SYSTEMCTL_BIN" restart fail2ban.service >/dev/null 2>&1 || true
                    sleep 1
                fi
                if "$FAIL2BAN_CLIENT_BIN" status sshd >/dev/null 2>&1; then
                    FAIL2BAN_STATUS="sshd: 5 попыток / 10 мин / бан 24 ч"
                    ok "Fail2ban настроен для SSH: maxretry=5, findtime=10 мин, bantime=24 ч"
                else
                    FAIL2BAN_STATUS="конфигурация есть, jail не подтверждён"
                    warn "Конфигурация Fail2ban валидна, но активный jail sshd не подтверждён."
                fi
            else
                if [[ -n $F2B_BACKUP && -f $F2B_BACKUP ]]; then
                    cp -a "$F2B_BACKUP" "$F2B_CONF"
                else
                    rm -f "$F2B_CONF"
                fi
                FAIL2BAN_STATUS="ошибка конфигурации"
                warn "Fail2ban не принял конфигурацию Nuvrion; предыдущая конфигурация восстановлена."
            fi
        fi
    else
        FAIL2BAN_STATUS="не установлен"
        warn "Fail2ban недоступен; SSH brute-force защита не настроена."
    fi
elif [[ $SECURITY_ENABLED != 1 ]]; then
    FAIL2BAN_STATUS="отключено NUVRION_SECURITY=0"
else
    FAIL2BAN_STATUS="sshd не обнаружен"
    info "sshd не обнаружен; Fail2ban для SSH не устанавливается."
fi

# ------------------------------------------------------------
# Автоматические security updates без автоматического reboot
# ------------------------------------------------------------
if [[ $SECURITY_ENABLED == 1 ]]; then
    if ! package_installed unattended-upgrades; then
        ensure_package unattended-upgrades || true
    fi

    if package_installed unattended-upgrades; then
        if apt-config dump | grep -E '^APT::Periodic::Unattended-Upgrade[[:space:]]+"1"' >/dev/null; then
            UPDATES_STATUS="уже включены"
            ok "Автоматические обновления безопасности уже включены; существующая конфигурация не изменяется"
            if grep -RqsE '^[[:space:]]*Unattended-Upgrade::Automatic-Reboot[[:space:]]+"true"' /etc/apt/apt.conf.d 2>/dev/null; then
                warn "В существующей конфигурации unattended-upgrades включена автоматическая перезагрузка; Nuvrion её не меняет автоматически."
                UPDATES_STATUS="включены, autoreboot=true (внешняя настройка)"
            fi
        else
            UA_CONF=/etc/apt/apt.conf.d/52nuvrion-unattended-upgrades
            cat >"$UA_CONF" <<'EOFUA'
// Nuvrion — автоматическая установка security updates без автоперезагрузки.
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
Unattended-Upgrade::Automatic-Reboot "false";
EOFUA
            chmod 0644 "$UA_CONF"
            UPDATES_STATUS="включены Nuvrion, autoreboot=off"
            ok "Автоматические обновления безопасности включены; автоматическая перезагрузка отключена"
        fi

        if [[ -n $SYSTEMCTL_BIN && -d /run/systemd/system ]]; then
            "$SYSTEMCTL_BIN" enable --now apt-daily.timer apt-daily-upgrade.timer >/dev/null 2>&1 || true
        fi
    else
        UPDATES_STATUS="unattended-upgrades недоступен"
        warn "unattended-upgrades не установлен; автоматические обновления безопасности не настроены."
    fi
else
    UPDATES_STATUS="отключены NUVRION_SECURITY=0"
fi

# ------------------------------------------------------------
# Firewall — автоматическое определение панели без списков портов
# ------------------------------------------------------------
# v1.0.0 не предполагает, что API Remnawave всегда слушает 2222, и не перебирает
# заранее заданный список портов. Идентификатор панели строится из фактических
# данных: env -> ранее подтверждённое состояние -> source-specific firewall
# rule -> listener процесса rw-node/remnanode -> ручной ввод.
#
# Если порт уже защищён правилом для конкретного IP, интерактивный запуск всегда
# просит подтвердить и порт, и IP. После подтверждения IP нельзя молча оставить
# пустым: нужно ввести корректный адрес либо явно выбрать "Пропустить".

normalize_ip_list() {
    local raw=${1:-} token out="" ip prefix
    raw=${raw//,/ }

    if [[ -n $PYTHON3_BIN ]]; then
        "$PYTHON3_BIN" - "$raw" <<'PYIP'
import ipaddress, sys
raw = sys.argv[1]
seen = set()
for token in raw.split():
    try:
        if "/" in token:
            value = str(ipaddress.ip_network(token, strict=False))
        else:
            value = str(ipaddress.ip_address(token))
    except ValueError:
        continue
    if value not in seen:
        seen.add(value)
        print(value)
PYIP
        return 0
    fi

    for token in $raw; do
        ip=${token%%/*}
        prefix=""
        [[ $token == */* ]] && prefix=${token##*/}
        if awk -v ip="$ip" -v prefix="$prefix" 'BEGIN {
            n=split(ip,a,".")
            if (n != 4) exit 1
            for (i=1;i<=4;i++) {
                if (a[i] !~ /^[0-9]+$/ || a[i] < 0 || a[i] > 255) exit 1
            }
            if (prefix != "" && (prefix !~ /^[0-9]+$/ || prefix < 0 || prefix > 32)) exit 1
            exit 0
        }'; then
            [[ -n $out ]] && out+=$'\n'
            out+="$token"
        fi
    done
    printf '%s\n' "$out"
    return 0
}

valid_tcp_port() {
    local p=${1:-}
    [[ $p =~ ^[0-9]{1,5}$ ]] || return 1
    p=$((10#$p))
    (( p >= 1 && p <= 65535 ))
}

public_tcp_port_listening() {
    local port=${1:-}
    [[ -n $SS_BIN ]] || return 1
    valid_tcp_port "$port" || return 1
    "$SS_BIN" -H -ltn 2>/dev/null | awk -v port="$port" '
        {
            a=$4; p=a; sub(/^.*:/,"",p)
            if (p != port) next
            if (a ~ /^127\./ || a ~ /^\[?::1\]?:/) next
            found=1
        }
        END { exit(found ? 0 : 1) }
    '
}

collect_rw_node_listener_ports() {
    [[ -n $SS_BIN ]] || return 0
    "$SS_BIN" -H -ltnp 2>/dev/null | awk '
        /users:\(\("(rw-node|remnanode)"/ {
            a=$4; p=a; sub(/^.*:/,"",p)
            if (p ~ /^[0-9]+$/) print (p+0)
        }
    ' | sort -n -u
    return 0
}

# UFW: source-specific ALLOW. Формат результата: PORT<TAB>IP/CIDR<TAB>ufw
collect_ufw_panel_candidates() {
    [[ -n $UFW_BIN ]] || return 0
    "$UFW_BIN" status 2>/dev/null | awk '
        {
            target=$1
            if (target !~ /^[0-9]+\/tcp$/) next
            split(target,a,"/"); port=a[1]
            if ($2=="ALLOW" && $3!="Anywhere" && $3!="Anywhere (v6)")
                print port "\t" $3 "\tufw"
            else if ($2=="(v6)" && $3=="ALLOW" && $4!="Anywhere" && $4!="Anywhere (v6)")
                print port "\t" $4 "\tufw"
        }
    ' || true
    return 0
}

# nftables: извлекает source-specific accept, включая ip saddr @set и
# tcp dport { p1, p2 }. Не делает вывод, что правило действительно panel API —
# это подтверждает пользователь.
collect_nft_panel_candidates() {
    [[ -n $NFT_BIN ]] || return 0
    local rules
    rules=$($NFT_BIN -nn list ruleset 2>/dev/null || true)
    [[ -n $rules ]] || return 0

    if [[ -n $PYTHON3_BIN ]]; then
        "$PYTHON3_BIN" - 3<<<"$rules" <<'PYNFT'
import re, sys, ipaddress, os
text=os.fdopen(3).read()
lines=text.splitlines()
sets={}
cur=None
buf=[]
depth=0
for line in lines:
    m=re.search(r'\bset\s+([A-Za-z0-9_.:-]+)\s*\{', line)
    if cur is None and m:
        cur=m.group(1); buf=[line]
        depth=line.count('{')-line.count('}')
        if depth<=0:
            body='\n'.join(buf)
            em=re.search(r'elements\s*=\s*\{([^}]*)\}',body,re.S)
            if em: sets[cur]=[x.strip() for x in em.group(1).split(',') if x.strip()]
            cur=None; buf=[]
        continue
    if cur is not None:
        buf.append(line); depth += line.count('{')-line.count('}')
        if depth<=0:
            body='\n'.join(buf)
            em=re.search(r'elements\s*=\s*\{([^}]*)\}',body,re.S)
            if em: sets[cur]=[x.strip() for x in em.group(1).split(',') if x.strip()]
            cur=None; buf=[]

def ports_from_rule(line):
    m=re.search(r'\btcp\s+dport\s+(.+?)(?:\s+(?:ip6?|ct|meta|counter|accept|drop|reject|jump|goto|comment|limit)\b|$)', line)
    if not m: return []
    s=m.group(1).replace('{',' ').replace('}',' ').replace(',',' ')
    return [int(x) for x in re.findall(r'(?<![0-9])([0-9]{1,5})(?![0-9])',s) if 1<=int(x)<=65535]

def normalize_addr(x):
    x=x.strip().strip(',')
    try:
        return str(ipaddress.ip_network(x,strict=False) if '/' in x else ipaddress.ip_address(x))
    except Exception:
        return None

seen=set()
for line in lines:
    if 'accept' not in line or not re.search(r'\btcp\s+dport\b',line):
        continue
    ports=ports_from_rule(line)
    if not ports: continue
    ips=[]
    for fam in ('ip','ip6'):
        m=re.search(r'\b'+fam+r'\s+saddr\s+(@[A-Za-z0-9_.:-]+|[^\s{};,]+)',line)
        if not m: continue
        val=m.group(1)
        if val.startswith('@'):
            for e in sets.get(val[1:],[]):
                n=normalize_addr(e)
                if n: ips.append(n)
        else:
            n=normalize_addr(val)
            if n: ips.append(n)
    for p in ports:
        for ip in ips:
            key=(p,ip)
            if key not in seen:
                seen.add(key)
                print(f"{p}\t{ip}\tnftables")
PYNFT
        return 0
    fi

    # Fallback без python3 — только прямой ip saddr ADDRESS в одной строке.
    awk '
        /tcp[[:space:]]+dport/ && /accept/ && /(ip|ip6)[[:space:]]+saddr/ {
            line=$0
            gsub(/[{},]/," ",line)
            n=split(line,f,/[	 ]+/)
            port=""; src=""
            for(i=1;i<=n;i++) {
                if(f[i]=="tcp" && f[i+1]=="dport" && f[i+2]~/^[0-9]+$/) port=f[i+2]
                if((f[i]=="ip"||f[i]=="ip6") && f[i+1]=="saddr" && f[i+2]!~/^@/) src=f[i+2]
            }
            if(port!="" && src!="") print port "\t" src "\tnftables"
        }
    ' <<<"$rules" || true
    return 0
}

collect_firewall_panel_candidates() {
    {
        collect_ufw_panel_candidates
        collect_nft_panel_candidates
    } | awk -F'\t' 'NF>=3 {key=$1 FS $2; if(!seen[key]++) print $1 FS $2 FS $3}'
    return 0
}

get_saved_panel_port() {
    [[ -s $PANEL_PORT_FILE ]] || return 0
    awk 'NR==1 {gsub(/[^0-9]/,""); if($0~/^[0-9]+$/) print $0}' "$PANEL_PORT_FILE" 2>/dev/null || true
    return 0
}

get_saved_panel_ips() {
    [[ -s $PANEL_IP_FILE ]] || return 0
    awk '{sub(/#.*/,""); gsub(/^[[:space:]]+|[[:space:]]+$/,""); if(length) print}' "$PANEL_IP_FILE" 2>/dev/null || true
    return 0
}

save_panel_identity() {
    [[ -n ${PANEL_PORT:-} && -n ${PANEL_IPS_NORMALIZED:-} ]] || return 1
    mkdir -p /etc/nuvrion-tuning
    printf '%s\n' "$PANEL_PORT" >"$PANEL_PORT_FILE"
    {
        echo '# Nuvrion — подтверждённые IP/CIDR панели Remnawave'
        printf '%s\n' "$PANEL_IPS_NORMALIZED"
    } >"$PANEL_IP_FILE"
    chmod 0600 "$PANEL_PORT_FILE" "$PANEL_IP_FILE"
    return 0
}

prompt_panel_ips_required() {
    local suggested=${1:-} normalized="" raw="" rc=0

    if [[ -n $suggested ]]; then
        normalized=$(normalize_ip_list "$suggested" | awk 'NF' || true)
        if [[ -n $normalized ]]; then
            printf '\nОбнаруженный IP/CIDR панели:\n%s\n' "$normalized"
            if prompt_choice_yes_no_skip "Подтвердите этот IP/CIDR панели?"; then
                PANEL_IPS_NORMALIZED=$normalized
                return 0
            else
                rc=$?
                if (( rc == 2 || rc == 3 )); then
                    PANEL_SETUP_SKIPPED=1
                    PANEL_FIREWALL_STATUS="настройка панели пропущена"
                    return 2
                fi
            fi
        fi
    fi

    [[ -t 0 ]] || {
        warn "IP панели не подтверждён, а stdin не интерактивен; настройка firewall для панели пропущена. Используйте NUVRION_PANEL_IPS."
        PANEL_SETUP_SKIPPED=1
        PANEL_FIREWALL_STATUS="IP панели не задан (неинтерактивный запуск)"
        return 2
    }

    choice_hint_skip
    while true; do
        printf '%s%sВведите IP/CIDR панели (несколько — через запятую): %s' "$C_BOLD" "$C_YELLOW" "$C_RESET"
        IFS= read -r raw || { PANEL_SETUP_SKIPPED=1; return 2; }
        case "$raw" in
            п|П|пропустить|ПРОПУСТИТЬ|Пропустить|s|S|skip|SKIP|Skip)
                PANEL_SETUP_SKIPPED=1
                PANEL_FIREWALL_STATUS="настройка панели пропущена"
                return 2
                ;;
        esac
        if [[ -z ${raw//[[:space:]]/} ]]; then
            warn "IP панели нужно подтвердить. Введите корректный IP/CIDR либо П для явного пропуска всей настройки панели."
            continue
        fi
        normalized=$(normalize_ip_list "$raw" | awk 'NF' || true)
        if [[ -z $normalized ]]; then
            warn "Не удалось распознать IP/CIDR. Повторите ввод."
            continue
        fi
        PANEL_IPS_NORMALIZED=$normalized
        return 0
    done
}

prompt_manual_panel_port() {
    local suggestion=${1:-} raw="" p="" rc=0
    [[ -t 0 ]] || {
        PANEL_SETUP_SKIPPED=1
        PANEL_FIREWALL_STATUS="порт панели не определён (неинтерактивный запуск)"
        warn "Автоматически подтвердить порт панели без интерактивного ввода нельзя. Используйте NUVRION_PANEL_PORT и NUVRION_PANEL_IPS."
        return 2
    }

    choice_hint_skip
    while true; do
        if [[ -n $suggestion ]]; then
            printf '%s%sВведите порт панели [%s]: %s' "$C_BOLD" "$C_YELLOW" "$suggestion" "$C_RESET"
        else
            printf '%s%sВведите порт панели (1-65535): %s' "$C_BOLD" "$C_YELLOW" "$C_RESET"
        fi
        IFS= read -r raw || { PANEL_SETUP_SKIPPED=1; return 2; }
        case "$raw" in
            п|П|пропустить|ПРОПУСТИТЬ|Пропустить|s|S|skip|SKIP|Skip)
                PANEL_SETUP_SKIPPED=1
                PANEL_FIREWALL_STATUS="настройка панели пропущена"
                return 2
                ;;
        esac
        [[ -z ${raw//[[:space:]]/} && -n $suggestion ]] && raw=$suggestion
        [[ -z ${raw//[[:space:]]/} ]] && {
            PANEL_SETUP_SKIPPED=1
            PANEL_FIREWALL_STATUS="настройка панели пропущена"
            return 2
        }
        if ! valid_tcp_port "$raw"; then
            warn "Порт должен быть числом от 1 до 65535."
            continue
        fi
        p=$((10#$raw))
        if ! public_tcp_port_listening "$p"; then
            if prompt_choice_yes_no_skip "Порт ${p}/tcp сейчас не слушается публично. Всё равно считать его портом панели?"; then
                :
            else
                rc=$?
                if (( rc == 2 || rc == 3 )); then
                    PANEL_SETUP_SKIPPED=1
                    PANEL_FIREWALL_STATUS="настройка панели пропущена"
                    return 2
                fi
                continue
            fi
        fi
        PANEL_PORT=$p
        PANEL_IDENTITY_SOURCE="ручной ввод"
        return 0
    done
}

# Группирует source-specific firewall candidates по порту.
# Формат: PORT<TAB>ip1,ip2<TAB>source1,source2
collect_grouped_firewall_candidates() {
    collect_firewall_panel_candidates | awk -F'\t' '
        NF>=3 {
            p=$1; ip=$2; src=$3
            if (!(p SUBSEP ip in seenip)) {
                seenip[p SUBSEP ip]=1
                ips[p]=(ips[p]==""?ip:ips[p]","ip)
            }
            if (!(p SUBSEP src in seensrc)) {
                seensrc[p SUBSEP src]=1
                srcs[p]=(srcs[p]==""?src:srcs[p]","src)
            }
            if (!(p in order)) { order[p]=++n; plist[n]=p }
        }
        END { for(i=1;i<=n;i++){p=plist[i]; print p "\t" ips[p] "\t" srcs[p]} }
    '
    return 0
}

resolve_panel_identity() {
    local saved_port="" saved_ips="" normalized="" row="" port="" ips="" src="" rc=0
    local -a rw_ports=() preferred=() other=()
    PANEL_IPS_NORMALIZED=""

    # 1) Явные env-параметры считаются осознанным административным выбором.
    if [[ -n $PANEL_PORT_ENV ]]; then
        PANEL_PORT=$PANEL_PORT_ENV
        PANEL_IDENTITY_SOURCE="NUVRION_PANEL_PORT"
        if [[ -n ${NUVRION_PANEL_IPS:-} ]]; then
            normalized=$(normalize_ip_list "$NUVRION_PANEL_IPS" | awk 'NF' || true)
            if [[ -n $normalized ]]; then
                PANEL_IPS_NORMALIZED=$normalized
                save_panel_identity
                ok "Порт панели задан явно: ${PANEL_PORT}/tcp; IP панели подтверждён через env"
                return 0
            fi
            warn "NUVRION_PANEL_IPS задан, но не содержит корректного IP/CIDR."
        fi
        saved_ips=$(get_saved_panel_ips)
        prompt_panel_ips_required "$saved_ips" || return $?
        save_panel_identity
        ok "Порт панели задан явно: ${PANEL_PORT}/tcp; IP панели подтверждён"
        return 0
    fi

    # 2) Повторный запуск использует ранее подтверждённую пару порт+IP без вопросов.
    saved_port=$(get_saved_panel_port)
    saved_ips=$(get_saved_panel_ips)
    if valid_tcp_port "$saved_port" && [[ -n $saved_ips ]]; then
        normalized=$(normalize_ip_list "$saved_ips" | awk 'NF' || true)
        if [[ -n $normalized ]]; then
            PANEL_PORT=$((10#$saved_port))
            PANEL_IPS_NORMALIZED=$normalized
            PANEL_IDENTITY_SOURCE="ранее подтверждено"
            ok "Используется ранее подтверждённая панель: ${PANEL_PORT}/tcp"
            return 0
        fi
    fi

    # 3) Сильные кандидаты: source-specific firewall rule. Сначала те, чей порт
    # реально принадлежит rw-node/remnanode, затем остальные не-SSH listeners.
    mapfile -t rw_ports < <(collect_rw_node_listener_ports)
    while IFS=$'\t' read -r port ips src; do
        [[ -n $port ]] || continue
        valid_tcp_port "$port" || continue
        local is_rw=0 sp
        for sp in "${rw_ports[@]}"; do [[ $sp == "$port" ]] && is_rw=1; done
        for sp in "${SSH_PORTS[@]}"; do [[ $sp == "$port" ]] && is_rw=-1; done
        (( is_rw < 0 )) && continue
        row="${port}"$'\t'"${ips}"$'\t'"${src}"
        if (( is_rw == 1 )); then preferred+=("$row"); else other+=("$row"); fi
    done < <(collect_grouped_firewall_candidates)

    for row in "${preferred[@]}" "${other[@]}"; do
        [[ -n $row ]] || continue
        IFS=$'\t' read -r port ips src <<<"$row"
        public_tcp_port_listening "$port" || continue
        printf '\n%s%s[ НАЙДЕНО ]%s Вероятный порт панели: %s/tcp\n' "$C_BOLD" "$C_MAGENTA" "$C_RESET" "$port"
        printf '  Правило firewall: %s\n' "$src"
        printf '  Разрешённый источник: %s\n' "$ips"
        if prompt_choice_yes_no_skip "Подтвердите, что ${port}/tcp — порт панели?"; then
            PANEL_PORT=$((10#$port))
            PANEL_IDENTITY_SOURCE="firewall: ${src}"
            if prompt_panel_ips_required "$ips"; then
                save_panel_identity
                ok "Порт и IP панели подтверждены: ${PANEL_PORT}/tcp"
                return 0
            else
                return $?
            fi
        else
            rc=$?
            if (( rc == 2 || rc == 3 )); then
                PANEL_SETUP_SKIPPED=1
                PANEL_FIREWALL_STATUS="настройка панели пропущена"
                info "Настройка панели пропущена пользователем; переход к следующему этапу."
                return 2
            fi
        fi
    done

    # 4) Если source-specific правила нет, используем listener rw-node/remnanode
    # только как подсказку. Пользователь всё равно вводит/подтверждает порт сам.
    local suggestion=""
    if ((${#rw_ports[@]} == 1)); then
        suggestion=${rw_ports[0]}
        info "Обнаружен открытый TCP listener rw-node/remnanode: ${suggestion}/tcp."
    elif ((${#rw_ports[@]} > 1)); then
        info "Обнаружены TCP listeners rw-node/remnanode: $(IFS=,; echo "${rw_ports[*]}")."
    else
        info "Source-specific firewall rule для панели не найден; порт панели автоматически не подтверждён."
    fi

    prompt_manual_panel_port "$suggestion" || return $?

    # Для вручную выбранного порта можно предложить IP из firewall, если он там есть.
    ips=$(collect_grouped_firewall_candidates | awk -F'\t' -v p="$PANEL_PORT" '$1==p{print $2; exit}' || true)
    prompt_panel_ips_required "$ips" || return $?
    save_panel_identity
    ok "Панель подтверждена: ${PANEL_PORT}/tcp"
    return 0
}

panel_api_listening() {
    [[ -n ${PANEL_PORT:-} ]] || return 1
    public_tcp_port_listening "$PANEL_PORT"
}

docker_panel_port_published() {
    [[ -n ${PANEL_PORT:-} && -n $DOCKER_BIN ]] || return 1
    "$DOCKER_BIN" inspect --type container remnanode >/dev/null 2>&1 || return 1
    "$DOCKER_BIN" port remnanode "${PANEL_PORT}/tcp" 2>/dev/null | grep -q .
}

panel_container_network_mode() {
    [[ -n $DOCKER_BIN ]] || { printf 'unknown\n'; return 0; }
    "$DOCKER_BIN" inspect --type container -f '{{.HostConfig.NetworkMode}}' remnanode 2>/dev/null || printf 'unknown\n'
}

panel_access_needed() {
    [[ -n ${PANEL_PORT:-} && ${PANEL_SETUP_SKIPPED:-0} -eq 0 ]] || return 1
    return 0
}

panel_ufw_can_enforce() {
    if [[ -n $DOCKER_BIN ]] && "$DOCKER_BIN" inspect --type container remnanode >/dev/null 2>&1; then
        local mode
        mode=$(panel_container_network_mode)
        if [[ $mode != host ]] && docker_panel_port_published; then
            return 1
        fi
    fi
    return 0
}

panel_port_collides_with_ssh() {
    local sp
    [[ -n ${PANEL_PORT:-} ]] || return 1
    for sp in "${SSH_PORTS[@]}"; do
        [[ $sp == "$PANEL_PORT" ]] && return 0
    done
    return 1
}

get_existing_ufw_panel_sources() {
    [[ -n $UFW_BIN && -n ${PANEL_PORT:-} ]] || return 0
    "$UFW_BIN" status 2>/dev/null | awk -v target="${PANEL_PORT}/tcp" '
        $1==target && $2=="ALLOW" && $3!="Anywhere" {print $3}
        $1==target && $2=="(v6)" && $3=="ALLOW" && $4!="Anywhere" {print $4}
    ' | sort -u
    return 0
}

ufw_has_broad_panel_rule() {
    [[ -n $UFW_BIN && -n ${PANEL_PORT:-} ]] || return 1
    "$UFW_BIN" status 2>/dev/null | grep -Eq "^[[:space:]]*${PANEL_PORT}/tcp([[:space:]]+\\(v6\\))?[[:space:]]+ALLOW[[:space:]]+Anywhere([[:space:]]|$)"
}

remove_broad_panel_rules() {
    local -a nums=()
    local n
    [[ -n $UFW_BIN && -n ${PANEL_PORT:-} ]] || return 1
    mapfile -t nums < <(
        "$UFW_BIN" status numbered 2>/dev/null |
        awk -v target="${PANEL_PORT}/tcp" '
            match($0,/^\[[[:space:]]*[0-9]+\][[:space:]]+/) {
                n=substr($0,RSTART,RLENGTH); gsub(/[^0-9]/,"",n)
                rest=substr($0,RSTART+RLENGTH)
                if (n == "") next
                if (rest !~ ("^" target "([[:space:]]|$)")) next
                if (rest !~ /(ALLOW|DENY) IN/) next
                if (rest !~ /Anywhere/) next
                print n
            }
        ' | sort -nr
    )
    for n in "${nums[@]}"; do "$UFW_BIN" --force delete "$n" >/dev/null 2>&1 || true; done
    return 0
}

collect_public_tcp_ports() {
    [[ -n $SS_BIN ]] || return 0
    "$SS_BIN" -H -ltn 2>/dev/null | awk '
        { a=$4; p=a; sub(/^.*:/,"",p); if(p!~/^[0-9]+$/)next; if(a~/^127\./||a~/^\[?::1\]?:/)next; print p }' | sort -n -u
    return 0
}

collect_public_low_udp_ports() {
    [[ -n $SS_BIN ]] || return 0
    "$SS_BIN" -H -lun 2>/dev/null | awk -v high="$((PORT_LOW - 1))" '
        { a=$4; p=a; sub(/^.*:/,"",p); if(p!~/^[0-9]+$/)next; if((p+0)>high)next; if(a~/^127\./||a~/^\[?::1\]?:/)next; print (p+0) }' | sort -n -u
    return 0
}

add_ufw_udp_spec() {
    local spec=${1:-} token start end
    [[ -n $spec ]] || return 0
    spec=${spec//,/ }
    for token in $spec; do
        if [[ $token =~ ^([0-9]+)-([0-9]+)$ ]]; then
            start=${BASH_REMATCH[1]}; end=${BASH_REMATCH[2]}
            (( start>=1 && end<=65535 && start<=end )) || continue
            "$UFW_BIN" allow "${start}:${end}/udp" >/dev/null 2>&1 || true
        elif [[ $token =~ ^[0-9]+$ ]] && (( token>=1 && token<=65535 )); then
            "$UFW_BIN" allow "${token}/udp" >/dev/null 2>&1 || true
        fi
    done
    return 0
}

add_ufw_extra_ports() {
    local raw=${NUVRION_FIREWALL_PORTS:-} token proto port
    [[ -n $raw ]] || return 0
    raw=${raw//,/ }
    for token in $raw; do
        proto=""; port=""
        if [[ $token =~ ^(tcp|udp):([0-9]+)$ ]]; then proto=${BASH_REMATCH[1]}; port=${BASH_REMATCH[2]}
        elif [[ $token =~ ^([0-9]+)/(tcp|udp)$ ]]; then port=${BASH_REMATCH[1]}; proto=${BASH_REMATCH[2]}; fi
        [[ $port =~ ^[0-9]+$ ]] || continue
        (( port>=1 && port<=65535 )) || continue
        "$UFW_BIN" allow "${port}/${proto}" >/dev/null 2>&1 || return 1
    done
    return 0
}

# Ошибка сохранения доступа — основание остановиться ДО включения UFW.
protect_ssh_before_ufw() {
    local ssh_port
    for ssh_port in "${SSH_PORTS[@]}"; do
        if ! "$UFW_BIN" allow "${ssh_port}/tcp" >/dev/null 2>&1; then
            printf 'ОШИБКА: не удалось разрешить SSH TCP/%s. UFW не включается.\n' "$ssh_port" >&2
            return 1
        fi
    done
}

configure_panel_ufw_rule() {
    local ip
    [[ -n ${PANEL_PORT:-} && -n ${PANEL_IPS_NORMALIZED:-} ]] || return 1
    if panel_port_collides_with_ssh; then
        warn "Порт панели ${PANEL_PORT}/tcp совпадает с портом SSH; ограничение по IP через UFW не применяется."
        PANEL_FIREWALL_STATUS="не ограничен: порт совпадает с SSH"
        return 2
    fi
    if ! panel_ufw_can_enforce; then
        warn "remnanode опубликован через Docker bridge; UFW не гарантирует фильтрацию ${PANEL_PORT}/tcp."
        PANEL_FIREWALL_STATUS="Docker bridge: требуется DOCKER-USER/эквивалент"
        return 3
    fi
    if ufw_has_broad_panel_rule; then
        info "Удаляются широкие правила ${PANEL_PORT}/tcp -> Anywhere; разрешение останется только для IP панели."
    fi
    while IFS= read -r ip; do
        [[ -n $ip ]] || continue
        "$UFW_BIN" allow from "$ip" to any port "$PANEL_PORT" proto tcp >/dev/null 2>&1 || return 1
    done <<<"$PANEL_IPS_NORMALIZED"
    remove_broad_panel_rules
    "$UFW_BIN" deny "${PANEL_PORT}/tcp" >/dev/null 2>&1 || return 1
    PANEL_SOURCE_CSV=$(awk 'NF{if(out!="")out=out",";out=out $0} END{print out}' <<<"$PANEL_IPS_NORMALIZED")
    PANEL_FIREWALL_STATUS="${PANEL_PORT}/tcp только: ${PANEL_SOURCE_CSV}"
    FIREWALL_CHANGED=1
    return 0
}

# Возвращает source IP/CIDR из nftables source-specific accept для выбранного порта.
nft_sources_for_panel_port() {
    [[ -n $NFT_BIN && -n ${PANEL_PORT:-} ]] || return 0
    collect_nft_panel_candidates | awk -F'\t' -v p="$PANEL_PORT" '$1==p{print $2}' | sort -u
    return 0
}

nft_has_panel_drop() {
    [[ -n $NFT_BIN && -n ${PANEL_PORT:-} ]] || return 1
    local rules
    rules=$($NFT_BIN -nn list ruleset 2>/dev/null || true)
    [[ -n $rules ]] || return 1
    awk -v p="$PANEL_PORT" '
        /tcp[ \t]+dport/ && /(^|[[:space:]])drop([[:space:]]|$)/ {
            s=$0; gsub(/[{},]/," ",s); n=split(s,f," ")
            for(i=1;i<=n;i++) if(f[i]==p) found=1
        }
        END{exit(found?0:1)}' <<<"$rules"
}

nft_existing_panel_protection_ok() {
    local expected actual ip
    expected=$(printf '%s\n' "$PANEL_IPS_NORMALIZED" | awk 'NF' | sort -u)
    actual=$(nft_sources_for_panel_port)
    [[ -n $expected && -n $actual ]] || return 1
    while IFS= read -r ip; do
        [[ -n $ip ]] || continue
        grep -Fxq "$ip" <<<"$actual" || return 1
    done <<<"$expected"
    nft_has_panel_drop
}

configure_panel_nft_guard() {
    [[ -n $NFT_BIN && -n ${PANEL_PORT:-} && -n ${PANEL_IPS_NORMALIZED:-} ]] || return 1
    if panel_port_collides_with_ssh; then
        PANEL_FIREWALL_STATUS="nftables: порт совпадает с SSH"
        warn "Порт панели ${PANEL_PORT}/tcp совпадает с SSH; nftables guard не создаётся."
        return 2
    fi
    if [[ -n $DOCKER_BIN ]] && "$DOCKER_BIN" inspect --type container remnanode >/dev/null 2>&1; then
        local mode
        mode=$(panel_container_network_mode)
        if [[ $mode != host ]] && docker_panel_port_published; then
            PANEL_FIREWALL_STATUS="Docker bridge: автоматический nft guard пропущен"
            warn "Порт панели опубликован через Docker bridge; универсальный input-hook не гарантирует фильтрацию после DNAT."
            warn "Для этой схемы используйте DOCKER-USER/эквивалент либо host networking."
            return 3
        fi
    fi

    local nft_file=/etc/nuvrion-tuning/panel-firewall.nft
    local setup=/usr/local/sbin/nuvrion-panel-firewall.sh
    local unit=/etc/systemd/system/nuvrion-panel-firewall.service
    local v4="" v6="" ip
    while IFS= read -r ip; do
        [[ -n $ip ]] || continue
        if [[ $ip == *:* ]]; then v6+="${v6:+, }$ip"; else v4+="${v4:+, }$ip"; fi
    done <<<"$PANEL_IPS_NORMALIZED"

    mkdir -p /etc/nuvrion-tuning /usr/local/sbin
    {
        echo 'flush table inet nuvrion_panel_guard'
        [[ -n $v4 ]] && printf 'add set inet nuvrion_panel_guard panel_v4 { type ipv4_addr; flags interval; elements = { %s }; }\n' "$v4"
        [[ -n $v6 ]] && printf 'add set inet nuvrion_panel_guard panel_v6 { type ipv6_addr; flags interval; elements = { %s }; }\n' "$v6"
        echo 'add chain inet nuvrion_panel_guard input { type filter hook input priority -50; policy accept; }'
        printf 'add rule inet nuvrion_panel_guard input iifname "lo" tcp dport %s accept\n' "$PANEL_PORT"
        [[ -n $v4 ]] && printf 'add rule inet nuvrion_panel_guard input tcp dport %s ip saddr @panel_v4 accept\n' "$PANEL_PORT"
        [[ -n $v6 ]] && printf 'add rule inet nuvrion_panel_guard input tcp dport %s ip6 saddr @panel_v6 accept\n' "$PANEL_PORT"
        printf 'add rule inet nuvrion_panel_guard input tcp dport %s drop\n' "$PANEL_PORT"
    } >"$nft_file"
    chmod 0600 "$nft_file"

    cat >"$setup" <<EOFSETUP
#!/usr/bin/env bash
set -u
NFT_BIN=\$(command -v nft || true)
[[ -n \$NFT_BIN ]] || exit 0
\$NFT_BIN list table inet nuvrion_panel_guard >/dev/null 2>&1 || \$NFT_BIN add table inet nuvrion_panel_guard
\$NFT_BIN -f '$nft_file'
EOFSETUP
    chmod 0755 "$setup"

    # Создаём пустую собственную table один раз; последующее flush+add выполняется
    # одной nft-транзакцией. Чужие tables/chains не меняются.
    "$NFT_BIN" list table inet nuvrion_panel_guard >/dev/null 2>&1 || "$NFT_BIN" add table inet nuvrion_panel_guard >/dev/null 2>&1 || return 1
    if ! "$NFT_BIN" -c -f "$nft_file" >/dev/null 2>&1; then
        warn "Сгенерированная nftables-защита панели не прошла nft -c; изменения не применены."
        return 1
    fi
    "$setup" >/dev/null 2>&1 || return 1

    if [[ -n $SYSTEMCTL_BIN && -d /run/systemd/system ]]; then
        cat >"$unit" <<EOFUNIT
[Unit]
Description=Nuvrion — ограничение доступа к панели Remnawave
After=nftables.service network-pre.target
Wants=network-pre.target

[Service]
Type=oneshot
ExecStart=$setup
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOFUNIT
        chmod 0644 "$unit"
        "$SYSTEMCTL_BIN" daemon-reload
        "$SYSTEMCTL_BIN" enable nuvrion-panel-firewall.service >/dev/null 2>&1 || true
    fi

    PANEL_SOURCE_CSV=$(awk 'NF{if(out!="")out=out",";out=out $0} END{print out}' <<<"$PANEL_IPS_NORMALIZED")
    PANEL_FIREWALL_STATUS="nftables guard: ${PANEL_PORT}/tcp только ${PANEL_SOURCE_CSV}"
    FIREWALL_CHANGED=1
    return 0
}

audit_or_configure_external_firewall_panel() {
    local fw=$1
    panel_access_needed || return 0

    if panel_port_collides_with_ssh; then
        PANEL_FIREWALL_STATUS="внешний firewall: порт совпадает с SSH"
        warn "Порт панели ${PANEL_PORT}/tcp совпадает с портом SSH; автоматическое ограничение не выполняется."
        return 0
    fi

    if [[ $fw == nftables.service ]]; then
        if [[ -z $NFT_BIN ]]; then
            PANEL_FIREWALL_STATUS="nftables: команда nft недоступна"
            warn "nftables.service активен, но команда nft недоступна; защита панели не изменяется."
            return 0
        fi
        if nft_existing_panel_protection_ok; then
            PANEL_FIREWALL_STATUS="nftables: подтверждён whitelist + drop остальных"
            ok "Панель ${PANEL_PORT}/tcp уже защищена nftables: подтверждённые IP разрешены, остальные блокируются"
            return 0
        fi
        info "Существующее nftables-правило не подтверждает полную защиту ${PANEL_PORT}/tcp для выбранного IP панели."
        if configure_panel_nft_guard; then
            ok "Создана отдельная защита Nuvrion для ${PANEL_PORT}/tcp в nftables; чужие таблицы не изменялись"
        else
            warn "Автоматически закрепить ограничение ${PANEL_PORT}/tcp в nftables не удалось."
        fi
    else
        PANEL_FIREWALL_STATUS="${fw}: автоматическая настройка не поддерживается"
        warn "Активен внешний firewall ${fw}; порт/IP панели подтверждены, но этот firewall автоматически не изменяется."
    fi
    return 0
}

# Сначала определяем, что именно считать API панели. Это делается до выбора
# UFW/nftables, потому что уже существующий firewall сам является источником
# сильного сигнала для обнаружения порта и IP.
if [[ $SECURITY_ENABLED == 1 ]]; then
    resolve_panel_identity || true
    if (( PANEL_SETUP_SKIPPED )); then
        info "Настройка firewall для панели пропущена; остальные этапы безопасности продолжаются."
    fi
fi

if [[ $SECURITY_ENABLED == 1 ]]; then
    OTHER_FIREWALL=""
    UFW_REQUESTED=0
    PRE_UFW_ACTIVE=0
    if [[ -n $UFW_BIN ]] && "$UFW_BIN" status 2>/dev/null | grep -q '^Status: active'; then PRE_UFW_ACTIVE=1; fi
    if [[ -n $SYSTEMCTL_BIN && -d /run/systemd/system ]]; then
        if "$SYSTEMCTL_BIN" is-active --quiet firewalld.service 2>/dev/null; then OTHER_FIREWALL="firewalld"
        elif "$SYSTEMCTL_BIN" is-active --quiet nftables.service 2>/dev/null; then OTHER_FIREWALL="nftables.service"; fi
    fi

    if [[ -n $OTHER_FIREWALL && $PRE_UFW_ACTIVE -eq 0 ]]; then
        FIREWALL_STATUS="внешний: ${OTHER_FIREWALL}"
        info "Обнаружен активный ${OTHER_FIREWALL}; UFW поверх существующего firewall не внедряется."
        if (( PANEL_SETUP_SKIPPED == 0 )) && [[ -n ${PANEL_PORT:-} && -n ${PANEL_IPS_NORMALIZED:-} ]]; then
            audit_or_configure_external_firewall_panel "$OTHER_FIREWALL"
        fi
    else
        if [[ -z $UFW_BIN ]]; then
            WANT_UFW=0
            if [[ ${NUVRION_ENABLE_UFW:-auto} == 1 ]]; then WANT_UFW=1
            elif [[ ${NUVRION_ENABLE_UFW:-auto} == 0 ]]; then WANT_UFW=0
            elif prompt_yes_no "UFW не установлен. Установить и настроить firewall Nuvrion?"; then WANT_UFW=1; fi
            if (( WANT_UFW )); then
                UFW_REQUESTED=1
                ensure_package ufw || true
                UFW_BIN=$(command -v ufw || true)
            fi
        elif [[ ${NUVRION_ENABLE_UFW:-auto} == 1 ]]; then
            UFW_REQUESTED=1
        fi

        if [[ -n $UFW_BIN ]]; then
            UFW_ACTIVE=0
            "$UFW_BIN" status 2>/dev/null | grep -q '^Status: active' && UFW_ACTIVE=1
            PANEL_NEEDED=0
            panel_access_needed && PANEL_NEEDED=1
            PANEL_UFW_ALLOWED=1

            if (( PANEL_NEEDED )); then
                if panel_port_collides_with_ssh; then
                    PANEL_UFW_ALLOWED=0
                    PANEL_FIREWALL_STATUS="не ограничен: порт совпадает с SSH"
                    warn "Порт панели ${PANEL_PORT}/tcp совпадает с портом SSH; UFW-ограничение по IP пропущено."
                elif ! panel_ufw_can_enforce; then
                    PANEL_UFW_ALLOWED=0
                    PANEL_FIREWALL_STATUS="Docker bridge: требуется DOCKER-USER/эквивалент"
                    warn "Порт панели ${PANEL_PORT}/tcp опубликован Docker-контейнером не в host network; UFW недостаточен."
                fi
            fi

            if (( UFW_ACTIVE )); then
                FIREWALL_STATUS="UFW активен"
                protect_ssh_before_ufw
                add_ufw_extra_ports
                if (( PANEL_NEEDED && PANEL_UFW_ALLOWED )); then
                    if configure_panel_ufw_rule; then
                        ok "UFW: API панели ${PANEL_PORT}/tcp ограничен подтверждёнными IP панели"
                    else
                        warn "Не удалось полностью настроить UFW для ${PANEL_PORT}/tcp."
                    fi
                fi
                ok "UFW уже активен; существующая политика не сбрасывается"
            else
                WANT_ENABLE=0
                if (( UFW_REQUESTED )); then WANT_ENABLE=1
                elif [[ ${NUVRION_ENABLE_UFW:-auto} == 1 ]]; then WANT_ENABLE=1
                elif [[ ${NUVRION_ENABLE_UFW:-auto} == 0 ]]; then WANT_ENABLE=0
                elif prompt_yes_no "UFW установлен, но выключен. Настроить и включить firewall?"; then WANT_ENABLE=1; fi

                if (( WANT_ENABLE )); then
                    info "Перед включением UFW сохраняются фактически открытые сейчас сервисные порты; жёсткого списка портов Nuvrion нет."
                    protect_ssh_before_ufw
                    "$UFW_BIN" default deny incoming >/dev/null 2>&1
                    "$UFW_BIN" default allow outgoing >/dev/null 2>&1
                    while IFS= read -r tcp_port; do
                        [[ -n $tcp_port ]] || continue
                        [[ -n ${PANEL_PORT:-} && $tcp_port == "$PANEL_PORT" ]] && continue
                        "$UFW_BIN" allow "${tcp_port}/tcp" >/dev/null 2>&1 || true
                    done < <(collect_public_tcp_ports)
                    while IFS= read -r udp_port; do
                        [[ -n $udp_port ]] || continue
                        "$UFW_BIN" allow "${udp_port}/udp" >/dev/null 2>&1 || true
                    done < <(collect_public_low_udp_ports)
                    add_ufw_udp_spec "$EXPLICIT_UDP_RESERVED_RAW"
                    add_ufw_extra_ports
                    if (( PANEL_NEEDED && PANEL_UFW_ALLOWED )); then configure_panel_ufw_rule || true; fi
                    if "$UFW_BIN" --force enable >/dev/null 2>&1 && "$UFW_BIN" status 2>/dev/null | grep -q '^Status: active'; then
                        FIREWALL_STATUS="UFW включён, default deny incoming"
                        FIREWALL_CHANGED=1
                        ok "UFW включён: входящие по умолчанию запрещены, обнаруженные рабочие сервисы сохранены"
                    else
                        FIREWALL_STATUS="ошибка включения UFW"
                        warn "Не удалось подтвердить активацию UFW."
                    fi
                else
                    FIREWALL_STATUS="UFW выключен (не изменён)"
                    info "UFW не включён. Неинтерактивно: NUVRION_ENABLE_UFW=1 NUVRION_PANEL_PORT=PORT NUVRION_PANEL_IPS=IP."
                fi
            fi
        else
            FIREWALL_STATUS="UFW отсутствует (не выбран)"
            info "UFW не установлен/не выбран; firewall не изменяется."
        fi
    fi
else
    FIREWALL_STATUS="отключён NUVRION_SECURITY=0"
fi

# После первичного включения/существенного изменения UFW пересобираем Fail2ban,
# чтобы его firewall chains точно существовали после возможного UFW reload.
if (( FIREWALL_CHANGED )) && [[ -n $FAIL2BAN_CLIENT_BIN && -n $SYSTEMCTL_BIN && -d /run/systemd/system ]]; then
    if "$SYSTEMCTL_BIN" is-active --quiet fail2ban.service 2>/dev/null; then
        if "$SYSTEMCTL_BIN" restart fail2ban.service >/dev/null 2>&1; then
            sleep 1
            if "$FAIL2BAN_CLIENT_BIN" status sshd >/dev/null 2>&1; then
                ok "Fail2ban перепроверен после изменения firewall; jail sshd активен"
            else
                warn "После изменения firewall Fail2ban перезапущен, но jail sshd не подтверждён."
            fi
        else
            warn "Не удалось перезапустить Fail2ban после изменения UFW."
        fi
    fi
fi

# ------------------------------------------------------------
# Аудит публичных опасных портов и Docker socket
# ------------------------------------------------------------
if [[ -n $SS_BIN ]]; then
    DANGEROUS_PORT_SET='^(2375|2376|3306|5432|6379|11211|27017|9200|9300|15672)$'
    mapfile -t DANGEROUS_PUBLIC < <(
        "$SS_BIN" -H -ltn 2>/dev/null | awk '
            {
                a=$4; p=a; sub(/^.*:/,"",p)
                if (p !~ /^[0-9]+$/) next
                if (a ~ /^127\./ || a ~ /^\[?::1\]?:/) next
                print p
            }' | sort -n -u | grep -E "$DANGEROUS_PORT_SET" || true
    )
    if ((${#DANGEROUS_PUBLIC[@]})); then
        PUBLIC_DANGEROUS_PORTS=$(IFS=,; echo "${DANGEROUS_PUBLIC[*]}")
        warn "Публично слушаются потенциально чувствительные TCP-порты: ${PUBLIC_DANGEROUS_PORTS}. Скрипт не закрывает их автоматически, так как не знает назначение сервисов."
    else
        PUBLIC_DANGEROUS_PORTS="не найдены"
        ok "Потенциально чувствительные публичные TCP-порты из базового списка не обнаружены"
    fi
fi

if [[ -S /var/run/docker.sock && -n $STAT_BIN ]]; then
    DOCKER_SOCK_MODE=$($STAT_BIN -c '%a' /var/run/docker.sock 2>/dev/null || echo '')
    if [[ $DOCKER_SOCK_MODE =~ ^[0-7]+$ ]]; then
        OTHER_DIGIT=${DOCKER_SOCK_MODE: -1}
        if (( (10#$OTHER_DIGIT & 2) != 0 )); then
            warn "Docker socket /var/run/docker.sock доступен на запись всем пользователям (mode=${DOCKER_SOCK_MODE}); исправьте права/владельца вручную."
        else
            ok "Docker socket не является world-writable (mode=${DOCKER_SOCK_MODE})"
        fi
    fi
fi

# ============================================================
# Системное обслуживание: время, TRIM, диск и post-reboot check
# ============================================================

# ============================================================
# Сертификаты и автопродление
# ============================================================
section "СЕРТИФИКАТЫ И АВТОПРОДЛЕНИЕ"

CERT_STATUS="не проверены"
CERT_MANAGER="не обнаружен"
CERT_COUNT=0
CERT_TIMER_STATUS="не используется"
CERT_FIREWALL_STATUS="не требуется"
CERT_DRYRUN_STATUS="не выполнялся"
CERT_MIN_DAYS=""
CERT_VERIFY_OK=1
CERT_HTTP01_NEEDED=0
CERT_HTTP01_UNKNOWN=0
CERT_DRYRUN_STAMP="$STATE_DIR/certbot-dryrun-success.epoch"
CERT_DRYRUN_LOG="$STATE_DIR/certbot-dryrun-last.log"
CERT_FIREWALL_HELPER=/usr/local/sbin/nuvrion-certbot-firewall.sh
CERT_PRE_HOOK=/etc/letsencrypt/renewal-hooks/pre/90-nuvrion-firewall.sh
CERT_POST_HOOK=/etc/letsencrypt/renewal-hooks/post/90-nuvrion-firewall.sh
CERT_CLEANUP_SERVICE=/etc/systemd/system/nuvrion-certbot-firewall-cleanup.service

certbot_http01_scan() {
    local f auth pref
    CERT_HTTP01_NEEDED=0
    CERT_HTTP01_UNKNOWN=0
    shopt -s nullglob
    local files=(/etc/letsencrypt/renewal/*.conf)
    shopt -u nullglob
    for f in "${files[@]}"; do
        auth=$(awk -F= '/^[[:space:]]*authenticator[[:space:]]*=/{v=$2; gsub(/^[[:space:]]+|[[:space:]]+$/,"",v); print v; exit}' "$f" 2>/dev/null || true)
        pref=$(awk -F= '/^[[:space:]]*preferred_challenges[[:space:]]*=/{v=$2; gsub(/^[[:space:]]+|[[:space:]]+$/,"",v); print v; exit}' "$f" 2>/dev/null || true)
        case "$auth" in
            dns-*|*dns*)
                if [[ $pref == *http* ]]; then CERT_HTTP01_NEEDED=1; fi
                ;;
            webroot|nginx|apache|standalone)
                CERT_HTTP01_NEEDED=1
                ;;
            manual)
                if [[ $pref == *http* ]]; then CERT_HTTP01_NEEDED=1
                elif [[ $pref == *dns* ]]; then :
                else CERT_HTTP01_UNKNOWN=1
                fi
                ;;
            "")
                CERT_HTTP01_UNKNOWN=1
                ;;
            *)
                if [[ $pref == *http* ]]; then CERT_HTTP01_NEEDED=1
                elif [[ $pref == *dns* ]]; then :
                else CERT_HTTP01_UNKNOWN=1
                fi
                ;;
        esac
    done
    return 0
}

ufw_http80_broad_open() {
    [[ -n $UFW_BIN ]] || return 1
    "$UFW_BIN" status 2>/dev/null | awk '
        $1 ~ /^80\/tcp$/ && $0 ~ /ALLOW/ && $0 ~ /Anywhere/ {found=1}
        END {exit(found?0:1)}'
}

certbot_existing_firewall_automation() {
    # Не дублируем уже существующую автоматизацию пользователя.
    if grep -RqsE '(ufw|iptables|nft).*(80|http)|80/tcp' /etc/letsencrypt/renewal-hooks 2>/dev/null; then
        return 0
    fi
    if grep -qsEi '^[[:space:]]*(pre_hook|post_hook)[[:space:]]*=.*(ufw|iptables|nft).*(80|http)|^[[:space:]]*(pre_hook|post_hook)[[:space:]]=.*80/tcp' \
        /etc/letsencrypt/renewal/*.conf /etc/letsencrypt/cli.ini 2>/dev/null; then
        return 0
    fi
    return 1
}

nft_http80_broad_open() {
    [[ -n $NFT_BIN ]] || return 1
    local rules
    rules=$($NFT_BIN list ruleset 2>/dev/null || true)
    [[ -n $rules ]] || return 1
    awk '
        /tcp[ \t]+dport/ && /accept/ && $0 !~ /(ip|ip6)[ \t]+saddr/ {
            s=$0; gsub(/[{},]/," ",s); n=split(s,f,/[ \t]+/)
            for(i=1;i<=n;i++) if(f[i]=="tcp" && f[i+1]=="dport" && f[i+2]=="80") found=1
        }
        END {exit(found?0:1)}' <<<"$rules"
}

install_certbot_ufw_hooks() {
    [[ -n $UFW_BIN && -n $SYSTEMCTL_BIN ]] || return 1
    mkdir -p /usr/local/sbin /etc/letsencrypt/renewal-hooks/pre /etc/letsencrypt/renewal-hooks/post

    if [[ ! -s $CERT_FIREWALL_HELPER ]]; then
        cat >"$CERT_FIREWALL_HELPER" <<'CERTFW'
#!/usr/bin/env bash
set -u
MODE=${1:-}
MARKER=/run/nuvrion-certbot-ufw80-opened
COMMENT=Nuvrion-certbot-temporary
UFW=$(command -v ufw || true)
[[ -n $UFW ]] || exit 0
$UFW status 2>/dev/null | grep -q '^Status: active' || exit 0

broad_open() {
    $UFW status 2>/dev/null | awk '
        $1 ~ /^80\/tcp$/ && $0 ~ /ALLOW/ && $0 ~ /Anywhere/ {found=1}
        END {exit(found?0:1)}'
}

remove_own_rules() {
    local nums n
    nums=$($UFW status numbered 2>/dev/null | awk '
        /80\/tcp/ && /ALLOW/ && /Nuvrion-certbot-temporary/ {
            if(match($0,/\[[[:space:]]*[0-9]+\]/)) {
                n=substr($0,RSTART,RLENGTH); gsub(/[^0-9]/,"",n); if(n!="") print n
            }
        }' | sort -rn)
    while IFS= read -r n; do
        [[ $n =~ ^[0-9]+$ ]] || continue
        $UFW --force delete "$n" >/dev/null 2>&1 || true
    done <<<"$nums"
}

case "$MODE" in
    open)
        rm -f "$MARKER"
        # Сначала убираем только возможные зависшие временные правила Nuvrion.
        remove_own_rules
        broad_open && exit 0
        if $UFW insert 1 allow 80/tcp comment "$COMMENT" >/dev/null 2>&1; then
            : >"$MARKER"
        fi
        ;;
    close)
        if [[ -e $MARKER ]]; then
            remove_own_rules
            rm -f "$MARKER"
        else
            # Fail-safe: после аварийной перезагрузки marker мог исчезнуть из /run.
            remove_own_rules
        fi
        ;;
    *) exit 0 ;;
esac
exit 0
CERTFW
        chmod 0755 "$CERT_FIREWALL_HELPER"
    fi

    if [[ ! -s $CERT_PRE_HOOK ]]; then
        cat >"$CERT_PRE_HOOK" <<EOF
#!/usr/bin/env bash
exec ${CERT_FIREWALL_HELPER} open
EOF
        chmod 0755 "$CERT_PRE_HOOK"
    fi
    if [[ ! -s $CERT_POST_HOOK ]]; then
        cat >"$CERT_POST_HOOK" <<EOF
#!/usr/bin/env bash
exec ${CERT_FIREWALL_HELPER} close
EOF
        chmod 0755 "$CERT_POST_HOOK"
    fi

    if [[ ! -s $CERT_CLEANUP_SERVICE ]]; then
        cat >"$CERT_CLEANUP_SERVICE" <<EOF
[Unit]
Description=Nuvrion — очистка временного правила Certbot 80/tcp
After=ufw.service network-pre.target

[Service]
Type=oneshot
ExecStart=${CERT_FIREWALL_HELPER} close

[Install]
WantedBy=multi-user.target
EOF
        chmod 0644 "$CERT_CLEANUP_SERVICE"
    fi
    "$SYSTEMCTL_BIN" daemon-reload >/dev/null 2>&1 || return 1
    if ! "$SYSTEMCTL_BIN" is-enabled --quiet nuvrion-certbot-firewall-cleanup.service 2>/dev/null; then
        "$SYSTEMCTL_BIN" enable nuvrion-certbot-firewall-cleanup.service >/dev/null 2>&1 || return 1
    fi
    return 0
}

certbot_timer_detect_or_enable() {
    local unit=""

    # Существующий cron считаем уже настроенным механизмом и не заменяем timer-ом.
    if [[ -s /etc/cron.d/certbot ]]; then
        CERT_TIMER_STATUS="cron /etc/cron.d/certbot"
        return 0
    fi
    if [[ -n $CRONTAB_BIN ]] && "$CRONTAB_BIN" -l 2>/dev/null | grep -Eq '(^|[[:space:]])certbot([[:space:]]|$).*renew|certbot[[:space:]]+renew'; then
        CERT_TIMER_STATUS="root crontab"
        return 0
    fi

    [[ -n $SYSTEMCTL_BIN ]] || return 1
    unit=$($SYSTEMCTL_BIN list-unit-files --type=timer --no-legend 2>/dev/null | awk '$1 ~ /certbot.*\.timer$/ {print $1; exit}' || true)
    if [[ -n $unit ]]; then
        if "$SYSTEMCTL_BIN" is-enabled --quiet "$unit" 2>/dev/null && "$SYSTEMCTL_BIN" is-active --quiet "$unit" 2>/dev/null; then
            CERT_TIMER_STATUS="${unit} активен"
            return 0
        fi
        if "$SYSTEMCTL_BIN" enable --now "$unit" >/dev/null 2>&1; then
            CERT_TIMER_STATUS="${unit} включён Nuvrion"
            ok "Автопродление сертификатов включено: $unit"
            return 0
        fi
        CERT_TIMER_STATUS="${unit} найден, но не удалось включить"
        return 1
    fi
    return 1
}

certbot_schedule_current_ok() {
    local unit=""
    [[ -s /etc/cron.d/certbot ]] && return 0
    if [[ -n $CRONTAB_BIN ]] && "$CRONTAB_BIN" -l 2>/dev/null | grep -Eq '(^|[[:space:]])certbot([[:space:]]|$).*renew|certbot[[:space:]]+renew'; then
        return 0
    fi
    [[ -n $SYSTEMCTL_BIN ]] || return 1
    unit=$($SYSTEMCTL_BIN list-unit-files --type=timer --no-legend 2>/dev/null | awk '$1 ~ /certbot.*\.timer$/ {print $1; exit}' || true)
    [[ -n $unit ]] || return 1
    "$SYSTEMCTL_BIN" is-enabled --quiet "$unit" 2>/dev/null && "$SYSTEMCTL_BIN" is-active --quiet "$unit" 2>/dev/null
}

certbot_expiry_audit() {
    [[ -n $OPENSSL_BIN ]] || return 0
    local pem end epoch now days min=""
    now=$(date +%s)
    shopt -s nullglob
    local pems=(/etc/letsencrypt/live/*/fullchain.pem)
    shopt -u nullglob
    for pem in "${pems[@]}"; do
        [[ -r $pem ]] || continue
        end=$($OPENSSL_BIN x509 -in "$pem" -noout -enddate 2>/dev/null | cut -d= -f2- || true)
        [[ -n $end ]] || continue
        epoch=$(date -d "$end" +%s 2>/dev/null || true)
        [[ $epoch =~ ^[0-9]+$ ]] || continue
        days=$(( (epoch - now) / 86400 ))
        if [[ -z $min || $days -lt $min ]]; then min=$days; fi
    done
    CERT_MIN_DAYS=$min
    return 0
}

certbot_dryrun_needed() {
    [[ $CERTBOT_DRY_RUN == 1 ]] || return 1
    local now last age
    now=$(date +%s)
    if [[ -s $CERT_DRYRUN_STAMP ]]; then
        last=$(cat "$CERT_DRYRUN_STAMP" 2>/dev/null || echo 0)
        if [[ $last =~ ^[0-9]+$ ]]; then
            age=$((now-last))
            (( age < 604800 )) && return 1
        fi
    fi
    return 0
}

if [[ $CERTIFICATE_AUTOMATION != 1 ]]; then
    CERT_STATUS="отключено NUVRION_CERTIFICATES=0"
    info "Проверка сертификатов отключена NUVRION_CERTIFICATES=0."
elif [[ -n $CERTBOT_BIN || -d /etc/letsencrypt ]]; then
    CERT_MANAGER="certbot"
    if [[ -z $CERTBOT_BIN ]]; then CERTBOT_BIN=$(command -v certbot || true); fi
    CERT_COUNT=$({ find /etc/letsencrypt/renewal -maxdepth 1 -type f -name '*.conf' 2>/dev/null | wc -l | awk '{print $1}'; } || true)
    CERT_COUNT=${CERT_COUNT:-0}
    CERT_NO_CERTS=0
    if (( CERT_COUNT == 0 )); then
        CERT_NO_CERTS=1
        CERT_STATUS="certbot установлен, renewal-конфигурации не найдены"
        info "$CERT_STATUS"
    else
        ok "Certbot: найдено renewal-конфигураций: $CERT_COUNT"
        if [[ -z $CERTBOT_BIN ]]; then
            CERT_VERIFY_OK=0
            warn "Найдены renewal-конфигурации Let's Encrypt, но команда certbot недоступна."
        fi
        certbot_http01_scan
        certbot_expiry_audit

        if certbot_timer_detect_or_enable; then
            ok "Автопродление Certbot: $CERT_TIMER_STATUS"
        else
            CERT_VERIFY_OK=0
            warn "Certbot найден, но автоматический timer/cron автопродления не подтверждён."
            CERT_TIMER_STATUS="не подтверждён"
        fi

        if (( CERT_HTTP01_NEEDED )); then
            if [[ -n $UFW_BIN ]] && "$UFW_BIN" status 2>/dev/null | grep -q '^Status: active'; then
                if ufw_http80_broad_open; then
                    CERT_FIREWALL_STATUS="80/tcp уже открыт постоянно — не изменяется"
                    ok "HTTP-01: 80/tcp уже разрешён UFW; временные правила не требуются"
                elif [[ -s $CERT_PRE_HOOK && -s $CERT_POST_HOOK && -x $CERT_FIREWALL_HELPER ]]; then
                    if install_certbot_ufw_hooks; then
                        CERT_FIREWALL_STATUS="временный 80/tcp уже настроен Nuvrion"
                        ok "HTTP-01: существующие хуки Nuvrion временно открывают и закрывают 80/tcp"
                    else
                        CERT_VERIFY_OK=0
                        CERT_FIREWALL_STATUS="хуки Nuvrion найдены, fail-safe не подтверждён"
                        warn "HTTP-01: существующие хуки найдены, но их fail-safe/автозапуск проверить не удалось."
                    fi
                elif certbot_existing_firewall_automation; then
                    CERT_FIREWALL_STATUS="обнаружена существующая firewall-автоматизация — не изменяется"
                    ok "HTTP-01: обнаружена существующая автоматизация firewall; Nuvrion её не изменяет"
                elif install_certbot_ufw_hooks; then
                    CERT_FIREWALL_STATUS="временный 80/tcp настроен Nuvrion"
                    ok "HTTP-01: настроено временное открытие 80/tcp перед renew и закрытие после renew"
                else
                    CERT_VERIFY_OK=0
                    CERT_FIREWALL_STATUS="не удалось настроить временный 80/tcp"
                    warn "Не удалось настроить безопасное временное правило UFW для HTTP-01."
                fi
            elif [[ -n $SYSTEMCTL_BIN ]] && "$SYSTEMCTL_BIN" is-active --quiet nftables.service 2>/dev/null; then
                if nft_http80_broad_open; then
                    CERT_FIREWALL_STATUS="80/tcp уже разрешён nftables — не изменяется"
                    ok "HTTP-01: nftables уже разрешает 80/tcp; существующие правила не изменяются"
                elif certbot_existing_firewall_automation; then
                    CERT_FIREWALL_STATUS="обнаружена существующая firewall-автоматизация — не изменяется"
                    ok "HTTP-01: обнаружена существующая автоматизация открытия/закрытия firewall; Nuvrion её не изменяет"
                else
                    CERT_VERIFY_OK=0
                    CERT_FIREWALL_STATUS="внешний nftables: временный 80/tcp не настроен"
                    warn "HTTP-01 требует 80/tcp, но активен внешний nftables. Неизвестный ruleset автоматически не изменяется; настройте pre/post-hook или откройте 80/tcp."
                fi
            else
                CERT_FIREWALL_STATUS="активный host-firewall не обнаружен — хуки не нужны"
                ok "HTTP-01: активный UFW/nftables.service не обнаружен; временное firewall-правило не требуется"
            fi
        elif (( CERT_HTTP01_UNKNOWN )); then
            CERT_FIREWALL_STATUS="тип challenge определён не полностью — не изменяется"
            info "Certbot: тип challenge части renewal-конфигураций не определён однозначно; firewall не изменяется."
        else
            CERT_FIREWALL_STATUS="HTTP-01 не используется"
            ok "Certbot: HTTP-01 не обнаружен; открывать 80/tcp не требуется"
        fi

        if [[ -z $CERTBOT_BIN ]]; then
            CERT_DRYRUN_STATUS="невозможно: certbot недоступен"
            CERT_VERIFY_OK=0
            warn "Certbot dry-run невозможен: команда certbot отсутствует."
        elif [[ $CERTBOT_DRY_RUN != 1 ]]; then
            CERT_DRYRUN_STATUS="отключён NUVRION_CERTBOT_DRY_RUN=0"
            info "Certbot dry-run отключён NUVRION_CERTBOT_DRY_RUN=0."
        elif certbot_dryrun_needed; then
            info "Проверяется реальное автопродление: certbot renew --dry-run ..."
            DRY_CMD=("$CERTBOT_BIN" renew --dry-run)
            if "$CERTBOT_BIN" renew --help all 2>/dev/null | grep -q -- '--no-random-sleep-on-renew'; then
                DRY_CMD+=(--no-random-sleep-on-renew)
            fi
            mkdir -p "$STATE_DIR"
            if [[ -n $TIMEOUT_BIN ]]; then
                if "$TIMEOUT_BIN" 600 "${DRY_CMD[@]}" >"$CERT_DRYRUN_LOG" 2>&1; then DRY_RC=0; else DRY_RC=$?; fi
            else
                if "${DRY_CMD[@]}" >"$CERT_DRYRUN_LOG" 2>&1; then DRY_RC=0; else DRY_RC=$?; fi
            fi
            # Fail-safe: если certbot/timeout оборвался до post-hook, временный UFW 80/tcp
            # всё равно закрывается сразу после dry-run. Удаляются только правила Nuvrion.
            if [[ -x $CERT_FIREWALL_HELPER ]]; then
                "$CERT_FIREWALL_HELPER" close >/dev/null 2>&1 || true
            fi
            if (( DRY_RC == 0 )); then
                date +%s >"$CERT_DRYRUN_STAMP"
                chmod 0600 "$CERT_DRYRUN_STAMP" "$CERT_DRYRUN_LOG" 2>/dev/null || true
                CERT_DRYRUN_STATUS="успешно"
                ok "Certbot dry-run завершён успешно"
            else
                CERT_DRYRUN_STATUS="ошибка rc=$DRY_RC (лог: $CERT_DRYRUN_LOG)"
                CERT_VERIFY_OK=0
                warn "Certbot dry-run завершился ошибкой (код $DRY_RC). Лог: $CERT_DRYRUN_LOG"
            fi
        else
            CERT_DRYRUN_STATUS="успешно проверялся менее 7 дней назад"
            ok "Certbot dry-run недавно проходил успешно; повторная staging-проверка сейчас не нужна"
        fi

        if [[ -n $CERT_MIN_DAYS ]]; then
            if (( CERT_MIN_DAYS < 14 )); then
                CERT_VERIFY_OK=0
                warn "Минимальный срок сертификата: ${CERT_MIN_DAYS} дн. — требуется срочная проверка renewal."
            elif (( CERT_MIN_DAYS < 30 )); then
                warn "Минимальный срок сертификата: ${CERT_MIN_DAYS} дн. — проверьте ближайшее автопродление."
            else
                ok "Срок сертификатов: минимум ${CERT_MIN_DAYS} дн."
            fi
        fi
        CERT_STATUS="certbot: ${CERT_COUNT} шт.; ${CERT_TIMER_STATUS}; dry-run=${CERT_DRYRUN_STATUS}"
    fi
elif command -v acme.sh >/dev/null 2>&1 || [[ -x /root/.acme.sh/acme.sh ]]; then
    CERT_MANAGER="acme.sh"
    ACME_CRON=0
    if [[ -n $CRONTAB_BIN ]] && "$CRONTAB_BIN" -l 2>/dev/null | grep -q 'acme\.sh'; then ACME_CRON=1; fi
    if grep -Rq 'acme\.sh' /etc/cron.d /etc/systemd/system 2>/dev/null; then ACME_CRON=1; fi
    if (( ACME_CRON )); then
        CERT_STATUS="acme.sh: автопродление обнаружено — не изменяется"
        ok "acme.sh: существующий механизм автопродления обнаружен; Nuvrion его не изменяет"
    else
        CERT_VERIFY_OK=0
        CERT_STATUS="acme.sh обнаружен, расписание renewal не подтверждено"
        warn "acme.sh обнаружен, но cron/systemd автопродления не найден."
    fi
elif command -v dehydrated >/dev/null 2>&1 || command -v lego >/dev/null 2>&1; then
    CERT_MANAGER="внешний ACME-клиент"
    CERT_STATUS="внешний ACME-клиент обнаружен — конфигурация не изменяется"
    info "$CERT_STATUS"
else
    CERT_STATUS="сертификаты/ACME-клиент не обнаружены — не требуется"
    info "$CERT_STATUS"
fi

section "СИСТЕМНОЕ ОБСЛУЖИВАНИЕ"

NTP_STATUS="не проверен"
FSTRIM_STATUS="не проверен"
DISK_STATUS="не проверен"
INODE_STATUS="не проверен"
POST_REBOOT_STATUS="не требуется"
POST_REBOOT_MARKER="$STATE_DIR/post-reboot-check.pending"
POST_REBOOT_LOG="$STATE_DIR/post-reboot-last.txt"
POST_REBOOT_SCRIPT=/usr/local/sbin/nuvrion-post-reboot-check.sh
POST_REBOOT_SERVICE=/etc/systemd/system/nuvrion-post-reboot-check.service

if [[ $SYSTEM_MAINTENANCE == 1 ]]; then
    # --------------------------------------------------------
    # NTP: если синхронизация уже работает — ничего не меняем.
    # Если её нет и systemd/timedatectl доступны — включаем NTP.
    # --------------------------------------------------------
    if [[ -n $TIMEDATECTL_BIN && -n $SYSTEMCTL_BIN && -d /run/systemd/system ]]; then
        NTP_SYNC=$($TIMEDATECTL_BIN show -p NTPSynchronized --value 2>/dev/null || true)
        if [[ $NTP_SYNC == yes ]]; then
            NTP_STATUS="синхронизировано (существующая настройка)"
            ok "Системное время синхронизировано; существующая NTP-настройка не изменяется"
        else
            NTP_SERVICE_ACTIVE=""
            for ntp_svc in chrony.service chronyd.service systemd-timesyncd.service; do
                if "$SYSTEMCTL_BIN" is-active --quiet "$ntp_svc" 2>/dev/null; then
                    NTP_SERVICE_ACTIVE=$ntp_svc
                    break
                fi
            done

            if [[ -n $NTP_SERVICE_ACTIVE ]]; then
                NTP_STATUS="${NTP_SERVICE_ACTIVE} активен, синхронизация ожидается"
                info "NTP-служба ${NTP_SERVICE_ACTIVE} уже активна; конфигурация не изменяется, синхронизация может занять время."
            elif "$TIMEDATECTL_BIN" set-ntp true >/dev/null 2>&1; then
                sleep 1
                NTP_SYNC=$($TIMEDATECTL_BIN show -p NTPSynchronized --value 2>/dev/null || true)
                if [[ $NTP_SYNC == yes ]]; then
                    NTP_STATUS="включено Nuvrion, синхронизировано"
                    ok "NTP включён и системное время синхронизировано"
                else
                    NTP_STATUS="включено Nuvrion, синхронизация ожидается"
                    info "NTP включён; подтверждение синхронизации пока не получено — это нормально сразу после запуска."
                fi
            else
                NTP_STATUS="не удалось включить"
                warn "Синхронизация времени не подтверждена и timedatectl set-ntp true завершился ошибкой."
            fi
        fi
    else
        NTP_STATUS="timedatectl/systemd недоступны"
        info "Автонастройка NTP пропущена: timedatectl/systemd недоступны."
    fi

    # --------------------------------------------------------
    # fstrim.timer: существующую активную/включённую настройку
    # не трогаем. Для нового timer сначала проверяем реальную
    # discard-granularity корневого блочного устройства.
    # fstrim --dry-run сам по себе может вернуть rc=0 даже при 0 B.
    # --------------------------------------------------------
    if [[ -n $FSTRIM_BIN && -n $SYSTEMCTL_BIN && -d /run/systemd/system ]] && \
       "$SYSTEMCTL_BIN" cat fstrim.timer >/dev/null 2>&1; then
        FSTRIM_ENABLED=$($SYSTEMCTL_BIN is-enabled fstrim.timer 2>/dev/null || true)
        FSTRIM_ACTIVE=$($SYSTEMCTL_BIN is-active fstrim.timer 2>/dev/null || true)
        if [[ $FSTRIM_ENABLED == enabled || $FSTRIM_ACTIVE == active ]]; then
            FSTRIM_STATUS="уже включён"
            ok "fstrim.timer уже настроен; существующая конфигурация не изменяется"
        elif [[ $FSTRIM_ENABLED == masked ]]; then
            FSTRIM_STATUS="замаскирован пользователем"
            info "fstrim.timer замаскирован; Nuvrion не снимает пользовательскую mask-настройку."
        else
            FSTRIM_TEST_OK=0
            ROOT_SRC=""
            DISCARD_GRAN=""
            if [[ -n $FINDMNT_BIN && -n $LSBLK_BIN ]]; then
                ROOT_SRC=$($FINDMNT_BIN -no SOURCE / 2>/dev/null | head -n1 || true)
                # btrfs subvolume может выглядеть как /dev/xxx[/@].
                ROOT_SRC=${ROOT_SRC%%[*}
                if [[ $ROOT_SRC == /dev/* ]]; then
                    DISCARD_GRAN=$($LSBLK_BIN -bndo DISC-GRAN "$ROOT_SRC" 2>/dev/null | awk 'NR==1 {print $1}' || true)
                fi
            fi
            if [[ $DISCARD_GRAN =~ ^[0-9]+$ ]] && (( DISCARD_GRAN > 0 )); then
                FSTRIM_TEST_OK=1
            fi

            if (( FSTRIM_TEST_OK )); then
                if "$SYSTEMCTL_BIN" enable --now fstrim.timer >/dev/null 2>&1; then
                    FSTRIM_STATUS="включён Nuvrion (discard=${DISCARD_GRAN} B)"
                    ok "Корневое устройство поддерживает discard (${DISCARD_GRAN} B); fstrim.timer включён"
                else
                    FSTRIM_STATUS="discard поддерживается, timer не включён"
                    warn "Discard поддерживается, но не удалось включить fstrim.timer."
                fi
            else
                FSTRIM_STATUS="discard не подтверждён/не требуется"
                info "Поддержка discard для корневого блочного устройства не подтверждена; fstrim.timer не изменяется."
            fi
        fi
    else
        FSTRIM_STATUS="fstrim.timer недоступен"
        info "fstrim.timer недоступен; автоматическая настройка TRIM пропущена."
    fi

    # --------------------------------------------------------
    # Заполнение диска и inode. Только аудит; ничего не удаляем.
    # --------------------------------------------------------
    if [[ -n $DF_BIN ]]; then
        DISK_USE=$($DF_BIN -P / 2>/dev/null | awk 'NR==2 {gsub(/%/,"",$5); print $5}' || true)
        INODE_USE=$($DF_BIN -Pi / 2>/dev/null | awk 'NR==2 {gsub(/%/,"",$5); print $5}' || true)

        if [[ $DISK_USE =~ ^[0-9]+$ ]]; then
            DISK_STATUS="${DISK_USE}%"
            if (( DISK_USE >= 90 )); then
                warn "Корневая файловая система заполнена на ${DISK_USE}% — требуется освободить место."
            elif (( DISK_USE >= 85 )); then
                warn "Корневая файловая система заполнена на ${DISK_USE}% — рекомендуется проверить свободное место."
            else
                ok "Свободное место: занято ${DISK_USE}% корневой файловой системы"
            fi
        else
            DISK_STATUS="не удалось определить"
            info "Не удалось определить заполнение корневой файловой системы."
        fi

        if [[ $INODE_USE =~ ^[0-9]+$ ]]; then
            INODE_STATUS="${INODE_USE}%"
            if (( INODE_USE >= 90 )); then
                warn "Использование inode на корневой файловой системе ${INODE_USE}% — требуется проверка."
            elif (( INODE_USE >= 85 )); then
                warn "Использование inode на корневой файловой системе ${INODE_USE}% — приближается к пределу."
            else
                ok "Inode: использовано ${INODE_USE}%"
            fi
        else
            INODE_STATUS="не удалось определить"
            info "Не удалось определить использование inode."
        fi
    else
        DISK_STATUS="df недоступен"
        INODE_STATUS="df недоступен"
    fi
else
    NTP_STATUS="отключено NUVRION_SYSTEM_MAINTENANCE=0"
    FSTRIM_STATUS="$NTP_STATUS"
    DISK_STATUS="$NTP_STATUS"
    INODE_STATUS="$NTP_STATUS"
    info "Системное обслуживание отключено NUVRION_SYSTEM_MAINTENANCE=0."
fi

# ------------------------------------------------------------
# Одноразовая самопроверка после следующей требуемой перезагрузки.
# Сервис остаётся установленным, но запускается только при marker-файле.
# Сам check ничего не меняет и всегда завершается без перевода systemd
# в degraded; полный результат сохраняется в STATE_DIR.
# ------------------------------------------------------------
install_post_reboot_check() {
    [[ $POST_REBOOT_ENABLED == 1 ]] || return 1
    [[ -n $SYSTEMCTL_BIN && -d /run/systemd/system ]] || return 1

    mkdir -p /usr/local/sbin
    cat >"$POST_REBOOT_SCRIPT" <<'POSTCHECK'
#!/usr/bin/env bash
set -u
export LC_ALL=C

STATE_DIR=/var/lib/nuvrion-tuning
MARKER="$STATE_DIR/post-reboot-check.pending"
LOG="$STATE_DIR/post-reboot-last.txt"
CONF=/etc/sysctl.d/99-zzzz-nuvrion-performance.conf
mkdir -p "$STATE_DIR"

exec > >(tee "$LOG") 2>&1

OKS=0
WARNS=0
ok() { printf '[ OK ] %s\n' "$*"; OKS=$((OKS + 1)); }
warn() { printf '[ВНИМАНИЕ] %s\n' "$*"; WARNS=$((WARNS + 1)); }
info() { printf '[ИНФО] %s\n' "$*"; }
ws() { awk '{$1=$1; print}' <<<"${1:-}"; }

expected_sysctl() {
    local key=$1 line rhs
    [[ -f $CONF ]] || return 1
    line=$(grep -E "^[[:space:]]*${key//./\\.}[[:space:]]*=" "$CONF" 2>/dev/null | tail -n1 || true)
    [[ -n $line ]] || return 1
    rhs=${line#*=}
    ws "$rhs"
}

check_sysctl() {
    local key=$1 exp act
    exp=$(expected_sysctl "$key" || true)
    [[ -n $exp ]] || { info "$key отсутствует в профиле; проверка пропущена"; return 0; }
    act=$(sysctl -n "$key" 2>/dev/null || true)
    if [[ $(ws "$act") == $(ws "$exp") ]]; then
        ok "$key = $(ws "$act")"
    else
        warn "$key: ожидалось '$(ws "$exp")', фактически '$(ws "$act")'"
    fi
}

printf '============================================================\n'
printf ' Nuvrion — проверка после перезагрузки\n'
printf ' Дата: %s\n' "$(date -Is 2>/dev/null || date)"
printf '============================================================\n'

for key in \
    net.core.default_qdisc \
    net.ipv4.tcp_congestion_control \
    net.core.rmem_max \
    net.core.wmem_max \
    net.core.netdev_max_backlog \
    net.core.somaxconn \
    net.ipv4.ip_local_port_range \
    net.netfilter.nf_conntrack_max \
    net.netfilter.nf_conntrack_buckets; do
    check_sysctl "$key"
done

if command -v swapon >/dev/null 2>&1; then
    ZDEV=$(swapon --show=NAME --noheadings 2>/dev/null | awk '$1 ~ /^\/dev\/zram/ {print $1; exit}' || true)
    if [[ -n $ZDEV ]]; then
        ok "ZRAM активен: $ZDEV"
    elif systemctl is-enabled --quiet nuvrion-zram.service 2>/dev/null; then
        warn "nuvrion-zram.service включён, но активный /dev/zram* не найден"
    else
        info "ZRAM не обнаружен; возможно используется внешняя/иная swap-конфигурация."
    fi
fi

if command -v docker >/dev/null 2>&1 && docker inspect --type container remnanode >/dev/null 2>&1; then
    RUNNING=$(docker inspect --type container -f '{{.State.Running}}' remnanode 2>/dev/null || true)
    if [[ $RUNNING == true ]]; then
        NETMODE=$(docker inspect --type container -f '{{.HostConfig.NetworkMode}}' remnanode 2>/dev/null || true)
        [[ $NETMODE == host ]] && ok "remnanode network mode: host" || info "remnanode network mode: ${NETMODE:-не определён}"
        NOFILE=$(docker exec remnanode sh -c 'printf "%s/%s" "$(ulimit -Sn)" "$(ulimit -Hn)"' 2>/dev/null || true)
        if [[ $NOFILE == */* ]]; then
            S=${NOFILE%/*}; H=${NOFILE#*/}
            if [[ $S =~ ^[0-9]+$ && $H =~ ^[0-9]+$ ]] && (( S >= 1048576 && H >= 1048576 )); then
                ok "remnanode NOFILE: $NOFILE"
            else
                warn "remnanode NOFILE ниже целевого или нечисловой: $NOFILE"
            fi
        else
            info "Не удалось прочитать NOFILE remnanode; контейнер не изменяется."
        fi
    else
        warn "Контейнер remnanode существует, но не запущен."
    fi
fi

if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q '^Status: active'; then
    ok "UFW активен"
elif command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet nftables.service 2>/dev/null; then
    ok "nftables.service активен"
else
    info "Активный UFW/nftables.service не подтверждён."
fi

printf '============================================================\n'
printf 'ИТОГ: OK=%s, WARN=%s\n' "$OKS" "$WARNS"
printf '============================================================\n'
rm -f "$MARKER"
exit 0
POSTCHECK
    chmod 0755 "$POST_REBOOT_SCRIPT"

    cat >"$POST_REBOOT_SERVICE" <<EOF
[Unit]
Description=Nuvrion — одноразовая проверка после перезагрузки
Wants=network-online.target
After=network-online.target docker.service
ConditionPathExists=${POST_REBOOT_MARKER}

[Service]
Type=oneshot
ExecStart=${POST_REBOOT_SCRIPT}

[Install]
WantedBy=multi-user.target
EOF
    chmod 0644 "$POST_REBOOT_SERVICE"
    "$SYSTEMCTL_BIN" daemon-reload >/dev/null 2>&1 || return 1
    "$SYSTEMCTL_BIN" enable nuvrion-post-reboot-check.service >/dev/null 2>&1 || return 1
    return 0
}

if [[ -e /var/run/reboot-required || $PROFILE_REBOOT_REQUIRED -eq 1 ]]; then
    if [[ $POST_REBOOT_ENABLED == 1 ]]; then
        if install_post_reboot_check; then
            : >"$POST_REBOOT_MARKER"
            chmod 0600 "$POST_REBOOT_MARKER" 2>/dev/null || true
            POST_REBOOT_STATUS="запланирована после следующей перезагрузки"
            ok "После следующей перезагрузки будет выполнена одноразовая самопроверка Nuvrion; отчёт: $POST_REBOOT_LOG"
        else
            POST_REBOOT_STATUS="не удалось запланировать"
            warn "Не удалось настроить одноразовую проверку после перезагрузки."
        fi
    else
        POST_REBOOT_STATUS="отключена NUVRION_POST_REBOOT_CHECK=0"
        info "Самопроверка после reboot отключена NUVRION_POST_REBOOT_CHECK=0."
    fi
else
    POST_REBOOT_STATUS="не требуется сейчас"
fi

# ------------------------------------------------------------
# Права только на собственные файлы Nuvrion
# ------------------------------------------------------------
mkdir -p /etc/nuvrion-tuning "$STATE_DIR" "$SNAPSHOT_DIR" "$BACKUP_DIR"
PERMISSIONS_OK=1
normalize_owned_mode() {
    local mode=$1 path=${2:-}
    [[ -n $path && ( -e $path || -L $path ) ]] || return 0
    if [[ -L $path || ! -f $path ]] || ! chmod "$mode" "$path"; then
        PERMISSIONS_OK=0
    fi
}
chmod 0700 /etc/nuvrion-tuning "$STATE_DIR" "$SNAPSHOT_DIR" "$BACKUP_DIR" 2>/dev/null || PERMISSIONS_OK=0
normalize_owned_mode 0600 "$RESERVED_BASELINE_FILE"
normalize_owned_mode 0600 "$UDP_PORTS_FILE"
normalize_owned_mode 0600 "${PANEL_IP_FILE:-}"
normalize_owned_mode 0755 "$ZRAM_SETUP"
normalize_owned_mode 0755 "$RPS_SETUP"
normalize_owned_mode 0755 "${POST_REBOOT_SCRIPT:-}"
normalize_owned_mode 0600 "${POST_REBOOT_MARKER:-}"
normalize_owned_mode 0600 "${POST_REBOOT_LOG:-}"
normalize_owned_mode 0600 "${CERT_DRYRUN_STAMP:-}"
normalize_owned_mode 0600 "${CERT_DRYRUN_LOG:-}"
normalize_owned_mode 0755 "${CERT_FIREWALL_HELPER:-}"
if [[ -n $CHOWN_BIN ]]; then
    "$CHOWN_BIN" -R root:root /etc/nuvrion-tuning "$STATE_DIR" >/dev/null 2>&1 || PERMISSIONS_OK=0
else
    PERMISSIONS_OK=0
fi
if (( PERMISSIONS_OK )); then
    SECURITY_FILES_STATUS="права собственных файлов нормализованы"
    ok "Права на собственные конфигурации/снимки Nuvrion нормализованы"
else
    SECURITY_FILES_STATUS="не удалось нормализовать права всех собственных файлов"
    warn "$SECURITY_FILES_STATUS"
fi

# ============================================================
# Финальная проверка всех компонентов
# ============================================================
section "ФИНАЛЬНАЯ ПРОВЕРКА ВСЕХ КОМПОНЕНТОВ"

certificate_final_check() {
    [[ $CERTIFICATE_AUTOMATION == 1 ]] || return 2
    case "$CERT_MANAGER" in
        certbot)
            (( ${CERT_NO_CERTS:-0} == 0 )) || return 2
            [[ -n $CERTBOT_BIN ]] || return 1
            certbot_schedule_current_ok || return 1
            (( CERT_VERIFY_OK )) || return 1
            if (( CERT_HTTP01_NEEDED )) && [[ -n $UFW_BIN ]] && "$UFW_BIN" status 2>/dev/null | grep -q '^Status: active'; then
                if ! ufw_http80_broad_open; then
                    [[ -x $CERT_FIREWALL_HELPER && -s $CERT_PRE_HOOK && -s $CERT_POST_HOOK ]] || \
                    certbot_existing_firewall_automation || return 1
                fi
            fi
            return 0
            ;;
        acme.sh)
            (( CERT_VERIFY_OK )) && return 0 || return 1
            ;;
        "внешний ACME-клиент")
            return 2
            ;;
        *) return 2 ;;
    esac
}

FINAL_TOTAL=0
FINAL_OK=0
FINAL_WARN=0
FINAL_SKIP=0

ufw_current_panel_protection_ok() {
    [[ -n $UFW_BIN && -n ${PANEL_PORT:-} && -n ${PANEL_IPS_NORMALIZED:-} ]] || return 1
    local expected actual ip
    expected=$(printf '%s\n' "$PANEL_IPS_NORMALIZED" | awk 'NF' | sort -u)
    actual=$(get_existing_ufw_panel_sources)
    [[ -n $expected && -n $actual ]] || return 1
    while IFS= read -r ip; do
        [[ -n $ip ]] || continue
        grep -Fxq "$ip" <<<"$actual" || return 1
    done <<<"$expected"
    ufw_has_broad_panel_rule && return 1
    "$UFW_BIN" status 2>/dev/null | grep -Eq "^[[:space:]]*${PANEL_PORT}/tcp([[:space:]]+\(v6\))?[[:space:]]+DENY[[:space:]]+Anywhere([[:space:]]|$)" || return 1
    return 0
}

final_ok() {
    FINAL_TOTAL=$((FINAL_TOTAL + 1)); FINAL_OK=$((FINAL_OK + 1))
    printf '%s%s[  OK  ]%s     %s — %s\n' "$C_BOLD" "$C_GREEN" "$C_RESET" "$1" "$2"
    return 0
}
final_warn() {
    FINAL_TOTAL=$((FINAL_TOTAL + 1)); FINAL_WARN=$((FINAL_WARN + 1))
    printf '%s%s[ ВНИМАНИЕ ]%s %s — %s\n' "$C_BOLD" "$C_YELLOW" "$C_RESET" "$1" "$2"
    return 0
}
final_skip() {
    FINAL_TOTAL=$((FINAL_TOTAL + 1)); FINAL_SKIP=$((FINAL_SKIP + 1))
    printf '%s[ ПРОПУСК ]%s  %s — %s\n' "$C_CYAN" "$C_RESET" "$1" "$2"
    return 0
}

ALL_SYSCTL_OK=1
for key in "${!DESIRED[@]}"; do
    actual=$($SYSCTL_BIN -n "$key" 2>/dev/null || true)
    if [[ $(normalize_ws "$actual") != $(normalize_ws "${DESIRED[$key]}") ]]; then ALL_SYSCTL_OK=0; break; fi
done
if (( ALL_SYSCTL_OK )); then final_ok "Профиль sysctl" "все целевые значения совпадают"; else final_warn "Профиль sysctl" "есть расхождения"; fi

if [[ $($SYSCTL_BIN -n net.ipv4.tcp_congestion_control 2>/dev/null || true) == bbr && $($SYSCTL_BIN -n net.core.default_qdisc 2>/dev/null || true) == fq ]]; then
    final_ok "BBR / qdisc" "bbr / fq"
else
    final_warn "BBR / qdisc" "не соответствует профилю"
fi

CT_NOW=$($SYSCTL_BIN -n net.netfilter.nf_conntrack_max 2>/dev/null || true)
if [[ $CT_NOW == "${DESIRED[net.netfilter.nf_conntrack_max]:-}" ]]; then final_ok "Conntrack" "$CT_NOW"; else final_warn "Conntrack" "max=${CT_NOW:-неизвестно}"; fi

ZCHECK=$(get_active_zram || true)
if [[ -n $ZCHECK ]]; then
    ZCHECK_MB=$(get_zram_size_mb "$ZCHECK")
    ZCHECK_PRIO=$(get_zram_priority "$ZCHECK")
    if (( ZCHECK_MB > 0 )); then
        final_ok "ZRAM" "активен: $ZCHECK, ${ZCHECK_MB} MB${ZCHECK_PRIO:+, priority=${ZCHECK_PRIO}}"
    else
        final_warn "ZRAM" "$ZCHECK активен, но disksize не подтверждён"
    fi
elif (( ZRAM_DEFERRED_READY )); then
    final_skip "ZRAM" "$ZRAM_STATUS"
else
    final_warn "ZRAM" "не активен — ${ZRAM_STATUS:-причина не определена}"
fi

if (( CPU <= 1 || RXQ_COUNT >= CPU )); then
    final_skip "RPS / ядра" "не требуется для текущих CPU/RX"
else
    RPS_ACTUAL=0
    for q in "${RXQS[@]}"; do
        if [[ -r $q/rps_cpus ]] && rps_value_nonzero "$(cat "$q/rps_cpus")"; then RPS_ACTUAL=1; fi
    done
    if (( RPS_ACTUAL )); then final_ok "RPS / ядра" "активная маска подтверждена"
    else final_warn "RPS / ядра" "активная маска не подтверждена"; fi
fi

if [[ -n $DOCKER_BIN ]] && "$DOCKER_BIN" inspect --type container remnanode >/dev/null 2>&1; then
    RUNNING=$($DOCKER_BIN inspect --type container -f '{{.State.Running}}' remnanode 2>/dev/null || true)
    NFP=$(get_remnanode_nofile || true)
    if [[ $RUNNING == true && $NFP == */* ]] && nofile_pair_ok "$NFP"; then final_ok "Remnawave Node" "running, NOFILE=$NFP"; else final_warn "Remnawave Node" "running=${RUNNING:-?}, NOFILE=${NFP:-?}"; fi
else
    final_skip "Remnawave Node" "контейнер remnanode не обнаружен"
fi

if [[ $SECURITY_ENABLED == 1 ]]; then
    if [[ -n $FAIL2BAN_CLIENT_BIN ]] && "$FAIL2BAN_CLIENT_BIN" status sshd >/dev/null 2>&1; then
        final_ok "Fail2ban" "jail sshd активен"
    elif [[ ${FAIL2BAN_STATUS:-} == *"sshd не обнаружен"* ]]; then
        final_skip "Fail2ban" "sshd не обнаружен — не требуется"
    else
        final_warn "Fail2ban" "${FAIL2BAN_STATUS:-не подтверждён}"
    fi
    if apt-config dump | grep -E '^APT::Periodic::Unattended-Upgrade[[:space:]]+"1"' >/dev/null; then final_ok "Обновления безопасности" "$UPDATES_STATUS"; else final_warn "Обновления безопасности" "не подтверждены"; fi
else
    final_skip "Безопасность" "NUVRION_SECURITY=0"
fi

FINAL_UFW_ACTIVE=0
FINAL_NFT_ACTIVE=0
[[ -n $UFW_BIN ]] && "$UFW_BIN" status 2>/dev/null | grep -q '^Status: active' && FINAL_UFW_ACTIVE=1
[[ -n $SYSTEMCTL_BIN && -n $NFT_BIN ]] && "$SYSTEMCTL_BIN" is-active --quiet nftables.service 2>/dev/null && FINAL_NFT_ACTIVE=1
if (( FINAL_UFW_ACTIVE && FINAL_NFT_ACTIVE )); then
    FIREWALL_STATUS="одновременно активны UFW и nftables.service"
    final_warn "Брандмауэр" "$FIREWALL_STATUS"
elif (( FINAL_UFW_ACTIVE )); then
    FIREWALL_STATUS="UFW активен"
    final_ok "Брандмауэр" "$FIREWALL_STATUS"
elif (( FINAL_NFT_ACTIVE )); then
    FIREWALL_STATUS="внешний: nftables.service"
    final_ok "Брандмауэр" "$FIREWALL_STATUS"
else
    final_skip "Брандмауэр" "${FIREWALL_STATUS:-не используется}"
fi

if (( PANEL_SETUP_SKIPPED )); then
    final_skip "API панели" "настройка явно пропущена"
elif [[ -n ${PANEL_PORT:-} ]]; then
    PANEL_ACTUAL_OK=0
    if [[ -n $UFW_BIN ]] && "$UFW_BIN" status 2>/dev/null | grep -q '^Status: active'; then
        ufw_current_panel_protection_ok && PANEL_ACTUAL_OK=1
    elif [[ -n $SYSTEMCTL_BIN && -n $NFT_BIN ]] && "$SYSTEMCTL_BIN" is-active --quiet nftables.service 2>/dev/null; then
        nft_existing_panel_protection_ok && PANEL_ACTUAL_OK=1
    elif [[ ${PANEL_FIREWALL_STATUS:-} == *"guard:"* || ${PANEL_FIREWALL_STATUS:-} == *"защищ"* ]]; then
        PANEL_ACTUAL_OK=1
    fi
    if (( PANEL_ACTUAL_OK )); then final_ok "API панели ${PANEL_PORT}/tcp" "защита подтверждена повторной проверкой"; else final_warn "API панели ${PANEL_PORT}/tcp" "${PANEL_FIREWALL_STATUS:-защита не подтверждена}"; fi
else
    final_skip "API панели" "порт не определён"
fi

if [[ $SYSTEM_MAINTENANCE == 1 ]]; then
    if [[ -n $TIMEDATECTL_BIN && $("$TIMEDATECTL_BIN" show -p NTPSynchronized --value 2>/dev/null) == yes ]]; then
        final_ok "NTP / время" "$NTP_STATUS"
    elif [[ ${NTP_STATUS:-} == *"timedatectl/systemd недоступны"* ]]; then
        final_skip "NTP / время" "$NTP_STATUS"
    else
        final_warn "NTP / время" "${NTP_STATUS:-не подтверждено}"
    fi
    if [[ -n $SYSTEMCTL_BIN ]] && "$SYSTEMCTL_BIN" is-active --quiet fstrim.timer; then final_ok "TRIM" "таймер активен"; else final_skip "TRIM" "${FSTRIM_STATUS:-не требуется/не поддерживается}"; fi
else
    final_skip "Обслуживание" "NUVRION_SYSTEM_MAINTENANCE=0"
fi

CERT_FINAL_RC=0
certificate_final_check || CERT_FINAL_RC=$?
case "$CERT_FINAL_RC" in
    0) final_ok "Сертификаты" "$CERT_STATUS" ;;
    2) final_skip "Сертификаты" "$CERT_STATUS" ;;
    *) final_warn "Сертификаты" "$CERT_STATUS" ;;
esac

if [[ -n $SYSTEMCTL_BIN && -f $AUTHORITATIVE_SERVICE ]]; then
    if "$SYSTEMCTL_BIN" is-enabled --quiet nuvrion-performance-sysctl.service 2>/dev/null; then
        final_ok "Автоприменение sysctl" "nuvrion-performance-sysctl.service включён"
    else
        final_warn "Автоприменение sysctl" "systemd-unit существует, но не enabled"
    fi
else
    final_skip "Автоприменение sysctl" "systemd-unit не используется"
fi

if [[ -S /var/run/docker.sock && -n $STAT_BIN ]]; then
    DSMODE=$($STAT_BIN -c '%a' /var/run/docker.sock 2>/dev/null || true)
    if [[ -n $DSMODE ]] && (( (10#$DSMODE % 10) & 2 )); then
        final_warn "Docker socket" "world-writable mode=${DSMODE}"
    else
        final_ok "Docker socket" "mode=${DSMODE:-неизвестно}"
    fi
else
    final_skip "Docker socket" "не обнаружен"
fi

if [[ $SECURITY_ENABLED == 1 ]]; then
    if [[ -n $SSHD_BIN ]] && "$SSHD_BIN" -T | grep -q '^passwordauthentication no$'; then
        final_ok "SSH-аудит" "$SSH_SECURITY_STATUS"
    elif [[ ${SSH_SECURITY_STATUS:-} == *"sshd не обнаружен"* ]]; then
        final_skip "SSH-аудит" "sshd не обнаружен"
    else
        final_warn "SSH-аудит" "${SSH_SECURITY_STATUS:-не подтверждён}"
    fi

    if [[ ${PUBLIC_DANGEROUS_PORTS:-} == "не найдены" ]]; then
        final_ok "Чувствительные порты" "не найдены"
    elif [[ -z ${SS_BIN:-} || -z ${PUBLIC_DANGEROUS_PORTS:-} ]]; then
        final_skip "Чувствительные порты" "ss недоступен — аудит не выполнен"
    else
        final_warn "Чувствительные порты" "$PUBLIC_DANGEROUS_PORTS"
    fi
fi

if [[ ${DISK_STATUS:-} =~ ^[0-9]+%$ && ${INODE_STATUS:-} =~ ^[0-9]+%$ ]]; then
    DU=${DISK_STATUS%%%}; IU=${INODE_STATUS%%%}
    if (( DU < 85 && IU < 85 )); then final_ok "Диск / inode" "${DISK_STATUS}, inode=${INODE_STATUS}"; else final_warn "Диск / inode" "${DISK_STATUS}, inode=${INODE_STATUS}"; fi
else
    final_skip "Диск / inode" "статус не определён"
fi

FINAL_CHECK_STATUS="OK=${FINAL_OK}, предупреждений=${FINAL_WARN}, пропущено=${FINAL_SKIP}, всего=${FINAL_TOTAL}"
if (( FINAL_WARN > 0 && WARNINGS == 0 )); then WARNINGS=1; fi
printf '%s%s%s\n' "$C_DIM" "$UI_LINE" "$C_RESET"
printf '  Финальная проверка: %s\n' "$FINAL_CHECK_STATUS"

# ============================================================
# Итоговый отчёт
# ============================================================

printf '\n%s%s%s\n' "$C_BOLD" "$C_CYAN" "$UI_LINE"
printf '  Nuvrion v1.0.0  ·  ИТОГОВЫЙ ОТЧЁТ\n'
printf '%s%s\n' "$UI_LINE" "$C_RESET"

printf '%sСИСТЕМА%s\n' "$C_BOLD" "$C_RESET"
printf '  CPU / RAM             %s vCPU / %s MB\n' "$CPU" "$RAM_MB"
printf '  Конфигурация          %s\n' "$CONF"
printf '  Снимок до изменений   %s\n' "$SNAPSHOT"
printf '  ZRAM                  %s\n' "$ZRAM_STATUS"
printf '  RPS / ядра            %s\n' "$RPS_STATUS"
printf '  NTP / время           %s\n' "$NTP_STATUS"
printf '  TRIM                  %s\n' "$FSTRIM_STATUS"
printf '  Диск /                %s, inode=%s\n' "$DISK_STATUS" "$INODE_STATUS"

printf '\n%sСЕТЬ И ПРОИЗВОДИТЕЛЬНОСТЬ%s\n' "$C_BOLD" "$C_RESET"
printf '  Буферы                rmem=%s wmem=%s\n' "$(sysctl -n net.core.rmem_max 2>/dev/null)" "$(sysctl -n net.core.wmem_max 2>/dev/null)"
printf '  Backlog / SYN         %s / %s\n' "$(sysctl -n net.core.netdev_max_backlog 2>/dev/null)" "$(sysctl -n net.ipv4.tcp_max_syn_backlog 2>/dev/null)"
printf '  BBR / qdisc           %s / %s\n' "$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)" "$(sysctl -n net.core.default_qdisc 2>/dev/null)"
printf '  Диапазон портов       %s\n' "$(normalize_ws "$(sysctl -n net.ipv4.ip_local_port_range 2>/dev/null)")"
printf '  Резерв UDP            только явно заданные\n'
if (( MANAGE_RESERVED )); then printf '  Зарезерв. порты       %s\n' "$(sysctl -n net.ipv4.ip_local_reserved_ports 2>/dev/null || true)"; fi
printf '  Лимиты нагрузки       изменено=%s, ошибок=%s\n' "$LIMIT_CHANGES" "$LIMIT_FIX_ERRORS"
printf '  Docker                restart=%s, recreate remnanode=%s\n' "$DOCKER_RESTARTED" "$DOCKER_CONTAINER_RECREATED"
printf '  Systemd-сервисы       перезапущено=%s\n' "$SYSTEMD_SERVICES_RESTARTED"

printf '\n%sБЕЗОПАСНОСТЬ%s\n' "$C_BOLD" "$C_RESET"
printf '  Защита ядра           %s параметров\n' "${#SECURITY_SYSCTL_KEYS[@]}"
printf '  Fail2ban              %s\n' "$FAIL2BAN_STATUS"
printf '  Обновления            %s\n' "$UPDATES_STATUS"
printf '  Брандмауэр            %s\n' "$FIREWALL_STATUS"
if [[ -n ${PANEL_PORT:-} ]]; then
    printf '  Панель %-15s %s\n' "${PANEL_PORT}/tcp" "$PANEL_FIREWALL_STATUS"
    printf '  Определение панели    %s\n' "$PANEL_IDENTITY_SOURCE"
else
    printf '  Панель API            %s\n' "$PANEL_FIREWALL_STATUS"
fi
printf '  SSH                   %s\n' "$SSH_SECURITY_STATUS"
printf '  Опасные порты         %s\n' "${PUBLIC_DANGEROUS_PORTS:-не проверены}"
printf '  Файлы Nuvrion        %s\n' "$SECURITY_FILES_STATUS"
printf '  Сертификаты           %s\n' "$CERT_STATUS"
printf '  ACME / firewall       %s\n' "$CERT_FIREWALL_STATUS"
printf '\n%sИЗМЕНЕНИЯ И ПРОВЕРКИ%s\n' "$C_BOLD" "$C_RESET"
printf '  Предупреждения        %s\n' "$WARNINGS"
printf '  Конфликты             %s\n' "$CONFLICTS"
printf '  Пропущено sysctl      %s\n' "$SKIPPED"
printf '  Изменено принудит.    %s параметров\n' "$FORCED_CHANGES"
printf '  Уже совпадало         %s параметров\n' "$ALREADY_MATCHED"
printf '  Отключено поздних     %s назначений / %s файлов\n' "$CLEANED_ASSIGNMENTS" "$CLEANED_FILES"
printf '  Восстановлено старых  %s назначений / %s файлов\n' "$RESTORED_ASSIGNMENTS" "$RESTORED_FILES"
if (( AUTHORITATIVE_BOOT )); then
    printf '  Автоприменение        после systemd-sysctl\n'
else
    printf '  Автоприменение        только sysctl.d\n'
fi
printf '  Самопроверка reboot   %s\n' "$POST_REBOOT_STATUS"
printf '  Финальная проверка    %s\n' "$FINAL_CHECK_STATUS"
if (( PROFILE_REBOOT_REQUIRED )); then printf '  Ожидает reboot        conntrack hash table\n'; fi

printf '%s%s%s\n' "$C_DIM" "$UI_LINE" "$C_RESET"

if (( CONFLICTS > 0 )); then
    printf '%s%s  РЕЗУЛЬТАТ  КОНФЛИКТ%s\n' "$C_BOLD" "$C_RED" "$C_RESET"
    printf '  Профиль применён, но требуется проверка найденных конфликтов.\n'
elif (( WARNINGS > 0 || SKIPPED > 0 )); then
    printf '%s%s  РЕЗУЛЬТАТ  ЕСТЬ ПРЕДУПРЕЖДЕНИЯ%s\n' "$C_BOLD" "$C_YELLOW" "$C_RESET"
    printf '  Профиль активен; проверьте предупреждения выше.\n'
else
    printf '%s%s  РЕЗУЛЬТАТ  ВСЁ ОК%s\n' "$C_BOLD" "$C_GREEN" "$C_RESET"
fi
printf '%s%s%s%s\n' "$C_BOLD" "$C_CYAN" "$UI_LINE" "$C_RESET"

# ============================================================
# Уведомление о необходимости перезагрузки
# ============================================================
if [[ -e /var/run/reboot-required || $PROFILE_REBOOT_REQUIRED -eq 1 ]]; then
    printf '\n%s%s%s\n' "$C_BOLD" "$C_YELLOW" "$UI_LINE"
    printf '  ПЕРЕЗАГРУЗКА СЕРВЕРА ТРЕБУЕТСЯ\n'
    printf '%s%s\n' "$UI_LINE" "$C_RESET"
    if [[ -e /var/run/reboot-required ]]; then
        printf 'Ubuntu сообщает, что после системных обновлений требуется перезагрузка.\n'
    fi
    if (( PROFILE_REBOOT_REQUIRED )); then
        printf 'Часть параметров conntrack будет окончательно применена после перезагрузки.\n'
    elif [[ -e /var/run/reboot-required ]]; then
        printf 'Профиль Nuvrion и лимиты нагрузки уже применены; перезагрузка требуется из-за системных обновлений.\n'
    fi
    if [[ ${POST_REBOOT_STATUS:-} == запланирована* ]]; then
        printf 'После загрузки отчёт самопроверки будет сохранён: %s\n' "$POST_REBOOT_LOG"
    fi
    printf '\n  Команда: %sreboot%s\n' "$C_BOLD" "$C_RESET"
    printf '%s%s%s%s\n' "$C_BOLD" "$C_YELLOW" "$UI_LINE" "$C_RESET"
else
    printf '\n%s%s[  OK  ]%s Перезагрузка сервера не требуется.\n' "$C_BOLD" "$C_GREEN" "$C_RESET"
    if (( LIMIT_RESTART_NOTICE )); then
        printf '%s[ ИНФО ]%s Изменённые лимиты уже применены перезапуском/пересозданием соответствующей нагрузки.\n' "$C_CYAN" "$C_RESET"
    fi
fi
