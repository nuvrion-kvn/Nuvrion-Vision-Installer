#!/usr/bin/env bash
# Nuvrion · release 1.0.0
# ==============================================================================
# Nuvrion Vision Installer
# Автор и разработчик: Nuvrion
# GitHub: nuvrion-kvn
# Copyright (c) 2026 Nuvrion
# SPDX-License-Identifier: MIT
# ==============================================================================
set -Eeuo pipefail
umask 077
export LC_ALL=C.UTF-8
export PYTHONUTF8=1
readonly NUVRION_VERSION=1.0.0
# Фиксированный каталог используется службами systemd и хуками.
readonly BASE=/opt/remnanode
WORK=''
STAGING=''
ACME_OPEN=0
APT_APPROVED=0
CYAN='' GREEN='' YELLOW='' RED='' BOLD='' RESET=''
if [[ -t 1 && ! ${NO_COLOR+x} ]]; then
    CYAN=$'\033[36m'; GREEN=$'\033[32m'; YELLOW=$'\033[33m'; RED=$'\033[31m'
    BOLD=$'\033[1m'; RESET=$'\033[0m'
fi
say() { printf '%s\n' "$*"; }
ui_file() {
    if [[ -n $WORK && -f $WORK/terminal_ui.py ]]; then printf '%s' "$WORK/terminal_ui.py"
    elif [[ -f $BASE/terminal_ui.py ]]; then printf '%s' "$BASE/terminal_ui.py"
    fi
}
step() {
    local ui; ui=$(ui_file)
    if [[ -n $ui ]]; then python3 "$ui" heading "$*"
    else printf '\n%s%s──────────────────────────────────────────────\n  %s\n──────────────────────────────────────────────%s\n' "$BOLD" "$CYAN" "$*" "$RESET"
    fi
}
ok() {
    local ui; ui=$(ui_file)
    if [[ -n $ui ]]; then python3 "$ui" ok "$*"
    else printf '  %s[✓]%s %s\n' "$GREEN" "$RESET" "$*"; fi
}
warn() {
    local ui; ui=$(ui_file)
    if [[ -n $ui ]]; then python3 "$ui" warn "$*"
    else printf '  %s[!]%s %s\n' "$YELLOW" "$RESET" "$*"; fi
}
skip() {
    local ui; ui=$(ui_file)
    if [[ -n $ui ]]; then python3 "$ui" info "$*"
    else printf '  [•] %s\n' "$*"; fi
}
banner() {
    step "Nuvrion · VISION / $NUVRION_VERSION"
    say '  Установка и настройка VPN-ноды'
    say '  Автор и разработчик: Nuvrion'
    say '  GitHub: nuvrion-kvn'
    say ''
    say '  ◆ RemnaNode для подключения к панели Remnawave'
    say '  ◆ VLESS с TLS 1.3 и режимом Vision'
    say '  ◆ Нейтральный сайт на nginx через два Unix-сокета'
    say "  ◆ Сертификат Let's Encrypt и автоматическое продление"
    say '  ◆ Продвинутая настройка Nuvrion: сеть, ZRAM, защита сервера'
    say '  ◆ Ограничение API IP-адресами панели, защита служб и SSH'
    say '  ◆ Защита от входящих ICMP echo и timestamp-запросов'
    say '  ◆ Nuvrion Traffic Control — опционально: фильтрация по трём внешним спискам'
    say ''
    say '  По завершении: готовый профиль ноды и настройки хоста.'
    say '  Нужен отдельный сервер с прямым IP и доменом без CDN.'
    say '  Системные компоненты и обновления будут проверены перед настройкой.'
    say ''
    say '  Д/Y — да · Н/N — нет. Enter без ответа означает «Нет».'
    say '  [✓] выполнено · [•] информация · [!] внимание · [✗] ошибка'
}
ask_yes() {
    local answer
    local BOLD=$BOLD YELLOW=$YELLOW RESET=$RESET
    if [[ -t 0 && ! ${NO_COLOR+x} && ${TERM:-} != dumb ]]; then
        BOLD=$'\033[1m'; YELLOW=$'\033[93m'; RESET=$'\033[0m'
    fi
    while true; do
        printf '\n  %s%s%s [Д/Н; Enter — Н]: %s' "$BOLD" "$YELLOW" "$1" "$RESET" > /dev/tty
        IFS= read -r answer < /dev/tty || return 1
        case "$answer" in
            Д|д|Да|да|ДА|дА|[Yy]|[Yy][Ee][Ss]) return 0;;
            ''|Н|н|Нет|НеТ|НЕт|НЕТ|нет|неТ|нЕт|нЕТ|[Nn]|[Nn][Oo]) return 1;;
            *) printf '  %s%sВведите Д/Y — да или Н/N — нет%s\n' "$BOLD" "$YELLOW" "$RESET" > /dev/tty;;
        esac
    done
}
confirm_install() { ask_yes 'Установить на машину Nuvrion Vision?'; }
die() { printf '\n  %s%s✗ ОШИБКА:%s %s\n' "$BOLD" "$RED" "$RESET" "$*" >&2; exit 1; }
# shellcheck disable=SC2317,SC2329
cleanup() {
    local rc=$?
    if [[ ${ACME_OPEN:-0} == 1 ]]; then
        if ! "$BASE/acme-firewall.sh" close; then
            printf '  ✗ ОШИБКА: временный TCP/80 не удалось закрыть; проверьте правила ACME.\n' >&2
            (( rc != 0 )) || rc=1
        fi
    fi
    [[ -z $WORK ]] || rm -rf -- "$WORK"
    [[ -z $STAGING ]] || rm -rf -- "$STAGING"
    exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'printf "\n  %s✗ ОШИБКА:%s остановка на строке %s (код %s)\n" "$RED" "$RESET" "$LINENO" "$?" >&2' ERR

unpack() {
    [[ -z $WORK ]] || return 0
    if ! declare -F payload >/dev/null || [[ -z ${NUVRION_PAYLOAD_SHA256:-} ]]; then
        die 'Для операции со встроенным архивом нужен исходный самодостаточный установщик.'
    fi
    WORK=$(mktemp -d)
    # Сборка содержит собственный код, локальную заглушку и закреплённые компоненты.
    # Архив проверяется до распаковки; загруженный код на этом этапе не выполняется.
    if ! payload | base64 -d > "$WORK/bundle.tar.gz" 2>/dev/null; then
        die 'Встроенный архив повреждён: не удалось декодировать Base64.'
    fi
    if ! printf '%s  %s\n' "$NUVRION_PAYLOAD_SHA256" "$WORK/bundle.tar.gz" | \
      sha256sum -c --status -; then
        die 'Контрольная сумма встроенного архива не совпала. Установка остановлена.'
    fi
    if ! tar -xzf "$WORK/bundle.tar.gz" -C "$WORK" 2>/dev/null; then
        die 'Не удалось распаковать проверенный встроенный архив.'
    fi
}

compose() {
    docker compose --project-directory "$BASE" -f "$BASE/docker-compose.yml" "$@"
}

get_setting() {
    python3 -c 'import json,sys
v=json.load(open(sys.argv[1],encoding="utf-8"))[sys.argv[2]]
print(" ".join(map(str,v)) if isinstance(v,list) else v)' "$BASE/settings.json" "$1"
}

os_identity() (
    # Все поля os-release остаются в дочерней оболочке, включая неизвестные.
    ID='' VERSION_ID='' VERSION_CODENAME='' UBUNTU_CODENAME=''
    [[ -r /etc/os-release ]] || die 'Не найден файл сведений об операционной системе'
    # shellcheck disable=SC1091
    source /etc/os-release
    printf '%s:%s:%s\n' "$ID" "$VERSION_ID" "${UBUNTU_CODENAME:-$VERSION_CODENAME}"
)

require_server() {
    (( EUID == 0 )) || die 'Запустите скрипт от имени root'
    [[ -d /run/systemd/system ]] || die 'Нужен сервер с systemd, не контейнер/chroot.'
    local identity distro release codename
    identity=$(os_identity)
    IFS=: read -r distro release codename <<< "$identity"
    case "$distro:$release" in ubuntu:22.04|ubuntu:24.04|debian:12|debian:13) ;;
        *) die 'Поддерживаются Ubuntu 22.04/24.04 и Debian 12/13.';; esac
    case "$(uname -m)" in x86_64|aarch64) ;; *) die 'Поддерживаются x86_64 и arm64.';; esac
}

approve_apt_for_run() {
    (( APT_APPROVED == 0 )) || return 0
    if ! ask_yes 'Разрешить для текущей установки обновление APT и системы, а также установку обязательных пакетов, Docker и nginx?'; then
        die 'Обновление системы и установка компонентов отменены. Установка ноды не начата'
    fi
    APT_APPROVED=1
    ok 'Действия APT разрешены для текущего запуска; каждый план будет показан перед применением'
}

apt_confirmed() {
    local simulation plan verified attempts=0
    local -a added updated removed
    while true; do
        simulation=$(apt-get -s -o Dpkg::Options::=--force-confold "$@" 2>&1) || {
            say "$simulation" >&2
            die 'Не удалось рассчитать доступные обновления APT. Проверьте состояние пакетов'
        }
        plan=$(awk '$1=="Inst" || $1=="Remv" || $1=="Conf"' <<< "$simulation")
        if [[ -z $plan ]]; then
            ok 'Для этого действия APT обновлений нет'
            return
        fi
        mapfile -t added < <(awk '$1=="Inst" && $3 !~ /^\[/ {print $2}' <<< "$plan" | sort -u)
        mapfile -t updated < <(awk '$1=="Inst" && $3 ~ /^\[/ {print $2}' <<< "$plan" | sort -u)
        mapfile -t removed < <(awk '$1=="Remv" {print $2}' <<< "$plan" | sort -u)
        say '  План APT'
        show_package_list 'Новые пакеты и зависимости:' "${added[@]}"
        show_package_list 'Обновляемые пакеты:' "${updated[@]}"
        show_package_list 'Удаляемые пакеты:' "${removed[@]}"
        say '  Точные версии и действия:'
        printf '%s\n' "$plan" | sed 's/^/    /'
        (( ${#removed[@]} == 0 )) || die 'План требует удаления пакетов. Автоудаление запрещено; разберите план вручную'
        approve_apt_for_run
        verified=$(apt-get -s -o Dpkg::Options::=--force-confold "$@" 2>&1) || \
          die 'Повторная проверка плана APT завершилась ошибкой'
        verified=$(awk '$1=="Inst" || $1=="Remv" || $1=="Conf"' <<< "$verified")
        [[ $verified != "$plan" ]] || break
        attempts=$((attempts+1))
        (( attempts < 3 )) || die 'План APT постоянно меняется. Дождитесь завершения других обновлений'
        warn 'План APT изменился; пересчитываю его перед применением в рамках полученного разрешения'
    done
    # Даже при изменении состояния после симуляции APT не вправе удалять пакеты.
    apt-get -o DPkg::Lock::Timeout=600 -o Dpkg::Options::=--force-confold --no-remove -y "$@"
}

package_installed() {
    [[ $(dpkg-query -W -f='${Status}' "$1" 2>/dev/null || true) == 'install ok installed' ]]
}

show_package_list() {
    local title=$1; shift
    say "  $title"
    if (( $# == 0 )); then
        say '    — нет'
        return
    fi
    printf '    • %s\n' "$@"
}

cleanup_system_packages() {
    local simulation plan verified package option pattern
    local -a packages=()
    # До проверки загрузки нового ядра сохраняем ВСЕ ядра и загрузчик.
    # Не меняем apt-mark и постоянные настройки APT.
    local -a protection=(
        -o 'APT::NeverAutoRemove::=^linux-.*'
        -o 'APT::NeverAutoRemove::=^(grub|shim|initramfs|dracut|intel-microcode|amd64-microcode).*'
        -o 'APT::NeverAutoRemove::=^(apt|dpkg|systemd|udev|openssh|ufw|nftables|iptables|fail2ban|docker|containerd|nginx|cloud-init|netplan|network-manager|ifupdown|iproute2|python3|ca-certificates|curl|gnupg|openssl|dnsutils|certbot|unattended-upgrades)([-:]|$)'
    )
    step 'Очистка ненужных зависимостей и устаревшего кэша APT'
    simulation=$(apt-get -s "${protection[@]}" autoremove 2>&1) || {
        warn 'Не удалось рассчитать очистку APT; удаление пропущено.'
        return 0
    }
    plan=$(awk '$1=="Inst" || $1=="Remv" || $1=="Conf"' <<< "$simulation")
    if [[ -n $plan ]]; then
        if grep -Eq '^(Inst|Conf) ' <<< "$plan"; then
            warn 'Очистка требует других изменений пакетов; удаление пропущено.'
            return 0
        fi
        mapfile -t packages < <(awk '$1=="Remv" {print $2}' <<< "$plan")
        for package in "${packages[@]}"; do
            for option in "${protection[@]}"; do
                [[ $option == APT::NeverAutoRemove::* ]] || continue
                pattern=${option#*=}
                if [[ $package =~ $pattern ]]; then
                    warn "APT предложил удалить защищённый пакет $package; очистка пропущена."
                    return 0
                fi
            done
        done
        show_package_list 'APT предлагает удалить ненужные зависимости:' "${packages[@]}"
        say '  Ядра и загрузчик сохраняются. Конфигурационные файлы не очищаются.'
        if ask_yes 'Удалить перечисленные ненужные зависимости?'; then
            verified=$(apt-get -s "${protection[@]}" autoremove 2>&1) || {
                warn 'Повторная проверка очистки не прошла; удаление пропущено.'
                return 0
            }
            verified=$(awk '$1=="Inst" || $1=="Remv" || $1=="Conf"' <<< "$verified")
            if [[ $verified != "$plan" ]]; then
                warn 'Список удаления изменился; очистка пропущена, чтобы не удалять неподтверждённые пакеты.'
                return 0
            fi
            apt-get -o DPkg::Lock::Timeout=600 "${protection[@]}" -y autoremove
        else
            skip 'Удаление зависимостей отменено.'
        fi
    else
        ok 'Ненужных зависимостей для удаления нет.'
    fi
    apt-get -o DPkg::Lock::Timeout=600 autoclean
    ok 'Устаревшие архивы пакетов очищены; установленные ядра сохранены.'
}

prepare_system_packages() {
    step '00 / Проверка компонентов и обновлений системы'
    local package command_name
    # Компоненты безопасности ставятся здесь же, чтобы Auto Tuning не повторял apt update.
    local -a required=(ca-certificates curl gnupg openssl python3 xz-utils dnsutils iproute2 certbot ufw nftables openssh-server fail2ban unattended-upgrades)
    local -a missing=()
    for package in "${required[@]}"; do
        package_installed "$package" || missing+=("$package")
    done
    say '  Перед настройкой ноды будет обновлён индекс APT.'
    show_package_list 'Недостающие обязательные пакеты по текущему индексу:' "${missing[@]}"
    say '  После обновления индекса скрипт покажет точный план изменений.'
    say '  Docker и nginx устанавливаются позже — после проверок совместимости и портов.'
    warn 'Обновление пакетов может перезапустить системные службы и потребовать перезагрузку.'
    approve_apt_for_run

    export DEBIAN_FRONTEND=noninteractive
    export NEEDRESTART_MODE=a
    export APT_LISTCHANGES_FRONTEND=none
    apt-get -o DPkg::Lock::Timeout=600 update

    missing=()
    for package in "${required[@]}"; do
        package_installed "$package" || missing+=("$package")
    done
    if (( ${#missing[@]} > 0 )); then
        apt_confirmed install --no-install-recommends "${missing[@]}"
    fi
    # Новый план рассчитывается после установки зависимостей, а не до неё.
    # Обычное обновление с новыми зависимостями, в том числе пакетами ядра.
    # Пакеты, которым требуется удаление/конфликтная замена, остаются удержанными.
    apt_confirmed --with-new-pkgs upgrade
    cleanup_system_packages
    for package in "${required[@]}"; do
        package_installed "$package" || die "Обязательный пакет $package не установлен."
    done
    for command_name in python3 openssl curl gpg dig ip ss certbot ufw nft sshd; do
        command -v "$command_name" >/dev/null || die "Не найдена обязательная команда: $command_name."
    done
    ok 'Проверка компонентов и обновлений завершена.'
    if [[ -e /run/reboot-required ]]; then
        warn 'Система сообщает о требуемой перезагрузке. Завершите установку, затем перезагрузите сервер.'
    fi
}

collect() {
    [[ -r /dev/tty ]] || die 'Нужен интерактивный терминал для домена и секретного ключа.'
    step '01 / Настройки вашей ноды'
    python3 "$WORK/runtime.py" collect --output "$WORK/rendered" < /dev/tty
}

check_ssh_collision() {
    local port=$1 effective='' listener='' session_port=''
    local config_file line keyword value configured_port socket_port
    if command -v sshd >/dev/null; then
        effective=$(sshd -T 2>/dev/null | awk '$1=="port" {print $2}' || true)
    fi
    [[ -z ${SSH_CONNECTION:-} ]] || session_port=${SSH_CONNECTION##* }
    listener=$(ss -H -ltnp "sport = :$port")
    if [[ $session_port == "$port" ]] || grep -Fxq "$port" <<< "$effective" || [[ $listener == *sshd* ]]; then
        die "Порт API $port совпадает с портом SSH. Выберите другой порт API; ограничивать SSH по IP панели нельзя."
    fi
    # Ubuntu 24.04 может передавать SSH-порт через systemd socket activation.
    while IFS= read -r socket_port; do
        [[ $socket_port != "$port" ]] || \
          die "Порт API $port используется ssh.socket. Выберите другой порт API."
    done < <(
        systemctl show ssh.socket --property=Listen --value 2>/dev/null | awk '
          {
            for (i=1; i<=NF; i++) {
              value=$i
              if (value ~ /^[0-9]+$/) print value
              else if (value ~ /\]:[0-9]+$/) {sub(/^.*\]:/, "", value); print value}
              else if (value ~ /:[0-9]+$/) {sub(/^.*:/, "", value); print value}
            }
          }' || true
    )
    for config_file in /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf; do
        [[ -r $config_file ]] || continue
        while IFS= read -r line; do
            line=${line%%#*}
            read -r keyword value _ <<< "$line" || true
            configured_port=''
            case "${keyword,,}" in
                port)
                    [[ $value =~ ^[0-9]+$ ]] && configured_port=$value;;
                listenaddress)
                    if [[ $value =~ ^\[[^]]+\]:([0-9]+)$ || $value =~ ^[^:]+:([0-9]+)$ ]]; then
                        configured_port=${BASH_REMATCH[1]}
                    fi;;
            esac
            [[ $configured_port != "$port" ]] || \
              die "Порт API $port указан в $config_file как порт SSH. Выберите другой порт API."
        done < "$config_file"
    done
}

preflight() {
    step '02 / Проверка сервера и DNS'
    local port other listeners
    port=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1],encoding="utf-8"))["node_port"])' "$WORK/rendered/settings.json")
    check_ssh_collision "$port"
    for other in 80 443 "$port"; do
        listeners=$(ss -H -ltn "sport = :$other") || die 'Не удалось прочитать список слушающих портов'
        [[ -z $listeners ]] || die "Порт $other уже занят. Установка рассчитана на отдельную свободную ноду."
    done
    ! command -v nginx >/dev/null || die 'На сервере уже установлен nginx. Автозамена сторонней конфигурации запрещена.'
    [[ ! -e /var/www/decoy ]] || die 'Каталог /var/www/decoy уже существует; его содержимое не перезаписывается.'
    for other in /opt/nuvrion-node /usr/local/lib/nuvrion-pokehabitat /var/lib/nuvrion-pokehabitat /etc/nuvrion-pokehabitat.env; do
        [[ ! -e $other && ! -L $other ]] || die "Путь $other уже существует; данные не перезаписываются."
    done
    ! id nuvrion-game >/dev/null 2>&1 || die 'Пользователь nuvrion-game уже существует; требуется разбор прежней установки.'
    python3 "$WORK/runtime.py" check-dns --settings "$WORK/rendered/settings.json"
    # Поддержка HTTP/2 проверяется до изменения конфигурации ноды.
    curl -V | awk '/Features:/ && /HTTP2/ {ok=1} END {exit !ok}' || die 'Требуется curl с поддержкой HTTP/2 из системных пакетов'
    check_nat
    for other in nuvrion-decoy.service nuvrion-acme-cleanup.service nuvrion-pokehabitat.service; do
        [[ ! -e /etc/systemd/system/$other && ! -L /etc/systemd/system/$other ]] || \
          die "Служба $other уже существует. Требуется разбор предыдущей установки"
    done
}

check_nat() {
    local rules command_name
    # На выделенной новой ноде неизвестные DNAT/REDIRECT требуют ручного
    # разбора: это также охватывает диапазоны, наборы портов и nft maps.
    for command_name in iptables ip6tables; do
        command -v "$command_name" >/dev/null || continue
        rules=$("$command_name" -t nat -S 2>/dev/null) || \
          die "Не удалось прочитать NAT через $command_name; отсутствие конфликтов не подтверждено"
        if grep -Eq -- '-j (REDIRECT|DNAT)( |$)' <<< "$rules"; then
            die 'Найдены правила NAT DNAT/REDIRECT. Проверьте их совместимость с новой нодой вручную'
        fi
    done
    rules=$(nft list ruleset 2>/dev/null) || die 'Не удалось прочитать nftables; проверка NAT остановлена'
    if grep -Eq '(^|[[:space:]])(redirect|dnat)([[:space:]]|$)' <<< "$rules"; then
        die 'Найдены правила nftables DNAT/REDIRECT. Проверьте их совместимость с новой нодой вручную'
    fi
}

install_docker() {
    step '03 / Docker и подготовка проекта'
    if ! command -v docker >/dev/null; then
        # Пакеты проверяются APT из официального подписанного репозитория Docker.
        local distro codename arch conflict_package source_file identity release
        identity=$(os_identity)
        IFS=: read -r distro release codename <<< "$identity"
        arch=$(dpkg --print-architecture)
        case "$distro:$codename" in ubuntu:jammy|ubuntu:noble|debian:bookworm|debian:trixie) ;;
            *) die 'Неизвестная ОС для официального Docker APT.';; esac
        for conflict_package in docker.io docker-compose docker-compose-v2 podman-docker containerd runc; do
            if package_installed "$conflict_package"; then
                die "Уже установлен $conflict_package. Настройте совместимый Docker/Compose отдельно; автоматического удаления пакетов нет."
            fi
        done
        install -d -m 755 /etc/apt/keyrings
        curl --proto '=https' --tlsv1.2 -fSL --retry 3 --connect-timeout 15 --max-time 90 \
          "https://download.docker.com/linux/$distro/gpg" -o "$WORK/docker.asc"
        gpg --batch --show-keys "$WORK/docker.asc" >/dev/null
        cat > "$WORK/nuvrion-docker.sources" <<EOF
Types: deb
URIs: https://download.docker.com/linux/$distro
Suites: $codename
Components: stable
Architectures: $arch
Signed-By: /etc/apt/keyrings/nuvrion-docker.asc
EOF
        for source_file in /etc/apt/sources.list /etc/apt/sources.list.d/*.list /etc/apt/sources.list.d/*.sources; do
            [[ -f $source_file && $source_file != /etc/apt/sources.list.d/nuvrion-docker.sources ]] || continue
            if grep -q 'download.docker.com/linux/' "$source_file"; then
                die 'Docker APT уже настроен другим файлом. Завершите установку Docker/Compose через существующий репозиторий.'
            fi
        done
        [[ ! -f /etc/apt/keyrings/nuvrion-docker.asc ]] || cmp -s "$WORK/docker.asc" /etc/apt/keyrings/nuvrion-docker.asc || die 'Ключ собственного Docker APT изменился; требуется проверка.'
        [[ ! -f /etc/apt/sources.list.d/nuvrion-docker.sources ]] || cmp -s "$WORK/nuvrion-docker.sources" /etc/apt/sources.list.d/nuvrion-docker.sources || die 'Конфигурация собственного Docker APT отличается.'
        install -m 644 "$WORK/docker.asc" /etc/apt/keyrings/nuvrion-docker.asc
        install -m 644 "$WORK/nuvrion-docker.sources" /etc/apt/sources.list.d/nuvrion-docker.sources
        apt-get -o DPkg::Lock::Timeout=600 update
        apt_confirmed install --no-install-recommends docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
    fi
    docker compose version >/dev/null || die 'Установите Docker Compose v2.'
    systemctl enable --now docker
    docker info >/dev/null
    local security
    security=$(docker info --format '{{json .SecurityOptions}}')
    [[ $security != *rootless* && $security != *userns* ]] || die 'Для прямого bind сертификатов и root:root сокетов нужен rootful Docker без userns-remap.'
    [[ $security == *apparmor* && $security == *seccomp* ]] || die 'Для этой сборки Docker должен поддерживать включённые AppArmor и seccomp.'
    local other
    other=$(docker ps -a --format '{{.Names}} {{.Image}}' | awk '$1=="remnanode" || $1=="nuvrion-decoy" || $2 ~ /remnawave\/node/ {print $1}')
    [[ -z $other ]] || die "На сервере уже есть контейнер ноды/decoy: $other. Автоудаление не выполняется."
}

prepare_stack() {
    step '04 / Образ ноды и два Unix-сокета'
    compose config -q
    timeout --foreground 900 docker compose --project-directory "$BASE" -f "$BASE/docker-compose.yml" pull
    local image digest
    image=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1],encoding="utf-8"))["services"]["remnanode"]["image"])' \
      "$BASE/docker-compose.yml")
    digest=$(docker image inspect "$image" --format '{{index .RepoDigests 0}}') || \
      die 'Не удалось получить digest загруженного образа ноды'
    [[ $digest =~ ^[^[:space:]@]+@sha256:[[:xdigit:]]{64}$ ]] || \
      die 'Загруженный образ ноды не содержит корректного SHA-256 digest'
    python3 - "$BASE/docker-compose.yml" "$digest" <<'PY'
import json,sys
from pathlib import Path
p=Path(sys.argv[1]);v=json.loads(p.read_text(encoding='utf-8'));digest=sys.argv[2]
assert '@sha256:' in digest,'Image digest missing'
v['services']['remnanode']['image']=digest
sys.path.insert(0,str(p.parent))
from runtime import json_write
json_write(p,v)
PY
    systemctl enable --now nuvrion-pokehabitat.service
    systemctl enable --now nuvrion-decoy.service
    ok 'Образ закреплён по digest; служба Unix-сайта запущена.'
}

apply_tuning() {
    step '05 / Продвинутая настройка и защита сервера'
    local port ips
    port=$(get_setting node_port); ips=$(get_setting panel_ips)
    # Порт тюнинга обязан совпадать с NODE_PORT.
    # Сертификатами управляет этот установщик: standalone ACME и временный TCP/80.
    # needrestart в режиме list: не перезапускать службы посреди тюнинга.
    NEEDRESTART_MODE=l NEEDRESTART_SUSPEND=1 \
    NUVRION_ASSUME_YES=1 NUVRION_PANEL_PORT="$port" NUVRION_PANEL_IPS="$ips" \
      NUVRION_SECURITY=1 NUVRION_HARDEN_SSH=0 \
      NUVRION_FIREWALL_PORTS='tcp:443' NUVRION_ENABLE_UFW=1 NUVRION_CERTIFICATES=0 \
      bash "$BASE/vendor/nuvrion-auto-tuning.sh" < /dev/null | tee "$BASE/tuning-report.log" | \
      python3 "$BASE/terminal_ui.py" filter
    # После тюнинга ограничения API проверяются повторно.
    ufw status | awk '/^Status: active$/ {ok=1} END {exit !ok}' || die 'Продвинутая настройка не активировала UFW. Проверьте её отчёт'
    python3 "$BASE/security_check.py" --firewall
    ok 'Продвинутая настройка завершена; ограничения API подтверждены.'
}

harden_host() {
    step '06 / Усиление защиты SSH и сетевых настроек'
    bash "$BASE/hardening.sh"
    install -m 700 "$BASE/nuvrion-two-way-ping.sh" /usr/local/sbin/nuvrion-two-way-ping.sh
    install -m 644 "$BASE/nuvrion-two-way-ping.service" /etc/systemd/system/nuvrion-two-way-ping.service
    systemctl daemon-reload
    systemctl enable --now nuvrion-two-way-ping.service
    check_two_way_ping
    ok 'Параметры SSH и системная защита применены и проверены.'
}

check_two_way_ping() {
    local rules
    [[ -x /usr/local/sbin/nuvrion-two-way-ping.sh ]] || \
      die 'Не найден исполняемый файл защиты от Two-Way Ping'
    systemctl is-enabled --quiet nuvrion-two-way-ping.service || \
      die 'Автозапуск защиты от Two-Way Ping не включён'
    systemctl is-active --quiet nuvrion-two-way-ping.service || \
      die 'Служба защиты от Two-Way Ping не активна'
    rules=$(nft list table inet nuvrion_privacy 2>/dev/null) || \
      die 'Таблица защиты от Two-Way Ping не загружена'
    [[ $rules == *'hook input'* &&
       $rules == *'Nuvrion: block ICMP echo'* &&
       $rules == *'Nuvrion: block ICMP timestamp'* &&
       $rules == *'Nuvrion: block ICMPv6 echo'* ]] || \
      die 'Правила защиты от Two-Way Ping загружены не полностью'
    ok 'Входящие ICMP echo и timestamp-запросы блокируются; остальные ICMP-сообщения разрешены.'
}

start_stack() {
    step '07 / Запуск API ноды после настройки защиты'
    python3 "$BASE/security_check.py" --firewall
    compose up -d
    wait_api
}

wait_api() {
    local port i state
    port=$(get_setting node_port)
    for ((i=0; i<45; i++)); do
        state=$(timeout 10 docker inspect -f '{{.State.Running}}' remnanode 2>/dev/null || printf 'false')
        if [[ $state == true ]] && [[ -n $(ss -H -ltn "sport = :$port") ]]; then
            ok "remnanode слушает API TCP/$port (mTLS)."
            return 0
        fi
        sleep 1
    done
    die "API TCP/$port не появился. Проверьте локально: docker logs --tail 80 remnanode. Не публикуйте ключ."
}

issue_certificate() {
    step '08 / Доверенный TLS-сертификат'
    local domain email
    domain=$(get_setting domain); email=$(get_setting email)
    [[ -z $(ss -H -ltn 'sport = :80') ]] || die 'Порт 80 занят: Certbot standalone не может начать проверку.'
    install -d /etc/letsencrypt/renewal-hooks/{pre,post,deploy}
    install -m 755 "$BASE/acme-pre.sh" /etc/letsencrypt/renewal-hooks/pre/90-nuvrion-vision
    install -m 755 "$BASE/acme-post.sh" /etc/letsencrypt/renewal-hooks/post/90-nuvrion-vision
    ACME_OPEN=1
    "$BASE/acme-firewall.sh" open
    timeout --foreground 600 certbot certonly --standalone --preferred-challenges http --cert-name "$domain" -d "$domain" \
      --non-interactive --agree-tos --email "$email" --keep-until-expiring
    "$BASE/acme-firewall.sh" close
    ACME_OPEN=0
    openssl x509 -in "/etc/letsencrypt/live/$domain/fullchain.pem" -checkhost "$domain" -noout
    openssl x509 -in "/etc/letsencrypt/live/$domain/fullchain.pem" -checkend 86400 -noout
    install -m 755 "$BASE/renew-hook.sh" /etc/letsencrypt/renewal-hooks/deploy/90-nuvrion-vision
    systemctl enable --now certbot.timer
    # Скрипт firewall идемпотентен: open сначала удаляет только собственные
    # правила, а close допускает повторный вызов из Certbot post-hook.
    # Проверка staging не устанавливает тестовый сертификат вместо рабочего.
    ACME_OPEN=1
    "$BASE/acme-firewall.sh" open
    timeout --foreground 600 certbot renew --cert-name "$domain" --dry-run --no-random-sleep-on-renew
    "$BASE/acme-firewall.sh" close
    ACME_OPEN=0
    ok 'Сертификат и пробное продление проверены; временный порт 80 закрыт.'
}

traffic_control_report() {
    say '  Проверка Nuvrion Traffic Control'
    check_traffic_control
    /usr/local/bin/nuvrion-traffic-control status
    ok 'Фильтрация по трём внешним спискам включена.'
    ok 'Автовосстановление правил и ежедневное обновление списков работают.'
    ok 'Nuvrion Traffic Control установлен последним и полностью проверен.'
}

check_traffic_control() {
    [[ -x /usr/local/bin/nuvrion-traffic-control ]] || die 'Не найден основной файл Nuvrion Traffic Control.'
    [[ -x /usr/local/bin/ntc ]] || die 'Не найдена короткая команда ntc.'
    nft list table inet nuvrion_tc >/dev/null 2>&1 || die 'Таблица фильтрации Nuvrion Traffic Control не загружена.'
    systemctl is-enabled --quiet nuvrion-traffic-control.service || die 'Автовосстановление правил Nuvrion Traffic Control не включено.'
    systemctl is-active --quiet nuvrion-traffic-control-update.timer || die 'Таймер обновления списков Nuvrion Traffic Control не активен.'
    /usr/local/bin/nuvrion-traffic-control check
}

install_traffic_control() {
    step '09 / Nuvrion Traffic Control'
    local marker="$BASE/.traffic-control-choice" choice=''
    [[ -f $marker ]] && choice=$(<"$marker")
    case "$choice" in
        installed)
            traffic_control_report
            return;;
        skipped)
            skip 'Nuvrion Traffic Control пропущен по вашему выбору.'
            return;;
        installing)
            if [[ ! -x /usr/local/bin/nuvrion-traffic-control || ! -f /var/lib/nuvrion-traffic-control/state.json ]]; then
                die 'Предыдущая установка Nuvrion Traffic Control прервалась. Проверьте её состояние перед продолжением.'
            fi
            if [[ -f /var/lib/nuvrion-traffic-control/enabled ]]; then
                /usr/local/bin/nuvrion-traffic-control repair --yes
            else
                /usr/local/bin/nuvrion-traffic-control activate
            fi
            printf '%s\n' installed > "$marker"
            traffic_control_report
            return;;
        '') ;;
        *) die 'Повреждена отметка выбора Nuvrion Traffic Control.';;
    esac

    if [[ -e /usr/local/bin/nuvrion-traffic-control || -e /usr/local/bin/ntc || \
          -e /var/lib/nuvrion-traffic-control/state.json ]] || nft list table inet nuvrion_tc >/dev/null 2>&1; then
        die 'На сервере уже есть Nuvrion Traffic Control или его данные. Автоперезапись существующей установки запрещена.'
    fi

    say '  Компонент загрузит три внешних списка блокировок и применит их через nftables.'
    say '  IP администратора и панели будут добавлены в исключения после вашего подтверждения.'
    say '  SSH-порт не блокируется правилами списков.'
    if ! ask_yes 'Установить и включить Nuvrion Traffic Control?'; then
        printf '%s\n' skipped > "$marker"
        skip 'Nuvrion Traffic Control пропущен. Установка Vision продолжается.'
        return
    fi

    printf '%s\n' installing > "$marker"
    SSH_CONNECTION="${SSH_CONNECTION:-}" python3 -u -c '
import importlib.util, json, os, sys
from pathlib import Path
path = sys.argv[1]
settings_path = Path(sys.argv[2])
spec = importlib.util.spec_from_file_location("nuvrion_traffic_control", path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
args = ["install", "--yes"]
connection = os.environ.get("SSH_CONNECTION", "").split()
if len(connection) == 4:
    admin_ip = module.host(connection[0])
    ssh_port = str(module.port_list(connection[3])[0])
    settings = json.loads(settings_path.read_text(encoding="utf-8"))
    panel_ips = module.ip_list(settings["panel_ips"])
    allowed = sorted(set([admin_ip, *panel_ips]))
    args += ["--ssh-port", ssh_port]
    for address in allowed:
        args += ["--allow", address]
    module.info("Автоматически использованы параметры текущего SSH-подключения и ранее введённые IP панели.")
    module.info("SSH: " + ssh_port + "; исключения IP: " + ", ".join(allowed))
else:
    module.warn("Текущее SSH-подключение не определено; подтвердите предложенные параметры вручную.")
sys.exit(1 if module.main(args) else 0)
' "$BASE/nuvrion-traffic-control.py" "$BASE/settings.json" < /dev/tty | tee "$BASE/traffic-control-install.log"
    /usr/local/bin/nuvrion-traffic-control activate
    printf '%s\n' installed > "$marker"
    traffic_control_report
}

probe_http() {
    local label=$1 result
    shift
    result=$(curl --noproxy '*' -sS --connect-timeout 5 --max-time 35 "$@") || \
      die "Не удалось выполнить проверку: $label (ошибка соединения, TLS или превышено время ожидания)"
    printf '%s' "$result"
}

check_site_response() {
    local response=$1 protocol=$2
    if [[ $protocol == h1 ]]; then
        [[ $response == 200 ]] || die 'Неверный ответ HTTP/1.1 автономного сайта.'
    else
        [[ $response == 200:2 ]] || die 'Неверный ответ HTTP/2 автономного сайта.'
    fi
}

wait_game_api() {
    local attempt response
    # Type=simple becomes active before Node has opened SQLite and its socket.
    # At most ten bounded probes; never restart the game or other services here.
    for ((attempt=0; attempt<10; attempt++)); do
        if systemctl is-active --quiet nuvrion-pokehabitat.service && \
           response=$(curl --noproxy '*' -sS --connect-timeout 1 --max-time 2 \
             --unix-socket /run/nuvrion-pokehabitat/game.sock \
             -o /dev/null -w '%{http_code}' http://localhost/api/game/me 2>/dev/null) && \
           [[ $response == 200 ]]; then
            return 0
        fi
        if ((attempt<9)); then sleep 1; fi
    done
    die 'Локальный игровой API не отвечает. Проверьте: journalctl -u nuvrion-pokehabitat.service -n 60 --no-pager.'
}

check() {
    [[ -f $BASE/.nuvrion-managed && -f $BASE/settings.json ]] || die 'Установка Nuvrion не найдена.'
    step 'Проверка конфигурации и работающих компонентов'
    compose config -q
    nginx -t -c "$BASE/nginx.conf"
    systemctl is-active --quiet nuvrion-decoy.service
    wait_game_api
    wait_api
    docker exec -i remnanode sh < "$BASE/check-nofile.sh"
    local domain socket_name h1 h2 legacy_port
    domain=$(get_setting domain)
    for socket_name in h1 h2; do
        [[ -S $BASE/fallback-sockets/$socket_name.sock ]] || die "Нет сокета $socket_name.sock."
    done
    h1=$(probe_http 'сокет HTTP/1.1' --unix-socket "$BASE/fallback-sockets/h1.sock" -o /dev/null -w '%{http_code}' http://localhost/) || exit 1
    check_site_response "$h1" h1
    curl -V | awk '/Features:/ && /HTTP2/ {ok=1} END {exit !ok}' || die 'Требуется curl с поддержкой HTTP/2 из системных пакетов'
    h2=$(probe_http 'сокет HTTP/2' --http2-prior-knowledge --unix-socket "$BASE/fallback-sockets/h2.sock" -o /dev/null -w '%{http_code}:%{http_version}' http://localhost/) || exit 1
    check_site_response "$h2" h2
    docker exec remnanode xray run -test -config /opt/nuvrion/profile.json
    systemctl is-active --quiet certbot.timer
    python3 "$BASE/security_check.py"
    check_two_way_ping
    case "$(cat "$BASE/.traffic-control-choice" 2>/dev/null || true)" in
        installed)
            check_traffic_control
            ok 'Nuvrion Traffic Control, его правила и таймер обновлений активны.';;
        skipped) skip 'Nuvrion Traffic Control пропущен по вашему выбору.';;
        *) die 'Не найден результат этапа Nuvrion Traffic Control.';;
    esac
    [[ -z $(ss -H -ltnp | awk '/nginx/') ]] || die 'nginx неожиданно слушает TCP. Эталон допускает только Unix sockets.'
    for legacy_port in 8080 8081 18080 18081; do
        [[ -z $(ss -H -ltn "sport = :$legacy_port") ]] || die "Найден старый fallback-порт $legacy_port."
    done
    ok 'JSON принят Xray; категории geodata и сертификаты читаются; h1/h2 отвечают.'
    if [[ -z $(ss -H -ltn 'sport = :443') ]]; then
        warn 'Ожидание: примените профиль к ноде в панели. Сквозная проверка TLS/443 ещё не выполнена.'
        exit 2
    fi
    h1=$(probe_http 'TLS/443 HTTP/1.1' --resolve "$domain:443:127.0.0.1" --tlsv1.3 --http1.1 -o /dev/null -w '%{http_code}' "https://$domain/") || exit 1
    h2=$(probe_http 'TLS/443 HTTP/2' --resolve "$domain:443:127.0.0.1" --tlsv1.3 --http2 -o /dev/null -w '%{http_code}:%{http_version}' "https://$domain/") || exit 1
    check_site_response "$h1" h1
    check_site_response "$h2" h2
    if curl --noproxy '*' --resolve "$domain:443:127.0.0.1" --tlsv1.2 --tls-max 1.2 --http1.1 -sS --max-time 10 -o /dev/null "https://$domain/" 2>/dev/null; then
        die 'Порт 443 принимает TLS 1.2. Проверьте минимальную версию TLS в активном профиле панели.'
    fi
    ok 'TLS/443 → HTTP/1.1 и HTTP/2: транспорт, доверенная цепочка и имя сертификата проверены.'
    ok 'Проверочное подключение с TLS 1.2 отклонено.'
    warn 'Доступ из Интернета, связь с панелью и VLESS с реальным пользователем проверьте отдельно.'
}

installation_report() {
    python3 "$BASE/component_report.py" "$1"
}

show_result() {
    [[ -r $BASE/vision-config-profile.json && -r $BASE/host-settings.txt ]] || \
      die "Готовые профиль и настройки хоста не найдены в $BASE."
    step 'Готовый профиль ноды — вставьте в Remnawave'
    warn 'Ниже выводится профиль с доменом и путями сертификатов. Не публикуйте его, если добавили личные данные'
    cat "$BASE/vision-config-profile.json"
    step 'Настройки хоста — укажите в Remnawave'
    cat "$BASE/host-settings.txt"
}

publish_project() {
    local name
    local -a managed=(runtime.py renew-hook.sh acme-firewall.sh acme-pre.sh acme-post.sh
        check-nofile.sh hardening.sh security_check.py nuvrion-traffic-control.py
        nuvrion-two-way-ping.sh nuvrion-two-way-ping.service
        terminal_ui.py component_report.py site-install.py)
    [[ ! -e $BASE && ! -L $BASE ]] || die "Каталог $BASE уже существует; публикация отменена"
    # До атомарного переименования BASE не существует. Обычная ошибка удаляет
    # только этот временный каталог; SIGKILL оставляет безопасный staging-снимок.
    STAGING=$(mktemp -d "${BASE}.staging.XXXXXX")
    for name in settings.json vision-config-profile.json docker-compose.yml node.env host-settings.txt; do
        install -m 600 "$WORK/rendered/$name" "$STAGING/$name"
    done
    install -m 644 "$WORK/rendered/nginx.conf" "$STAGING/nginx.conf"
    for name in "${managed[@]}"; do
        install -m 600 "$WORK/$name" "$STAGING/$name"
    done
    chmod 700 "$STAGING/"*.sh
    install -d -m 700 "$STAGING/vendor" "$STAGING/bootstrap"
    install -m 600 "$WORK/nuvrion-auto-tuning.sh" "$STAGING/vendor/nuvrion-auto-tuning.sh"
    for name in decoy.html nuvrion-decoy.service nuvrion-acme-cleanup.service nuvrion-pokehabitat.service; do
        install -m 600 "$WORK/$name" "$STAGING/bootstrap/$name"
    done
    cp -a "$WORK/pokehabitat" "$STAGING/bootstrap/pokehabitat"
    install -m 700 "$WORK/installer-manager.sh" "$STAGING/installer.sh"
    printf '%s\n' "$NUVRION_VERSION" > "$STAGING/.nuvrion-managed"
    printf '%s\n' pending > "$STAGING/.bootstrap-pending"
    python3 - "$STAGING" "$BASE" <<'PY'
import os,sys
from pathlib import Path
staging,base=map(Path,sys.argv[1:])
if base.exists() or base.is_symlink():
    sys.exit('  ✗ ОШИБКА: каталог ноды уже существует; публикация отменена')
for root,dirs,files in os.walk(staging,topdown=False):
    for name in files:
        with open(Path(root)/name,'rb') as f:
            os.fsync(f.fileno())
    fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY)
    try: os.fsync(fd)
    finally: os.close(fd)
os.rename(staging,base)
fd=os.open(base.parent,os.O_RDONLY|os.O_DIRECTORY)
try: os.fsync(fd)
finally: os.close(fd)
PY
    STAGING=''
}

install_site_runtime() {
    local arch checksum version=v24.19.0
    if [[ -x /opt/nuvrion-node/bin/node ]]; then
        [[ $(/opt/nuvrion-node/bin/node --version) == "$version" ]] || die 'Сохранённая версия Node.js не совпала с закреплённой.'
        return 0
    fi
    case "$(uname -m)" in
        x86_64) arch=x64; checksum=14b342e71204f811bde6153be8e04b62aef63c236fef92b55f9c83154b409647;;
        aarch64) arch=arm64; checksum=01443c1e1a29e531ccad5a46fefa6df490d2189c49f7955904aecdbb0fe86fdc;;
        *) die 'Нет автономного игрового runtime для этой архитектуры.';;
    esac
    install -d -m 700 "$BASE/bootstrap/node-runtime"
    curl --proto '=https' --tlsv1.2 -fSL --retry 3 --connect-timeout 15 --max-time 180 \
        "https://nodejs.org/dist/$version/node-$version-linux-$arch.tar.xz" \
        -o "$BASE/bootstrap/node-runtime/node.tar.xz"
    printf '%s  %s\n' "$checksum" "$BASE/bootstrap/node-runtime/node.tar.xz" | sha256sum -c --status - || \
        die 'Контрольная сумма Node.js не совпала; установка остановлена.'
    install -d -m 755 /opt/nuvrion-node/bin
    tar -xJf "$BASE/bootstrap/node-runtime/node.tar.xz" -C "$BASE/bootstrap/node-runtime" \
        --no-same-owner "node-$version-linux-$arch/bin/node" "node-$version-linux-$arch/LICENSE"
    install -m 755 "$BASE/bootstrap/node-runtime/node-$version-linux-$arch/bin/node" /opt/nuvrion-node/bin/node
    install -m 644 "$BASE/bootstrap/node-runtime/node-$version-linux-$arch/LICENSE" /opt/nuvrion-node/LICENSE
    /opt/nuvrion-node/bin/node --version
}

install_game_site() {
    install_site_runtime
    if ! id nuvrion-game >/dev/null 2>&1; then
        useradd --system --gid www-data --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin nuvrion-game
    fi
    python3 "$BASE/site-install.py" "$BASE"
}

bootstrap_project() {
    [[ -f $BASE/.bootstrap-pending ]] || return 0
    local name nginx_version
    say '  Завершение сохранённой подготовки проекта'
    for name in decoy.html nuvrion-decoy.service nuvrion-acme-cleanup.service nuvrion-pokehabitat.service; do
        [[ -f $BASE/bootstrap/$name && ! -L $BASE/bootstrap/$name ]] || \
          die "Не найден сохранённый файл подготовки: $name. Автопродолжение невозможно"
    done
    # Секреты/код: root 0600/0700. Публичный сайт/nginx.conf: 0644.
    # Сокеты: root:root 0660, их каталог: 0755; родитель BASE остаётся 0700.
    # nginx-мастер открывает сокеты от root, рабочие процессы наследуют их;
    # контейнер обращается через отдельный bind-mount каталога сокетов.
    install -d -m 755 /var/www/decoy "$BASE/fallback-sockets"
    apt_confirmed install --no-install-recommends nginx
    install_game_site
    systemctl disable --now nginx
    systemctl mask nginx.service
    nginx_version=$(nginx -v 2>&1 | sed -n 's@.*nginx/\([0-9.]*\).*@\1@p')
    [[ $nginx_version =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die 'Не удалось определить версию nginx'
    python3 - "$BASE" "$nginx_version" <<'PY'
import json,sys
from pathlib import Path
base=Path(sys.argv[1]);sys.path.insert(0,str(base))
from runtime import nginx,json_write,write
s=json.loads((base/'settings.json').read_text(encoding='utf-8'));s['nginx_version']=sys.argv[2];s.pop('decoy_resolvers',None)
json_write(base/'settings.json',s);write(base/'nginx.conf',nginx(s),0o644)
PY
    for name in nuvrion-decoy.service nuvrion-acme-cleanup.service nuvrion-pokehabitat.service; do
        install -m 644 "$BASE/bootstrap/$name" "/etc/systemd/system/$name"
    done
    systemctl daemon-reload
    systemctl enable nuvrion-acme-cleanup.service
    # Отметка удаляется только после завершения всех подготовительных действий.
    python3 - "$BASE/.bootstrap-pending" <<'PY'
import os,sys
from pathlib import Path
p=Path(sys.argv[1]);p.unlink()
fd=os.open(p.parent,os.O_RDONLY|os.O_DIRECTORY)
try: os.fsync(fd)
finally: os.close(fd)
PY
}

main() {
    local action
    if (( $# == 0 )); then
        if declare -F payload >/dev/null; then action=--install; else action=--help; fi
    else
        action=$1
    fi
    if [[ $action != --render ]] && (( $# > 1 )); then
        die "Команда $action не принимает дополнительные аргументы"
    fi
    case "$action" in
        --version) say "$NUVRION_VERSION"; return;;
        --help|-h)
            if declare -F payload >/dev/null; then
                cat <<'EOF'
Nuvrion Vision Installer:
  --install                         установить Nuvrion Vision Installer
  --resume                          продолжить незавершённую установку
  --check                           проверить установленные компоненты
                                    код 2 означает ожидание профиля TLS/443
  --show                            показать профиль ноды и настройки хоста
  --preview                         показать вступление без установки
  --version                         показать версию установщика
  --render ФАЙЛ_НАСТРОЕК КАТАЛОГ    создать пример без установки

Коды: 0 — успех; 1 — ошибка; 2 — установка/проверка ожидает профиля TLS/443;
130 — прерывание пользователем; 143 — завершение сигналом TERM
EOF
            else
                cat <<'EOF'
Локальный менеджер Nuvrion Vision:
  --resume    продолжить незавершённую установку
  --check     проверить компоненты; код 2 означает ожидание профиля TLS/443
  --show      показать профиль ноды и настройки хоста
  --preview   показать вступление
  --version   показать версию установщика

Коды: 0 — успех; 1 — ошибка; 2 — ожидание профиля TLS/443;
130 — прерывание пользователем; 143 — завершение сигналом TERM

Для новой установки и --render используйте исходный самодостаточный файл.
EOF
            fi
            return;;
        --preview) banner; return;;
        --render)
            [[ $# == 3 ]] || die 'Нужно: --render settings.json новый_каталог'
            declare -F payload >/dev/null || \
              die 'Команда --render доступна только в исходном самодостаточном установщике.'
            [[ -r $2 ]] || die 'Файл настроек не найден или недоступен для чтения.'
            [[ ! -e $3 ]] || die 'Каталог вывода уже существует.'
            unpack
            python3 "$WORK/runtime.py" render --settings "$2" --output "$3"
            cp -a "$WORK/pokehabitat" "$3/pokehabitat"
            ok "Профиль и настройки созданы в $3. Установка не выполнялась."
            return;;
        --install|--resume|--check|--show) ;;
        *) die "Неизвестный аргумент: $action";;
    esac
    if [[ $action == --install ]] && ! declare -F payload >/dev/null; then
        die 'Новая установка доступна только из исходного самодостаточного файла.'
    fi
    if [[ $action == --install ]]; then
        banner
        [[ -r /dev/tty ]] || die 'Запустите из интерактивного терминала.'
        if ! confirm_install; then
            skip 'Установка отменена. Настройки сервера не изменены.'
            return
        fi
    fi
    require_server
    exec 9>/run/nuvrion-vision.lock
    flock -n 9 || die 'Другой экземпляр уже работает.'
    case "$action" in
        --show) show_result; return;;
        --check)
            local check_rc=0 report_rc=0
            bash "$BASE/installer.sh" --check-internal || check_rc=$?
            if [[ -f $BASE/component_report.py ]]; then
                installation_report "$check_rc" || report_rc=$?
            fi
            (( report_rc == 0 )) || exit 1
            exit "$check_rc";;
        --resume)
            [[ -f $BASE/.nuvrion-managed ]] || die 'Нет незавершённой установки Nuvrion.'
            [[ $(cat "$BASE/.nuvrion-managed") == "$NUVRION_VERSION" ]] || \
              die 'Версия установленного комплекта отличается. --resume не выполняет миграцию между версиями.'
            [[ -f $BASE/component_report.py && -f $BASE/terminal_ui.py ]] || \
              die 'На сервере сохранена другая ревизия комплекта. Используйте её локальный менеджер: bash /opt/remnanode/installer.sh --resume. Автоматическое обновление не выполняется.'
            if [[ -f $BASE/.installation-complete ]]; then
                say '  Установка уже завершена. Выполняется только проверка; настройки не меняются.'
                # Родитель уже держит flock: не запускать публичный --check повторно.
                local completed_rc=0
                bash "$BASE/installer.sh" --check-internal || completed_rc=$?
                installation_report "$completed_rc" || exit 1
                show_result
                exit "$completed_rc"
            fi
            say '  Возобновление с сохранённым доменом и секретом.'
            check_ssh_collision "$(get_setting node_port)"
            python3 "$BASE/runtime.py" check-dns --settings "$BASE/settings.json"
            ;;
        --install)
            [[ ! -e $BASE && ! -L $BASE ]] || \
              die "Каталог $BASE уже существует. Для управляемой установки используйте --resume. Без маркера — ручной разбор; ничего не удаляйте вслепую"
            prepare_system_packages
            unpack
            collect
            preflight
            install_docker
            publish_project
            ;;
    esac
    bootstrap_project
    prepare_stack
    # Firewall и тюнинг завершаются до первого запуска API.
    apply_tuning
    harden_host
    start_stack
    issue_certificate
    # Фильтрация по внешним спискам включается последней, после всех загрузок
    # и первичного ACME-цикла. Итоговая проверка подтверждает её состояние.
    install_traffic_control
    local rc=0
    # Отдельный процесс сохраняет строгий режим ошибок во всех проверках.
    step 'ИТОГИ УСТАНОВКИ / Проверка компонентов'
    bash "$BASE/installer.sh" --check-internal || rc=$?
    if [[ $rc != 0 && $rc != 2 ]]; then
        installation_report "$rc" || true
        die 'Итоговая проверка не прошла.'
    fi
    systemd-analyze security nuvrion-decoy.service --no-pager > "$BASE/service-security-report.txt" 2>&1 || skip 'Оценка systemd-analyze недоступна; обязательные параметры проверены отдельно.'
    if [[ $rc == 2 ]]; then
        warn 'Примените профиль в панели: сквозная проверка TLS/443 ещё ожидает выполнения.'
    else
        ok 'Локальные проверки компонентов и TLS/443 пройдены.'
    fi
    warn 'Подключение настоящим VLESS-клиентом и доступ извне проверяются отдельно.'
    installation_report "$rc" || die 'Отчёт обнаружил неисправные компоненты.'
    printf '%s\n' "$NUVRION_VERSION" > "$BASE/.installation-complete"
    show_result
    say "Файлы: $BASE · повторная проверка: bash $BASE/installer.sh --check"
    # exit, а не return: ожидаемое состояние не должно запускать ERR-ловушку.
    exit "$rc"
}

# Private child entry
# Внутренняя проверка не захватывает блокировку родительского процесса повторно.
if [[ ${1:-} == --check-internal ]]; then
    (( $# == 1 )) || die 'Внутренняя проверка не принимает дополнительные аргументы'
    require_server
    check
else
    main "$@"
fi
exit 0
