#!/usr/bin/env python3
# Nuvrion · release 1.0.0
"""Read-only checks. Never request Docker environment or print node credentials."""
import ipaddress
import grp
import json
from pathlib import Path
import re
import stat
import subprocess
import sys

BASE = Path('/opt/remnanode')


class CheckFailure(Exception):
    """Only explicitly authored, credential-free diagnostics."""


def need(condition, message):
    if not condition:
        raise CheckFailure(message)


def capture(*args):
    p = subprocess.run(args, capture_output=True, text=True, timeout=30)
    if p.returncode:
        raise CheckFailure(f'Не удалось выполнить проверку: {args[0]}.')
    return p.stdout.strip()


def firewall(text, port, panel_ips):
    need('Status: active' in text, 'UFW не активен.')
    need('deny (incoming)' in text and 'deny (routed)' in text, 'Неверная политика UFW.')
    allowed = set(map(ipaddress.ip_address, panel_ips.split()))
    seen = set()
    for line in text.splitlines():
        parts = re.split(r'\s{2,}', line.strip())
        if len(parts) < 3 or not parts[1].startswith(('ALLOW', 'LIMIT')):
            continue
        target, action, source = parts[:3]
        if 'OUT' in action:
            continue
        target = target.replace(' (v6)', '')
        source = source.split(' #')[0].replace(' (v6)', '')
        if target == 'OpenSSH':
            continue
        if '/' in target:
            ports, proto = target.split('/', 1)
            if proto == 'udp':
                continue
            need(proto == 'tcp', 'Неизвестный протокол правила UFW.')
        else:
            ports = target
        def matches(p):
            if ports == 'Anywhere':
                return True
            for spec in ports.split(','):
                bounds = spec.split(':')
                need(all(x.isdigit() for x in bounds) and len(bounds) <= 2,
                     'Нераспознанное разрешающее правило UFW: проверьте локально ufw status verbose.')
                if int(bounds[0]) <= p <= int(bounds[-1]):
                    return True
            return False
        need(not matches(80), 'TCP/80 постоянно разрешён в UFW. Удалите только подтверждённое лишнее правило.')
        if matches(port):
            try:
                addr = ipaddress.ip_address(source)
            except ValueError:
                raise CheckFailure('API разрешён для сети/любого адреса вместо отдельных IP панели.') from None
            need(addr in allowed, 'API разрешён постороннему IP.')
            seen.add(addr)
    need(seen == allowed, 'Не найдены все разрешения API для IP панели.')


def check_firewall():
    s = json.loads((BASE/'settings.json').read_text(encoding='utf-8'))
    firewall(capture('ufw', 'status', 'verbose'), s['node_port'], s['panel_ips'])
    print('✓ UFW: API ограничен IP панели; постоянного разрешения TCP/80 нет.')


def check():
    s = json.loads((BASE/'settings.json').read_text(encoding='utf-8'))
    for name, mode in [('', 0o700), ('settings.json', 0o600), ('node.env', 0o600),
                       ('vision-config-profile.json', 0o600), ('docker-compose.yml', 0o600)]:
        path = BASE/name
        need(not path.is_symlink(), 'Служебный файл неожиданно является ссылкой.')
        info = path.stat()
        need(info.st_uid == 0 and info.st_gid == 0 and stat.S_IMODE(info.st_mode) == mode,
             f'Неверные права или владелец: {path.name}.')
    for name in ('h1.sock', 'h2.sock'):
        st = (BASE/'fallback-sockets'/name).lstat()
        need(stat.S_ISSOCK(st.st_mode) and stat.S_IMODE(st.st_mode) == 0o660
             and st.st_uid == 0 and st.st_gid == 0, 'Неверные права Unix-сокета.')
    st = (BASE/'fallback-sockets').stat()
    need(not st.st_mode & 0o022, 'Каталог сокетов доступен на запись другим пользователям.')
    print('✓ Секретные файлы и Unix-сокеты: права и владельцы проверены.')
    le = Path('/etc/letsencrypt')
    key = (le/'live'/s['domain']/'privkey.pem').stat()
    need(key.st_uid == 0 and key.st_gid == 0 and stat.S_IMODE(key.st_mode) == 0o600,
         'Приватный ключ сертификата должен иметь права root:root 0600.')
    for folder in ('live', 'archive'):
        st = (le/folder).stat()
        need(st.st_uid == 0 and not st.st_mode & 0o077, 'Каталоги сертификатов доступны обычным пользователям.')
    print('✓ Приватный ключ сертификата и каталоги Let’s Encrypt защищены.')
    fmt = '{{json .HostConfig}}'
    host = json.loads(capture('docker', 'inspect', '-f', fmt, 'remnanode'))
    need(not host['Privileged'], 'Контейнер запущен с privileged=true.')
    opts = host.get('SecurityOpt') or []
    need(any(x in ('no-new-privileges', 'no-new-privileges:true', 'no-new-privileges=true') for x in opts),
         'В контейнере не включён no-new-privileges.')
    need(set(host.get('CapAdd') or []) & {'NET_ADMIN', 'CAP_NET_ADMIN'}, 'Отсутствует согласованная capability NET_ADMIN.')
    need(not any(x.startswith('seccomp=') or x.startswith('seccomp:') for x in opts),
         'Изменён стандартный профиль seccomp контейнера.')
    need(capture('docker', 'inspect', '-f', '{{.AppArmorProfile}}', 'remnanode') == 'docker-default',
         'Не применён AppArmor docker-default.')
    pid = int(capture('docker', 'inspect', '-f', '{{.State.Pid}}', 'remnanode'))
    need(pid > 0, 'Контейнер не запущен.')
    need(Path(f'/proc/{pid}/attr/current').read_text(encoding='utf-8').strip() == 'docker-default (enforce)',
         'AppArmor контейнера не в режиме enforce.')
    status = Path(f'/proc/{pid}/status').read_text(encoding='utf-8')
    need(re.search(r'^NoNewPrivs:\s+1$', status, re.M) and re.search(r'^Seccomp:\s+2$', status, re.M),
         'Не подтверждены NoNewPrivs/seccomp процесса контейнера.')
    image = capture('docker', 'inspect', '-f', '{{.Config.Image}}', 'remnanode')
    need('@sha256:' in image, 'Образ ноды не закреплён по digest.')
    mounts = json.loads(capture('docker','inspect','-f','{{json .Mounts}}','remnanode'))
    for destination in ('/etc/letsencrypt', '/run/xray-fallback', '/opt/nuvrion/profile.json'):
        need(any(m['Destination'] == destination and not m['RW'] for m in mounts), 'Неверный режим монтирования файлов ноды.')
    print('✓ Контейнер: no-new-privileges, AppArmor, seccomp, NET_ADMIN и образ проверены.')
    st = Path('/var/run/docker.sock').stat()
    need(stat.S_ISSOCK(st.st_mode) and stat.S_IMODE(st.st_mode) == 0o660
         and st.st_uid == 0 and st.st_gid == grp.getgrnam('docker').gr_gid,
         'Неверные права Docker socket: ожидается root:docker 0660.')
    listeners = capture('ss', '-H', '-lntup')
    need(not re.search(r'"(?:nginx|dockerd)"', listeners), 'nginx или Docker слушает TCP/UDP.')
    for p in (2375, 2376):
        need(not capture('ss','-H','-ltn',f'sport = :{p}'), f'Найден TCP listener на {p}.')
    check_firewall()
    for key, value in [('net.ipv4.tcp_congestion_control','bbr'), ('net.core.default_qdisc','fq'),
                       ('net.ipv4.tcp_fastopen','3')]:
        need(capture('sysctl','-n',key) == value, f'Не совпадает настройка {key}.')
    print('✓ BBR, fq и системная настройка TCP Fast Open проверены.')
    for prop, expected in [('NoNewPrivileges','yes'), ('ProtectSystem','strict'), ('PrivateTmp','yes'),
                           ('PrivateDevices','yes'), ('ProtectHome','yes'), ('ProtectKernelTunables','yes'),
                           ('ProtectKernelModules','yes'), ('ProtectControlGroups','yes'),
                           ('RestrictSUIDSGID','yes'), ('RestrictRealtime','yes'), ('LockPersonality','yes')]:
        need(capture('systemctl','show','nuvrion-decoy.service',f'--property={prop}','--value') == expected,
             f'Не применена защита nginx: {prop}.')
    for unit in ('nuvrion-decoy.service', 'nuvrion-pokehabitat.service'):
        families = set(capture('systemctl','show',unit,'--property=RestrictAddressFamilies','--value').split())
        need(families == {'AF_UNIX'}, f'Не применён запрет TCP/UDP: {unit}.')
    need(capture('systemctl','show','nuvrion-pokehabitat.service','--property=User','--value') == 'nuvrion-game',
         'Игровой API должен работать отдельным непривилегированным пользователем.')
    game_socket = Path('/run/nuvrion-pokehabitat/game.sock').lstat()
    need(stat.S_ISSOCK(game_socket.st_mode) and stat.S_IMODE(game_socket.st_mode) == 0o660,
         'Неверные права игрового Unix-сокета.')
    auth = Path('/etc/nuvrion-pokehabitat.env').lstat()
    need(stat.S_ISREG(auth.st_mode) and stat.S_IMODE(auth.st_mode) == 0o600 and auth.st_uid == 0,
         'Неверные права локального секрета игры.')
    print('✓ Автономный сайт и игра изолированы: только Unix-сокеты, без исходящего TCP/UDP.')
    for unit in ('docker.service', 'nuvrion-decoy.service', 'nuvrion-pokehabitat.service', 'certbot.timer', 'fail2ban.service'):
        need(capture('systemctl', 'is-active', unit) == 'active', f'Не активна служба {unit}.')
        need(capture('systemctl', 'is-enabled', unit) == 'enabled', f'Не включён автозапуск {unit}.')
    capture('fail2ban-client', 'status', 'sshd')
    print('✓ Автозапуск служб, таймер сертификата и SSH-защита Fail2ban проверены.')


if __name__ == '__main__':
    try:
        if sys.argv[1:] == ['--firewall']:
            check_firewall()
        elif not sys.argv[1:]:
            check()
        else:
            raise CheckFailure('Неизвестный режим проверки.')
    except CheckFailure as e:
        print(f'✗ {e}', file=sys.stderr)
        sys.exit(1)
    except (ValueError, OSError, KeyError, subprocess.TimeoutExpired):
        # Exception text could contain file contents from a damaged JSON; keep
        # the automatic report free of credentials even on malformed input.
        print('✗ Проверка защиты не пройдена. Последняя строка ✓ показывает завершённый этап. '
              'Проверьте локально параметры следующего этапа; секретные файлы не публикуйте.', file=sys.stderr)
        sys.exit(1)
