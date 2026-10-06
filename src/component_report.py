#!/usr/bin/env python3
# Nuvrion · release 1.0.0
"""Read-only component report; no enable/restart/install or secret output."""
import json
from pathlib import Path
import re
import subprocess
import sys

import security_check
import terminal_ui as ui

BASE = Path('/opt/remnanode')
PROFILE = Path('/etc/sysctl.d/99-zzzz-nuvrion-performance.conf')


def capture(*args, timeout=30):
    result = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        raise ValueError('проверка не пройдена')
    return result.stdout.strip()


def service(unit):
    active = capture('systemctl', 'is-active', unit) == 'active'
    enabled = capture('systemctl', 'is-enabled', unit) == 'enabled'
    if not active or not enabled:
        raise ValueError('служба или автозапуск неактивны')
    return 'Активен; автозапуск включён'


def sysctl_value(key, expected=None):
    value = capture('sysctl', '-n', key)
    if expected is not None and value != expected:
        raise ValueError('параметр не совпадает')
    return value


def tuning():
    pairs = []
    for line in PROFILE.read_text(encoding='utf-8').splitlines():
        if line.lstrip().startswith('#') or '=' not in line:
            continue
        key, value = line.split('=', 1)
        pairs.append((key.strip(), ' '.join(value.split())))
    if not pairs:
        raise ValueError('пустой профиль')
    # Не выдаём старый текстовый статус за текущие значения ядра.
    for key, value in pairs:
        if ' '.join(sysctl_value(key).split()) != value:
            raise ValueError('значение профиля не совпадает')
    return f'Проверено параметров: {len(pairs)}'


def zram():
    for line in Path('/proc/swaps').read_text().splitlines()[1:]:
        fields = line.split()
        if len(fields) >= 5 and re.fullmatch(r'/dev/zram[0-9]+', fields[0]):
            size = int((Path('/sys/block') / Path(fields[0]).name / 'disksize').read_text())
            if size > 0:
                return f'Активен; {size // 1048576} МБ; приоритет {fields[4]}'
    return pending_zram_kernel(), 'warn'


def pending_zram_kernel(prefix=Path('/')):
    root = Path(prefix)
    kernel = (root / 'var/lib/nuvrion-tuning/zram-pending-kernel').read_text().strip()
    pattern = r'(\d+)\.(\d+)\.(\d+)-(\d+)-([A-Za-z0-9_.+-]+)'
    future = re.fullmatch(pattern, kernel)
    current = re.fullmatch(pattern, capture('uname', '-r'))
    if not future or not current or future[5] != current[5] or \
       tuple(map(int, future.groups()[:4])) <= tuple(map(int, current.groups()[:4])):
        raise ValueError('нет подтверждённого нового ядра')
    modules = root / 'lib/modules' / kernel
    for candidate in (root / 'lib/modules').iterdir():
        version = re.fullmatch(pattern, candidate.name)
        if version and version[5] == future[5] and \
           tuple(map(int, version.groups()[:4])) > tuple(map(int, future.groups()[:4])) and \
           ((root / 'boot' / f'vmlinuz-{candidate.name}').is_file() or (candidate / 'vmlinuz').is_file()):
            raise ValueError('статус отложенного ZRAM устарел')
    if not ((root / 'boot' / f'vmlinuz-{kernel}').is_file() or (modules / 'vmlinuz').is_file()) or \
       not any(path.is_file() for path in (modules / 'kernel/drivers/block/zram').glob('zram.ko*')) or \
       capture('systemctl', 'is-enabled', 'nuvrion-zram.service') != 'enabled':
        raise ValueError('отложенный запуск не подтверждён')
    return f'Ожидает перезагрузки в ядро {kernel}'


def rps():
    queues = list(Path('/sys/class/net').glob('*/queues/rx-*/rps_cpus'))
    active = sum(bool(int(p.read_text().strip().replace(',', ''), 16)) for p in queues)
    return f'Активных RX-очередей: {active}' if active else 'Не включён / не требуется'


def updates():
    text = capture('apt-config', 'dump')
    if not re.search(r'^APT::Periodic::Unattended-Upgrade "1";', text, re.M):
        raise ValueError('автообновления выключены')
    service('apt-daily-upgrade.timer')
    return 'Включены; таймер активен'


def certificate(domain):
    path = f'/etc/letsencrypt/live/{domain}/fullchain.pem'
    capture('openssl', 'x509', '-in', path, '-checkhost', domain, '-noout')
    capture('openssl', 'x509', '-in', path, '-checkend', '86400', '-noout')
    capture('openssl', 'verify', '-untrusted', path, path)
    return 'Имя, срок и цепочка проверены'


def collect(validation_code):
    rows = []

    def probe(label, fn, failure='Проверка не пройдена', severity='error'):
        try:
            value = fn()
            detail, kind = value if isinstance(value, tuple) else (value, 'ok')
            rows.append((label, detail, kind))
        except (OSError, ValueError, KeyError, TypeError, AttributeError, OverflowError, subprocess.SubprocessError,
                security_check.CheckFailure):
            # Не выводить исключения: они могут содержать пользовательские данные.
            rows.append((label, failure, severity))

    try:
        settings = json.loads((BASE / 'settings.json').read_text(encoding='utf-8'))
        if not isinstance(settings, dict):
            settings = {}
    except (ValueError, OSError):
        settings = {}
    def packages():
        if capture('dpkg', '--audit'):
            raise ValueError('незавершённая настройка пакетов')
        return 'Целостность dpkg проверена'
    probe('Система и пакеты', packages)
    probe('Docker Engine', lambda: service('docker.service'))
    probe('Docker Compose', lambda: capture('docker', 'compose', 'version', '--short'))
    def node():
        if capture('docker', 'inspect', '-f', '{{.State.Running}}', 'remnanode') != 'true':
            raise ValueError('контейнер не запущен')
        return 'Запущен'
    probe('RemnaNode', node)
    def nofile():
        # Проверяем фактический soft/hard внутри контейнера, не только Compose.
        with (BASE / 'check-nofile.sh').open() as script:
            result = subprocess.run(('docker', 'exec', '-i', 'remnanode', 'sh'),
                                    stdin=script, capture_output=True, text=True, timeout=30)
        if result.returncode:
            raise ValueError('лимиты не подтверждены')
        return 'Оба лимита не ниже 1048576'
    probe('Лимиты RemnaNode', nofile)
    def api():
        port = int(settings['node_port'])
        if not capture('ss', '-H', '-ltn', f'sport = :{port}'):
            raise ValueError('порт API не слушается')
        security_check.firewall(capture('ufw', 'status', 'verbose'), port, settings['panel_ips'])
        return f'TCP/{port}; доступ только IP панели'
    probe('API ноды (mTLS)', api)
    def xray():
        capture('docker', 'exec', 'remnanode', 'xray', 'run', '-test', '-config', '/opt/nuvrion/profile.json')
        return 'Сохранённый профиль проверен'
    probe('Xray Core', xray)
    def decoy():
        service('nuvrion-decoy.service')
        for sock, proto, expected in (('h1', '--http1.1', '200:1.1'),
                                      ('h2', '--http2-prior-knowledge', '200:2')):
            value = capture('curl', '--noproxy', '*', '-sS', '--connect-timeout', '5', '--max-time', '35',
                            proto, '--unix-socket', str(BASE / 'fallback-sockets' / (sock + '.sock')),
                            '-o', '/dev/null', '-w', '%{http_code}:%{http_version}', 'http://localhost/', timeout=45)
            if value != expected:
                raise ValueError('неверный ответ сокета')
        return 'Автономный PokéHabitat: HTTP/1.1 и HTTP/2 — 200'
    probe('nginx и автономный сайт', decoy)
    def game():
        service('nuvrion-pokehabitat.service')
        response=capture('curl','--noproxy','*','-fsS','--max-time','10','--unix-socket',
                         '/run/nuvrion-pokehabitat/game.sock','http://localhost/api/game/me')
        if json.loads(response).get('profile','missing') is not None:
            raise ValueError('неверный ответ игрового API')
        return 'Локальный API, SQLite и авторизация; внешних зависимостей во время работы нет'
    probe('Игровой сервер PokéHabitat', game)
    probe('TLS-сертификат', lambda: certificate(settings['domain']))
    probe('Автопродление TLS', lambda: service('certbot.timer'))
    def ufw():
        if not re.search(r'^Status: active$', capture('ufw', 'status'), re.M):
            raise ValueError('неактивен')
        return 'Активен'
    probe('UFW', ufw)
    def fail2ban():
        service('fail2ban.service')
        capture('fail2ban-client', 'status', 'sshd')
        return 'Служба и защита sshd активны'
    probe('Fail2ban', fail2ban)
    def ssh():
        capture('sshd', '-t')
        data = dict(line.split(None, 1) for line in capture('sshd', '-T').splitlines() if ' ' in line)
        return 'Конфигурация верна; пароль: ' + ('да' if data.get('passwordauthentication') == 'yes' else 'нет')
    probe('SSH', ssh)
    def security():
        capture(sys.executable, str(BASE / 'security_check.py'), timeout=300)
        return 'Права, изоляция и ограничения проверены'
    probe('Защита файлов и служб', security)
    probe('Продвинутая настройка', tuning, 'Есть расхождения / профиль недоступен', 'warn')
    probe('BBR', lambda: sysctl_value('net.ipv4.tcp_congestion_control', 'bbr'))
    probe('qdisc по умолчанию', lambda: sysctl_value('net.core.default_qdisc', 'fq'))
    probe('TCP Fast Open', lambda: sysctl_value('net.ipv4.tcp_fastopen', '3'))
    probe('ZRAM', zram, 'Не активен / размер не подтверждён', 'warn')
    # Отсутствие RPS может быть корректным на 1 CPU или multiqueue.
    try:
        rows.append(('RPS', rps(), 'info'))
    except (OSError, ValueError):
        rows.append(('RPS', 'Не удалось прочитать состояние', 'warn'))
    probe('Обновления безопасности', updates, severity='warn')
    def ntp():
        if capture('timedatectl', 'show', '-p', 'NTPSynchronized', '--value') != 'yes':
            raise ValueError('не синхронизировано')
        return 'Синхронизировано'
    probe('NTP / время', ntp, 'Синхронизация не подтверждена', 'warn')
    probe('TRIM', lambda: service('fstrim.timer'), 'Неактивен / не поддерживается', 'warn')
    def privacy():
        service('nuvrion-two-way-ping.service')
        rules = capture('nft', 'list', 'table', 'inet', 'nuvrion_privacy')
        if not all(re.search(expr, rules) for expr in (
                r'icmp type echo-request.*\bdrop\b', r'icmp type timestamp-request.*\bdrop\b',
                r'icmpv6 type echo-request.*\bdrop\b')):
            raise ValueError('нет правил')
        return 'Три правила блокировки проверены'
    probe('Защита от Two-Way Ping', privacy)
    try:
        choice = (BASE / '.traffic-control-choice').read_text().strip()
    except OSError:
        choice = ''
    if choice == 'skipped':
        rows.append(('Nuvrion Traffic Control', 'Пропущен по вашему выбору', 'info'))
    else:
        def traffic():
            capture('/usr/local/bin/nuvrion-traffic-control', 'check', timeout=360)
            return 'Рабочие правила и службы проверены'
        probe('Nuvrion Traffic Control', traffic)
    rows.append(('Профиль TLS/443', {0: 'Сквозная локальная проверка пройдена',
                 2: 'Ожидает применения в Remnawave'}.get(validation_code, 'Полная проверка не пройдена'),
                 {0: 'ok', 2: 'warn'}.get(validation_code, 'error')))
    return rows


def main(validation_code):
    rows = collect(validation_code)
    ui.heading('ИТОГОВЫЙ ОТЧЁТ ПО КОМПОНЕНТАМ')
    ui.row('КОМПОНЕНТ', 'СОСТОЯНИЕ', 'heading')
    marks = {'ok': '[✓]', 'warn': '[!]', 'error': '[✗]', 'info': '[•]'}
    for name, value, kind in rows:
        ui.row(name, marks[kind] + ' ' + value, kind)
    failures = sum(kind == 'error' for _, _, kind in rows)
    warnings = sum(kind == 'warn' for _, _, kind in rows)
    ui.message(f'Ошибок: {failures}; предупреждений: {warnings}.', 'error' if failures else 'warn' if warnings else 'ok')
    ui.message('Связь mTLS с панелью и VLESS-клиент проверяются отдельно.')
    if Path('/run/reboot-required').exists():
        ui.message('Системе требуется перезагрузка: reboot.', 'warn')
    return 1 if failures else 0


if __name__ == '__main__':
    sys.exit(main(int(sys.argv[1])))
