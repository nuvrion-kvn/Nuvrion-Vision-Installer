#!/usr/bin/env python3
# Nuvrion · release 1.0.0
"""Nuvrion Vision: input validation and deterministic configuration generation."""
import argparse
import base64
import getpass
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

NODE_IMAGE = 'remnawave/node:latest'
# Fixed installation layout, not an operator-configurable path.
BASE = '/opt/remnanode'
TAG = 'Vision-TLS'


def confirmation_prompt(text):
    """Выделить запрос подтверждения, даже если вывод проходит через оболочку."""
    if not sys.stdin.isatty() or 'NO_COLOR' in os.environ:
        return text
    return '\033[1;93m' + text + '\033[0m'


def parse_yes_no(value):
    value = value.strip().lower()
    if value in ('y', 'yes', 'д', 'да'):
        return True
    if value in ('n', 'no', 'н', 'нет'):
        return False
    raise ValueError('Введите Д — да или Н — нет.')


def nginx_version(value):
    if not isinstance(value, str) or not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', value):
        raise ValueError('Не удалось определить версию nginx (ожидается, например, 1.24.0).')
    return tuple(map(int, value.split('.')))


def validate(settings):
    if not isinstance(settings, dict):
        raise ValueError('Настройки должны быть объектом JSON.')
    s = dict(settings)
    for field in ('domain', 'panel_ips', 'email'):
        if not isinstance(s.get(field), str):
            raise ValueError(f'Поле {field} должно быть строкой.')
    domain = s['domain'].lower().rstrip('.')
    labels = domain.split('.')
    if len(domain) > 253 or len(labels) < 2 or not all(
        re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', x) for x in labels
    ) or not re.search(r'[a-z]', labels[-1]):
        raise ValueError('Укажите домен ASCII/punycode без https://, порта и пути.')
    s['domain'] = domain
    port = str(s.get('node_port', '2222'))
    if not re.fullmatch(r'[0-9]{1,5}', port) or not 1024 <= int(port) <= 65535:
        raise ValueError('Порт API: целое число от 1024 до 65535.')
    s['node_port'] = int(port)
    ips = re.split(r'[\s,]+', s['panel_ips'].strip())
    if not ips or not ips[0]:
        raise ValueError('Укажите IP исходящих подключений панели.')
    for ip in ips:
        address = ipaddress.ip_address(ip)  # Только отдельные IP-адреса, без CIDR.
        if address.is_unspecified or address.is_multicast or address.is_loopback:
            raise ValueError('Нужен реальный исходящий IP панели, не wildcard/loopback/multicast.')
    s['panel_ips'] = ' '.join(dict.fromkeys(str(ipaddress.ip_address(x)) for x in ips))
    if not re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+', s['email']):
        raise ValueError('Нужен рабочий email для уведомлений о сертификате.')
    s.pop('panel_version', None)  # Совместимость с ранее сохранёнными настройками.
    nginx_version(s.get('nginx_version', '1.24.0'))
    return s


def collect(target):
    # Validate each field independently; ask for the secret only after all others are valid.
    s = dict(domain='node.example.com', node_port=2222, panel_ips='203.0.113.10',
             email='operator@example.com')
    print('Обозначения: Д — да · Н — нет. Enter принимает значение в скобках.')
    fields = [('domain', 'Домен ноды (без https://)', None),
              ('node_port', 'Порт API ноды, такой же в панели', '2222'),
              ('panel_ips', 'IP исходящих подключений панели (через пробел)', None),
              ('email', "Email для сертификата Let's Encrypt", None)]
    for field, label, default in fields:
        while True:
            value = input(confirmation_prompt(label + (f' [{default}]' if default else '') + ': '))
            value = value or default or ''
            try:
                s = validate(dict(s, **{field: value}))
                break
            except ValueError as e:
                print(f'Ошибка: {e} Повторите только это поле.', file=sys.stderr)
    print(f'Образ ноды: {NODE_IMAGE}.')
    while True:
        secret = getpass.getpass(confirmation_prompt('Секретный ключ ноды из панели (ввод скрыт): '))
        try:
            validate_key(secret)
            break
        except ValueError as e:
            print(f'Ошибка: {e} Повторите ключ.', file=sys.stderr)
    print(f'\nДомен: {s["domain"]} · API: {s["node_port"]} · Панель: {s["panel_ips"]}')
    print('Секрет получен и проверен; его значение не выводится.')
    while True:
        try:
            prompt = confirmation_prompt('Начать установку с этими настройками? [Д/Н; Enter — Н]: ')
            if not parse_yes_no(input(prompt) or 'Н'):
                raise KeyboardInterrupt
            break
        except ValueError as e:
            print(e, file=sys.stderr)
    render(s, target, secret)


def validate_dns_records(a_records, aaaa_records, local_addresses):
    """Каждый опубликованный IP-адрес домена должен принадлежать серверу."""
    resolved = {ipaddress.ip_address(x) for x in (*a_records, *aaaa_records)}
    local = {ipaddress.ip_address(x) for x in local_addresses}
    if not resolved:
        raise ValueError('У домена нет IP-адреса этого сервера.')
    wrong = resolved - local
    if wrong:
        raise ValueError('DNS содержит адреса другого сервера/CDN: ' + ', '.join(sorted(map(str, wrong))) +
                         '. Нужен прямой IP на интерфейсе; NAT требует отдельной проверки.')
    return True


def preflight_dns(settings):
    def capture(*args):
        r = subprocess.run(args, capture_output=True, text=True, timeout=15)
        if r.returncode:
            raise ValueError(f'Не удалось выполнить {args[0]} для проверки DNS/адресов.')
        return r.stdout
    records = {}
    for kind in ('A', 'AAAA'):
        answer = capture('dig', '+time=3', '+tries=1', '+noall', '+answer', '+comments', settings['domain'], kind)
        if 'status: NOERROR,' not in answer:
            raise ValueError(f'DNS-запрос {kind} завершился ошибкой, установка не продолжена.')
        records[kind] = [cols[-1] for line in answer.splitlines()
                         if len(cols := line.split()) >= 5 and cols[-2] == kind]
    interfaces = json.loads(capture('ip', '-j', 'address', 'show'))
    local = [a['local'] for i in interfaces for a in i.get('addr_info', []) if a.get('scope') == 'global']
    validate_dns_records(records['A'], records['AAAA'], local)
    print('✓ Все IP-адреса домена совпадают с адресами интерфейсов сервера.')


def write(path, content, mode=0o600):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', dir=path.parent, delete=False) as f:
            tmp = f.name
            os.fchmod(f.fileno(), mode)
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    finally:
        if tmp is not None and os.path.exists(tmp):
            os.unlink(tmp)
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def json_write(path, obj, mode=0o600):
    write(path, json.dumps(obj, ensure_ascii=False, indent=2) + '\n', mode)


def profile(s):
    cert = f"/etc/letsencrypt/live/{s['domain']}"
    return {
        'log': {'access': 'none', 'dnsLog': False, 'loglevel': 'warning'},
        'dns': {
            'servers': [
                {'address': f'https+local://{host}/dns-query', 'timeoutMs': 3000}
                for host in ('dns.adguard-dns.com', 'dns.comss.one')
            ],
            'disableCache': False,
            'disableFallback': False, 'enableParallelQuery': False,
        },
        'inbounds': [{
            'tag': TAG, 'port': 443,
            'protocol': 'vless',
            'settings': {'flow': 'xtls-rprx-vision', 'clients': [], 'fallbacks': [
                {'alpn': 'h2', 'dest': '/run/xray-fallback/h2.sock', 'xver': 0},
                {'dest': '/run/xray-fallback/h1.sock', 'xver': 0},
            ], 'decryption': 'none'},
            'sniffing': {'enabled': True, 'routeOnly': True,
                         'destOverride': ['http', 'tls', 'quic']},
            'streamSettings': {
                'network': 'tcp', 'security': 'tls',
                'sockopt': {
                    'tcpFastOpen': True,
                    'tcpcongestion': 'bbr',
                    'tcpKeepAliveIdle': 60,
                    'tcpKeepAliveInterval': 30,
                },
                'tlsSettings': {'alpn': ['h2', 'http/1.1'], 'minVersion': '1.3',
                                'certificates': [{'keyFile': cert + '/privkey.pem',
                                                  'certificateFile': cert + '/fullchain.pem'}],
                                'rejectUnknownSni': False},
            },
        }],
        'outbounds': [
            {'tag': 'DIRECT', 'protocol': 'freedom'},
            {'tag': 'BLOCK', 'protocol': 'blackhole'},
        ],
        'routing': {'rules': [
            {'type': 'field', 'port': '443', 'network': 'udp', 'inboundTag': [TAG], 'outboundTag': 'BLOCK'},
            {'type': 'field', 'port': '25', 'network': 'tcp', 'outboundTag': 'BLOCK'},
            {'type': 'field', 'protocol': ['bittorrent'], 'outboundTag': 'BLOCK'},
            {'type': 'field', 'ip': ['geoip:private'], 'outboundTag': 'BLOCK'},
            {'type': 'field', 'domain': ['geosite:private'], 'outboundTag': 'BLOCK'},
            {'type': 'field', 'domain': [
                'geosite:category-ads-all', 'domain:analytics.google.com', 'domain:adjust.net.in',
                'domain:amplitude.com', 'domain:metrika.yandex.ru', 'domain:mytracker.ru',
            ], 'outboundTag': 'BLOCK'},
        ], 'domainStrategy': 'IPIfNonMatch'},
    }


def nginx(s):
    version = nginx_version(s.get('nginx_version', '1.24.0'))
    h2listen = '' if version >= (1, 25, 1) else ' http2'
    h2on = '        http2 on;\n' if version >= (1, 25, 1) else ''
    domain = s['domain']
    common = f"""
        server_name {domain};
        root /var/www/decoy;
        index index.html;
        client_max_body_size 8k;
        add_header X-Content-Type-Options nosniff always;
        add_header Referrer-Policy same-origin always;
        add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'" always;
        location / {{
            try_files $uri $uri/ /index.html;
        }}
        location ~ ^/(pokemon|habitats|assets)/ {{
            try_files $uri =404;
            add_header Cache-Control "public, max-age=86400";
        }}
        location ^~ /api/game/ {{
            if ($game_bad_origin) {{ return 403; }}
            proxy_pass http://unix:/run/nuvrion-pokehabitat/game.sock;
            proxy_http_version 1.1;
            proxy_set_header Host {domain};
            proxy_set_header Origin $http_origin;
            proxy_set_header Connection "";
            proxy_set_header CF-Connecting-IP $remote_addr;
            proxy_set_header X-Forwarded-Proto https;
            proxy_connect_timeout 2s;
            proxy_read_timeout 15s;
            proxy_send_timeout 15s;
            proxy_intercept_errors off;
            add_header Cache-Control "no-store" always;
            error_page 502 504 =503 /_game_unavailable.json;
        }}
        location = /_game_unavailable.json {{
            internal;
            default_type application/json;
            add_header Cache-Control "no-store" always;
            return 503 '{{"error":"unavailable"}}';
        }}
        location ~ /\\. {{ deny all; }}
"""
    return f"""user www-data;
worker_processes auto;
error_log /var/log/nginx/nuvrion-error.log warn;
pid /run/nuvrion-nginx/nginx.pid;
events {{ worker_connections 1024; }}
http {{
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    access_log off;
    server_tokens off;
    client_body_temp_path /run/nuvrion-nginx/body;
    proxy_temp_path /run/nuvrion-nginx/proxy;
    fastcgi_temp_path /run/nuvrion-nginx/fastcgi;
    uwsgi_temp_path /run/nuvrion-nginx/uwsgi;
    scgi_temp_path /run/nuvrion-nginx/scgi;
    map $http_origin $game_bad_origin {{
        default 1;
        "" 0;
        "https://{domain}" 0;
    }}
    server {{
        listen unix:/opt/remnanode/fallback-sockets/h1.sock;
{common}    }}
    server {{
        listen unix:/opt/remnanode/fallback-sockets/h2.sock{h2listen};
{h2on}{common}    }}
}}
"""


def compose(s):
    # JSON is valid YAML; it avoids shell/YAML/Compose interpolation of user input.
    common = {'restart': 'unless-stopped', 'network_mode': 'host',
              'logging': {'driver': 'json-file', 'options': {'max-size': '10m', 'max-file': '3'}},
              'labels': {'com.nuvrion.vision.managed': '1'}}
    return {'name': 'nuvrion-vision', 'services': {
        'remnanode': {**common, 'container_name': 'remnanode', 'hostname': 'remnanode',
                     'user': '0:0',
                     'image': NODE_IMAGE, 'env_file': ['./node.env'],
                     'cap_add': ['NET_ADMIN'],
                     'security_opt': ['no-new-privileges:true'],
                     # Matches NOFILE_TARGET in the pinned Nuvrion tuning v1.0.0.
                     # Installer provisions it before first start, check() verifies the result.
                     'ulimits': {'nofile': {'soft': 1048576, 'hard': 1048576}},
                     'volumes': ['/etc/letsencrypt:/etc/letsencrypt:ro',
                                 './fallback-sockets:/run/xray-fallback:ro',
                                 './vision-config-profile.json:/opt/nuvrion/profile.json:ro']},
    }}


def validate_key(key):
    # Do not strip or silently repair a damaged secret. Pass the exact bytes to Docker.
    if not key or len(key) > 65536 or not re.fullmatch(r'[A-Za-z0-9+/=_-]+', key):
        raise ValueError('SECRET_KEY должен быть одной строкой Base64 из панели.')
    try:
        data = json.loads(base64.b64decode(key + '=' * (-len(key) % 4), altchars=b'-_', validate=True))
        fields = ('caCertPem', 'nodeCertPem', 'nodeKeyPem', 'jwtPublicKey')
        if not isinstance(data, dict) or not all(isinstance(data.get(k), str) and data[k] for k in fields):
            raise ValueError()
    except (ValueError, UnicodeError) as e:
        raise ValueError('Неверная структура SECRET_KEY; скопируйте полный ключ из панели.') from e
    with tempfile.TemporaryDirectory() as directory:
        p = Path(directory)
        for field in fields:
            value = data[field].replace('\\n', '\n').replace('\r\n', '\n').strip() + '\n'
            write(p / field, value)
        def check(*args):
            r = subprocess.run(['openssl', *map(str, args)], stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15)
            if r.returncode:
                raise ValueError('Ключ ноды: сертификат/подпись/срок/приватный ключ не прошёл проверку.')
            return r.stdout
        check('verify', '-CAfile', p/'caCertPem', p/'caCertPem', p/'nodeCertPem')
        check('x509', '-in', p/'nodeCertPem', '-checkend', '0', '-noout')
        public = check('x509', '-in', p/'nodeCertPem', '-pubkey', '-noout')
        actual = check('pkey', '-in', p/'nodeKeyPem', '-pubout')
        if public != actual:
            raise ValueError('Приватный ключ ноды не соответствует её сертификату.')
        check('pkey', '-pubin', '-in', p/'jwtPublicKey', '-noout')
    return key


def render(s, target, key=None):
    s = validate(s)
    target = Path(target)
    target.mkdir(parents=True, exist_ok=True, mode=0o700)
    json_write(target/'settings.json', s)
    json_write(target/'vision-config-profile.json', profile(s))
    json_write(target/'docker-compose.yml', compose(s))
    write(target/'nginx.conf', nginx(s), 0o644)
    if key is not None:
        validate_key(key)
        write(target/'node.env', f"NODE_PORT={s['node_port']}\nSECRET_KEY={key}\nSNI_VERIFICATION=true\n")
    else:
        write(target/'node.env', f"NODE_PORT={s['node_port']}\nSECRET_KEY=REPLACE_WITH_PANEL_SECRET\nSNI_VERIFICATION=true\n")
    host = f'''⚙ НАСТРОЙКИ ХОСТА В ПАНЕЛИ REMNAWAVE

Выберите профиль ноды.

Адрес:          {s['domain']}
Порт:           443

Безопасность
SNI:            {s['domain']}
Security Layer: TLS (Transport Layer Security)
Отпечаток:      firefox

Транспорт
ALPN:           h2,http/1.1
'''
    write(target/'host-settings.txt', host)


def main():
    p = argparse.ArgumentParser()
    p.add_argument('action', choices=['render', 'validate-key', 'collect', 'check-dns'])
    p.add_argument('--settings')
    p.add_argument('--output')
    p.add_argument('--key-file')
    args = p.parse_args()
    try:
        if args.action == 'collect':
            collect(args.output)
        elif args.action == 'check-dns':
            preflight_dns(validate(json.loads(Path(args.settings).read_text(encoding='utf-8'))))
        elif args.action == 'validate-key':
            validate_key(Path(args.key_file).read_text(encoding='utf-8').rstrip('\n'))
        else:
            key = Path(args.key_file).read_text(encoding='utf-8').rstrip('\n') if args.key_file else None
            render(json.loads(Path(args.settings).read_text(encoding='utf-8')), args.output, key)
    except (ValueError, KeyError, OSError, subprocess.TimeoutExpired) as e:
        print(f'Ошибка: {e}', file=sys.stderr)
        sys.exit(2)
    except (EOFError, KeyboardInterrupt):
        print('\nВвод отменён; конфигурация не сохранена.', file=sys.stderr)
        sys.exit(2)


if __name__ == '__main__':
    main()
