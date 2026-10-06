import base64
import json
from pathlib import Path
import re
import sys
import tempfile
import subprocess
import unittest
from unittest.mock import patch
import contextlib
import io

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'src'))
import runtime as r

SETTINGS = dict(domain='node.example.com', panel_ips='203.0.113.10',
                email='operator@example.com')


class ConfigTests(unittest.TestCase):
    def test_settings_must_be_json_object_with_string_fields(self):
        for document in (None, [], 'invalid', 1):
            with self.subTest(document=document), self.assertRaises(ValueError):
                r.validate(document)
        for field in ('domain', 'panel_ips', 'email'):
            for value in (None, [], {}, 1, True):
                with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                    r.validate(dict(SETTINGS, **{field:value}))

    def test_api_default(self):
        self.assertEqual(r.validate(SETTINGS)['node_port'], 2222)

    def test_domains(self):
        for domain in ['https://x.ru', 'a.ru:443', 'x.ru;id', 'x/ru', '*.ru', '-a.ru', 'a..ru',
                       '127.0.0.1', 'a.ru\nuser root;', 'a'*64+'.ru', 'кириллица.рф']:
            with self.subTest(domain=domain), self.assertRaises(ValueError):
                r.validate(dict(SETTINGS, domain=domain))
        self.assertEqual(r.validate(dict(SETTINGS, domain='NODE.EXAMPLE.COM.'))['domain'], 'node.example.com')

    def test_ports(self):
        for port in ['443', '80', '0', '65536', '-1', '2222;id', '22\n22', 'xyz']:
            with self.subTest(port=port), self.assertRaises(ValueError):
                r.validate(dict(SETTINGS, node_port=port))
        self.assertEqual(r.validate(dict(SETTINGS, node_port='02222'))['node_port'], 2222)

    def test_panel_ips(self):
        for ip in ['', '0.0.0.0/0', '1.2.3.4/24', 'panel.example.com', '1.2.3.4;id']:
            with self.subTest(ip=ip), self.assertRaises(ValueError):
                r.validate(dict(SETTINGS, panel_ips=ip))
        self.assertEqual(
            r.validate(dict(SETTINGS, panel_ips='203.0.113.10 2001:db8::1'))['panel_ips'],
            '203.0.113.10 2001:db8::1')
        self.assertEqual(r.validate(dict(SETTINGS, panel_ips='203.0.113.10 203.0.113.10'))['panel_ips'], '203.0.113.10')

    def test_legacy_panel_version_is_ignored(self):
        for version in ['2.8.1', '3.2.2', '4.0.0', 'latest', '3.4.3;id']:
            with self.subTest(version=version):
                self.assertEqual(r.validate(dict(SETTINGS, panel_version=version)), r.validate(SETTINGS))

    def test_yes_no(self):
        for text in ['y', 'Y', 'YES', 'yes', 'Да', 'д']:
            self.assertTrue(r.parse_yes_no(text))
        for text in ['n', 'N', 'NO', 'нет', 'Н']:
            self.assertFalse(r.parse_yes_no(text))
        with self.assertRaises(ValueError): r.parse_yes_no('maybe')

    def test_confirmation_prompt_is_bold_yellow_only_in_terminal(self):
        with patch.object(r.sys.stdin, 'isatty', return_value=True), \
             patch.dict(r.os.environ, {}, clear=True):
            prompt = r.confirmation_prompt('Подтвердить? ')
        self.assertEqual(prompt, '\033[1;93mПодтвердить? \033[0m')
        with patch.object(r.sys.stdin, 'isatty', return_value=False):
            self.assertEqual(r.confirmation_prompt('Подтвердить? '), 'Подтвердить? ')

    def test_nginx_version_errors(self):
        for value in ['', '1.24', None, 'foo', '1.24.0;id']:
            with self.subTest(value=value), self.assertRaises(ValueError):
                r.nginx(dict(SETTINGS, nginx_version=value))

    def test_all_dns_records_must_be_local(self):
        local=['203.0.113.11','203.0.113.12','2001:db8::1']
        self.assertTrue(r.validate_dns_records(local[:2], ['2001:db8::1'], local))
        for a,aaaa in [([],[]),(['203.0.113.11','203.0.113.99'],[]),
                       (['203.0.113.11'],['2001:db8::2'])]:
            with self.subTest(a=a,aaaa=aaaa), self.assertRaises(ValueError):
                r.validate_dns_records(a,aaaa,local)

    def test_dns_command_parsing(self):
        s=r.validate(SETTINGS)
        answers=[subprocess.CompletedProcess([],0,';; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1\nnode.example.com. 30 IN CNAME alias.example.com.\nalias.example.com. 30 IN A 203.0.113.11\n',''),
                 subprocess.CompletedProcess([],0,';; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 2\n',''),
                 subprocess.CompletedProcess([],0,json.dumps([{'addr_info':[{'local':'203.0.113.11','scope':'global'}]}]),'')]
        with patch.object(r.subprocess,'run',side_effect=answers),contextlib.redirect_stdout(io.StringIO()):
            r.preflight_dns(s)
        bad=subprocess.CompletedProcess([],0,';; ->>HEADER<<- opcode: QUERY, status: SERVFAIL, id: 1\n','')
        with patch.object(r.subprocess,'run',return_value=bad),self.assertRaises(ValueError):
            r.preflight_dns(s)

    def test_collect_retries_only_invalid_field_and_secret(self):
        # No actual credential is used here; cryptographic validation is tested separately.
        answers=['https://wrong.ru','node.example.com','x','2222','203.0.113.10',
                 'operator@example.com','Д']
        with patch('builtins.input',side_effect=answers) as inp, \
             patch.object(r.getpass,'getpass',side_effect=['bad','valid']) as gp, \
             patch.object(r,'validate_key',side_effect=[ValueError('bad key'),'valid']), \
             patch.object(r,'render') as render, \
             contextlib.redirect_stdout(io.StringIO()),contextlib.redirect_stderr(io.StringIO()):
            r.collect('/unused')
        self.assertEqual(inp.call_count,len(answers))
        self.assertTrue(all('Версия панели' not in call.args[0] for call in inp.call_args_list))
        self.assertEqual(gp.call_count,2)
        settings,out,secret=render.call_args.args
        self.assertEqual(settings['domain'],'node.example.com')
        self.assertEqual(settings['node_port'],2222)
        self.assertEqual(secret,'valid')

    def test_neutral_decoy(self):
        page=(Path(__file__).resolve().parents[1]/'src/decoy.html').read_text().lower()
        for term in ['nuvrion', 'vless', 'xray', 'remnawave', 'ghost']:
            self.assertNotIn(term,page)
        self.assertIn('pokéhabitat',page)

    def test_no_tcp_fallback(self):
        s = r.validate(SETTINGS)
        p = r.profile(s)
        self.assertNotIn('listen', p['inbounds'][0])
        self.assertEqual([v['dest'] for v in p['inbounds'][0]['settings']['fallbacks']],
                         ['/run/xray-fallback/h2.sock', '/run/xray-fallback/h1.sock'])
        for v in ('1.18.0', '1.22.1', '1.24.0', '1.26.3', '1.28.0'):
            nginx = r.nginx(dict(s, nginx_version=v))
            listens = re.findall(r'listen ([^;]+);', nginx)
            self.assertEqual(len(listens), 2)
            self.assertTrue(all(x.startswith('unix:/opt/remnanode/fallback-sockets/') for x in listens))
        self.assertEqual(len(r.compose(s)['services']), 1)

    def test_dns_and_tls(self):
        p=r.profile(r.validate(SETTINGS)); inbound=p['inbounds'][0]
        self.assertEqual([v['address'] for v in p['dns']['servers']],
                         ['https+local://dns.adguard-dns.com/dns-query','https+local://dns.comss.one/dns-query'])
        self.assertNotIn('queryStrategy', p['dns'])
        self.assertTrue(all('queryStrategy' not in server for server in p['dns']['servers']))
        self.assertNotIn('domainStrategy', p['outbounds'][0].get('settings', {}))
        self.assertEqual(inbound['streamSettings']['tlsSettings']['minVersion'], '1.3')
        self.assertFalse(inbound['streamSettings']['tlsSettings']['rejectUnknownSni'])
        self.assertEqual(inbound['settings']['flow'], 'xtls-rprx-vision')
        self.assertEqual(inbound['streamSettings']['sockopt'], {
            'tcpFastOpen': True,
            'tcpcongestion': 'bbr',
            'tcpKeepAliveIdle': 60,
            'tcpKeepAliveInterval': 30,
        })

    def test_bad_secrets(self):
        for secret in ['abc', 'abc\n', '$(id)', 'a b', base64.b64encode(b'{}').decode()]:
            with self.subTest(secret=secret), self.assertRaises(ValueError):
                r.validate_key(secret)

    def test_render_permissions(self):
        with tempfile.TemporaryDirectory() as td:
            r.render(SETTINGS, td)
            p=Path(td)
            for name in ['node.env', 'settings.json', 'vision-config-profile.json']:
                self.assertEqual((p/name).stat().st_mode & 0o777, 0o600)
            self.assertIn('NODE_PORT=2222', (p/'node.env').read_text())
            self.assertNotIn('SECRET_KEY=', (p/'host-settings.txt').read_text())

    def test_valid_secret_and_mismatched_key(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)
            def run(*args):
                subprocess.run(['openssl',*args],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,cwd=p)
            run('req','-x509','-newkey','rsa:2048','-nodes','-days','1','-keyout','ca.key','-out','ca.pem','-subj','/CN=TestCA')
            run('req','-newkey','rsa:2048','-nodes','-keyout','node.key','-out','node.csr','-subj','/CN=TestNode')
            run('x509','-req','-in','node.csr','-CA','ca.pem','-CAkey','ca.key','-CAcreateserial','-out','node.pem','-days','1')
            run('pkey','-in','ca.key','-pubout','-out','jwt.pem')
            payload=dict(caCertPem=(p/'ca.pem').read_text(),nodeCertPem=(p/'node.pem').read_text(),
                         nodeKeyPem=(p/'node.key').read_text(),jwtPublicKey=(p/'jwt.pem').read_text())
            secret=base64.b64encode(json.dumps(payload).encode()).decode()
            self.assertEqual(r.validate_key(secret),secret)
            payload['nodeKeyPem']=(p/'ca.key').read_text()
            with self.assertRaises(ValueError):
                r.validate_key(base64.b64encode(json.dumps(payload).encode()).decode())

    def test_nofile_tracks_vendor_target(self):
        vendor=(Path(__file__).resolve().parents[1]/'vendor/nuvrion-auto-tuning.sh').read_text()
        target=int(re.search(r'^NOFILE_TARGET=(\d+)$',vendor,re.M)[1])
        limits=r.compose(r.validate(SETTINGS))['services']['remnanode']['ulimits']['nofile']
        self.assertEqual(limits,dict(soft=target,hard=target))


if __name__=='__main__':
    unittest.main(verbosity=2)
