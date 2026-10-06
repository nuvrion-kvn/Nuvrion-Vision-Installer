"""Contracts for the complete proxied club and its local outage page."""
from html.parser import HTMLParser
from pathlib import Path
import re
import sys
import subprocess
import unittest
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'src'))
import runtime

class PageParser(HTMLParser):
    def __init__(self):
        super().__init__(); self.elements = []
    def handle_starttag(self, tag, attrs):
        self.elements.append((tag, dict(attrs)))

class DecoyTests(unittest.TestCase):
    def test_outage_page_is_self_contained_and_bilingual(self):
        source=(ROOT/'src/decoy.html').read_text();page=PageParser();page.feed(source)
        ids=[a['id'] for _,a in page.elements if 'id' in a]
        self.assertEqual(len(ids),len(set(ids)))
        for tag,attrs in page.elements:
            self.assertNotIn('src',attrs)
            if 'href' in attrs:self.assertEqual(attrs['href'],'/')
        self.assertIn('PokéHabitat',source)
        self.assertIn('Клуб временно недоступен',source)
        self.assertIn('The club is temporarily unavailable',source)
        self.assertIn('prefers-reduced-motion:reduce',source)
        for term in ('fetch(', 'XMLHttpRequest', 'document.cookie', 'localStorage'):
            self.assertNotIn(term,source)
        self.assertIn('aria-pressed',source)

    def test_site_is_local_and_api_uses_only_unix(self):
        config=runtime.nginx({'domain':'node.example.com','nginx_version':'1.24.0'})
        self.assertEqual(config.count('proxy_pass http://unix:/run/nuvrion-pokehabitat/game.sock;'),2)
        self.assertIn('try_files $uri $uri/ /index.html;',config)
        self.assertIn("connect-src 'self'",config)
        self.assertIn('proxy_intercept_errors off;',config)
        for remote in ('resolver ', 'proxy_ssl', 'chatgpt.site', 'https://pokehabitat'):
            self.assertNotIn(remote,config)

    def test_status_check_requires_a_working_local_site(self):
        source=(ROOT/'src/installer.sh').read_text()
        self.assertIn('check_site_response "$h1" h1',source)
        self.assertIn('check_site_response "$h2" h2',source)
        self.assertIn('systemctl is-active --quiet nuvrion-pokehabitat.service',source)
        self.assertIn('Локальный игровой API не отвечает.',source)

    def test_status_checks_accept_only_valid_transport_results(self):
        source=(ROOT/'src/installer.sh').read_text().split('# Private child entry')[0]
        for response,protocol,ok in [('200','h1',True),('503','h1',False),('200:2','h2',True),('503:2','h2',False),('500','h1',False),('503:1.1','h2',False),('','h1',False)]:
            with self.subTest(response=response,protocol=protocol):
                result=subprocess.run(['bash','-c',source+'\ncheck_site_response "$1" "$2"','fixture',response,protocol],capture_output=True,text=True)
                self.assertEqual(result.returncode==0,ok,result.stdout+result.stderr)
                if response.startswith('503') and ok:self.assertIn('страница 503',result.stdout)

    def test_node_origin_is_preserved(self):
        config=runtime.nginx({'domain':'node.example.com'})
        self.assertIn('proxy_set_header Origin $http_origin;',config)
        self.assertIn('"https://node.example.com" 0;',config)
        self.assertIn('default 1;',config)
        self.assertIn('if ($game_bad_origin) { return 403; }',config)
        self.assertNotIn('proxy_set_header Origin https://',config)

    def test_network_permission_does_not_add_inbound_tcp(self):
        unit=(ROOT/'src/nuvrion-decoy.service').read_text()
        self.assertIn('RestrictAddressFamilies=AF_UNIX',unit)
        self.assertIn('IPAddressDeny=any',unit)
        self.assertIn('ProtectSystem=strict',unit)
        game=(ROOT/'src/nuvrion-pokehabitat.service').read_text()
        self.assertIn('RestrictAddressFamilies=AF_UNIX',game)
        self.assertIn('User=nuvrion-game',game)
        self.assertIn('NoNewPrivileges=yes',unit)
        for version in ['1.18.0','1.24.0','1.28.0']:
            config=runtime.nginx({'domain':'node.example.com','nginx_version':version})
            listens=re.findall(r'listen ([^;]+);',config)
            self.assertEqual(len(listens),2)
            self.assertTrue(all(x.startswith('unix:') for x in listens))

if __name__=='__main__':unittest.main()
