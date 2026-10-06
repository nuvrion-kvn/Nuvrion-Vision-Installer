#!/usr/bin/env python3
"""Actual bundled frontend, Node/SQLite game and nginx, with no remote upstream."""
import hashlib
import json
import os
from pathlib import Path
import pwd
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
import runtime
from proxy_fixture import GameFixture,detect_nginx_version
ROOT=Path(__file__).resolve().parents[1]
NGINX,MIME=map(lambda x:str(Path(x).resolve()),sys.argv[1:3]);TCP='--tcp' in sys.argv[3:]
checks=0

def check(value,message):
    global checks
    if not value:raise AssertionError(message)
    checks+=1;print('PASS '+message,flush=True)

def main():
    with tempfile.TemporaryDirectory(prefix='cbv-local-site-') as td:
        d=Path(td);d.chmod(0o755);(d/'run').mkdir();shutil.copytree(ROOT/'site/dist',d/'public')
        fixture=GameFixture(d,TCP);proc=None
        try:
            config=fixture.configuration(runtime.nginx({'domain':'node.example.com','nginx_version':detect_nginx_version(NGINX)}))
            config=config.replace('/opt/remnanode/fallback-sockets',str(d)).replace('/var/www/decoy',str(d/'public'))
            config=config.replace('/run/nuvrion-nginx',str(d/'run')).replace('/var/log/nginx/nuvrion-error.log',str(d/'error.log')).replace('/etc/nginx/mime.types',MIME)
            config=config.replace('worker_processes auto;','worker_processes 1;').replace('user www-data;',f'user {pwd.getpwuid(os.getuid()).pw_name};')
            ports=[]
            if TCP:
                for name in ['h1','h2']:
                    with socket.socket() as p:p.bind(('127.0.0.1',0));port=p.getsockname()[1]
                    ports.append(port);config=config.replace('unix:'+str(d/(name+'.sock')),'127.0.0.1:'+str(port))
            (d/'nginx.conf').write_text(config)
            subprocess.run([NGINX,'-t','-p',str(d)+'/', '-c',str(d/'nginx.conf')],check=True)
            proc=subprocess.Popen([NGINX,'-p',str(d)+'/', '-c',str(d/'nginx.conf'),'-g','daemon off;'])
            for _ in range(100):
                if TCP:
                    try:
                        with socket.create_connection(('127.0.0.1',ports[0]),timeout=.2):break
                    except OSError:pass
                elif (d/'h1.sock').exists() and (d/'h2.sock').exists():break
                if proc.poll() is not None:raise RuntimeError((d/'error.log').read_text())
                time.sleep(.05)
            def request(path='/',proto='--http1.1',headers=(),body=None):
                command=['/usr/bin/curl','--noproxy','*','-sS','--max-time','15',proto,'-D',str(d/'headers'),'-w','\n%{http_code}:%{http_version}']
                if not TCP:command+=['--unix-socket',str(d/('h2.sock' if proto=='--http2-prior-knowledge' else 'h1.sock'))]
                target='http://127.0.0.1:'+str(ports[1 if proto=='--http2-prior-knowledge' else 0]) if TCP else 'http://node.example.com'
                for header in headers:command+=['-H',header]
                if body is not None:command+=['--data',json.dumps(body)]
                r=subprocess.run(command+[target+path],capture_output=True,check=True)
                content,status=r.stdout.rsplit(b'\n',1);return content,status.decode(),(d/'headers').read_text()
            for proto,version in [('--http1.1','1.1'),('--http2-prior-knowledge','2')]:
                body,status,headers=request('/?habitat=water&q=Pikachu',proto)
                check(status=='200:'+version and 'PokéHabitat' in body.decode(),'Complete local SPA serves '+version)
                check("connect-src 'self'" in headers,'Browser connections limited to same origin')
            for file in sorted((ROOT/'site/dist').rglob('*')):
                if file.is_file():
                    body,status,_=request('/'+file.relative_to(ROOT/'site/dist').as_posix())
                    check(status=='200:1.1' and hashlib.sha256(body).digest()==hashlib.sha256(file.read_bytes()).digest(),'Bundled asset '+file.name)
            origin=['Origin: https://node.example.com','Content-Type: application/json']
            body,status,headers=request('/api/game/auth/register',headers=origin,body={'username':'fixture_player','password':'a safe isolated test password','starter':1})
            data=json.loads(body);check(status=='201:1.1' and len(data['profile']['cards'])==3,'Local registration and three starting cards')
            cookie=next(x.split(':',1)[1].strip().split(';')[0] for x in headers.splitlines() if x.lower().startswith('set-cookie:'))
            check('HttpOnly' in headers and 'Secure' in headers and 'SameSite=Lax' in headers,'Secure host session cookie')
            body,status,_=request('/api/game/me',headers=['Cookie: '+cookie]);check(json.loads(body)['profile']['username']=='fixture_player','Local session authenticates')
            body,status,_=request('/api/game/team',headers=['Origin: https://evil.example'],body={});check(status=='403:1.1','Foreign Origin rejected')
            body,status,_=request('/api/game/team',headers=['Content-Type: application/json'],body={});check(status=='403:1.1' and json.loads(body)['error']=='origin','Missing POST Origin stays untrusted')
            body,status,_=request('/api/game/pack',headers=origin+['Cookie: '+cookie],body={'key':'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'});check(status=='409:1.1' and json.loads(body)['error']=='coins','Game status and JSON preserved')
            body,status,_=request('/api/game/me',headers=['Origin: https://evil.example']);check(status=='403:1.1','Foreign reads rejected')
            body,status,_=request('/assets/missing.js');check(status=='404:1.1','Missing asset never served as HTML')
            fixture.close();body,status,_=request('/api/game/me');check(status=='503:1.1' and json.loads(body)['error']=='unavailable','Stopped API returns local JSON 503')
            body,status,_=request('/');check(status=='200:1.1','Atlas remains available when game service stops')
            body,status,_=request('/_game_unavailable.json');check(status=='404:1.1','Internal API error route is private')
            print(json.dumps({'suite':'autonomous nginx + game','checks':checks,'transport':'loopback TCP test fixture' if TCP else 'real Unix sockets','status':'passed'}))
        finally:
            if proc and proc.poll() is None:
                proc.send_signal(signal.SIGQUIT)
                try:proc.wait(timeout=5)
                except subprocess.TimeoutExpired:proc.kill();proc.wait()
            fixture.close()
if __name__=='__main__':main()
