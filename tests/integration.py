#!/usr/bin/env python3
"""Real Xray+nginx loopback tests. No Docker, sysctl, firewall or real CA changes.

Usage: python3 tests/integration.py /path/to/xray /path/to/nginx /path/to/mime.types
Requires curl with HTTP/2 and openssl. Temporary self-signed certificates are TEST ONLY.
"""
import contextlib
from http.server import BaseHTTPRequestHandler, HTTPServer
import shutil
import json
import os
from pathlib import Path
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import uuid

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
import runtime
from proxy_fixture import detect_nginx_version

XRAY, NGINX, MIME = map(lambda x: str(Path(x).resolve()), sys.argv[1:4])
CURL = '/usr/bin/curl'
ROOT = Path(__file__).resolve().parents[1]


def run(*args, **kw):
    result=subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=20,**kw)
    if result.returncode:
        raise AssertionError(f'Command failed: {args[0:4]}\n{result.stderr.decode()}\n{result.stdout.decode()}')
    return result.stdout.decode().strip()


def port():
    with socket.socket() as s:
        s.bind(('127.0.0.1',0));return s.getsockname()[1]


def wait_for(fn):
    for _ in range(80):
        if fn():return
        time.sleep(.1)
    raise AssertionError('Readiness timeout')


def ready(p):
    try:
        with socket.create_connection(('127.0.0.1',p),timeout=.2):return True
    except OSError:return False


def main():
    processes=[]
    with tempfile.TemporaryDirectory(prefix='cbv-') as directory:
        d=Path(directory);d.chmod(0o755)
        (d/'logs').mkdir()
        run('openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','2',
            '-keyout',str(d/'key.pem'),'-out',str(d/'cert.pem'),'-subj','/CN=node.example.com',
            '-addext','subjectAltName=DNS:node.example.com')
        s=runtime.validate(dict(domain='node.example.com',panel_ips='203.0.113.10',
                                email='operator@example.com',nginx_version=detect_nginx_version(NGINX)))
        p=runtime.profile(s)
        server_port,client_port,backend_port=port(),port(),port()
        inbound=p['inbounds'][0];inbound['port']=server_port;inbound['listen']='127.0.0.1'
        uid=str(uuid.uuid4())
        inbound['settings']['clients']=[{'id':uid,'flow':'xtls-rprx-vision'}]
        cert=inbound['streamSettings']['tlsSettings']['certificates'][0]
        cert.update(keyFile=str(d/'key.pem'),certificateFile=str(d/'cert.pem'))
        for fb in inbound['settings']['fallbacks']:fb['dest']=str(d/Path(fb['dest']).name)
        # One explicit loopback fixture exception enables authenticated proxy testing.
        # The production private-network blocking rules remain unchanged below it.
        p['routing']['rules'].insert(0,{'type':'field','ip':['127.0.0.1'],'port':str(backend_port),'outboundTag':'DIRECT'})
        # Xray 26.7.28 also blocks private destinations inside Freedom itself.
        # Permit only this test backend; production defaults remain unchanged.
        p['outbounds'][0]['settings']={'finalRules':[{'action':'allow','network':'tcp',
                                                   'ip':['127.0.0.1/32'],'port':str(backend_port)}]}
        (d/'server.json').write_text(json.dumps(p))
        env=dict(os.environ,XRAY_LOCATION_ASSET=str(Path(XRAY).parent))
        run(XRAY,'run','-test','-config',str(d/'server.json'),env=env)
        print('PASS Xray parses generated profile, TLS files and every geo category',flush=True)
        n=runtime.nginx(s)
        n=n.replace('/opt/remnanode/fallback-sockets',str(d)).replace('/var/www/decoy',str(d))
        (d/'nginx-run').mkdir()
        n=n.replace('/etc/nginx/mime.types',MIME).replace('/var/log/nginx/nuvrion-error.log',str(d/'nginx.log')).replace('/run/nuvrion-nginx',str(d/'nginx-run'))
        n=n.replace('worker_processes auto;','worker_processes 1;')
        # The development sandbox maps only its current UID; production uses www-data.
        import pwd
        n=n.replace('user www-data;',f'user {pwd.getpwuid(os.getuid()).pw_name};')
        (d/'nginx.conf').write_text(n)
        shutil.copytree(ROOT/'site/dist',d/'public')
        n=n.replace('root '+str(d)+';', 'root '+str(d/'public')+';')
        (d/'nginx.conf').write_text(n)
        run(NGINX,'-t','-p',str(d)+'/', '-c',str(d/'nginx.conf'))
        logs=[]
        def launch(args,name):
            log=open(d/name,'wb');logs.append(log)
            proc=subprocess.Popen(args,stdout=log,stderr=log,env=env);processes.append(proc);return proc
        try:
            ng=launch([NGINX,'-p',str(d)+'/', '-c',str(d/'nginx.conf'),'-g','daemon off;'],'nginx-process.log')
            wait_for(lambda:(d/'h1.sock').is_socket() and (d/'h2.sock').is_socket())
            for proto,sock,expected in [('--http1.1','h1.sock','200:1.1'),('--http2-prior-knowledge','h2.sock','200:2')]:
                status=run(CURL,'--noproxy','*','-fsS',proto,'--unix-socket',str(d/sock),'-o','/dev/null','-w','%{http_code}:%{http_version}','http://localhost/')
                assert status==expected,status
            print('PASS Unix HTTP/1.1 and h2c both return 200',flush=True)
            xr=launch([XRAY,'run','-config',str(d/'server.json')],'xray-server.log');wait_for(lambda:ready(server_port))
            def tls(proto,expected):
                status=run(CURL,'--noproxy','*','-fsS',proto,'--tlsv1.3','--cacert',str(d/'cert.pem'),
                           '--resolve',f'node.example.com:{server_port}:127.0.0.1','-o','/dev/null','-w','%{http_code}:%{http_version}',f'https://node.example.com:{server_port}/')
                assert status==expected,status
            tls('--http1.1','200:1.1');tls('--http2','200:2')
            print('PASS TLS 1.3 -> Xray -> Unix fallback -> nginx HTTP/1.1 and HTTP/2 (verified cert)',flush=True)
            expected_cert=ssl.PEM_cert_to_DER_cert((d/'cert.pem').read_text())
            for sni in (None,'wrong.example.com'):
                context=ssl.create_default_context(cafile=str(d/'cert.pem'))
                # Only these probes omit hostname validation: an IP/unknown name
                # cannot match the domain certificate. Chain verification stays on.
                context.check_hostname=False
                context.minimum_version=ssl.TLSVersion.TLSv1_3
                context.set_alpn_protocols(['http/1.1'])
                with socket.create_connection(('127.0.0.1',server_port),timeout=5) as raw:
                    with context.wrap_socket(raw,server_hostname=sni) as conn:
                        assert conn.version()=='TLSv1.3',conn.version()
                        assert conn.selected_alpn_protocol()=='http/1.1'
                        assert conn.getpeercert(binary_form=True)==expected_cert
                        host=sni or '127.0.0.1'
                        conn.sendall(f'GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n'.encode())
                        with conn.makefile('rb') as response:
                            status=response.readline(4096)
                        assert status.startswith(b'HTTP/1.1 200 '),status
                print(f'PASS TLS 1.3 {"without SNI" if sni is None else "with unknown SNI"}: site certificate and HTTP 200 fallback',flush=True)
            bad=subprocess.run([CURL,'--noproxy','*','-fsS','--max-time','3','--cacert',str(d/'cert.pem'),
                                '--resolve',f'wrong.example.com:{server_port}:127.0.0.1',f'https://wrong.example.com:{server_port}/'],capture_output=True)
            assert bad.returncode==60,(bad.returncode,bad.stderr)
            print('PASS client still rejects certificate hostname mismatch',flush=True)
            client={'log':{'loglevel':'warning'},'inbounds':[{'listen':'127.0.0.1','port':client_port,'protocol':'socks','settings':{'auth':'noauth'}}],
                    'outbounds':[{'protocol':'vless','settings':{'vnext':[{'address':'127.0.0.1','port':server_port,'users':[{'id':uid,'encryption':'none','flow':'xtls-rprx-vision'}]}]},
                                  'streamSettings':{'network':'tcp','security':'tls','tlsSettings':{'serverName':'node.example.com','alpn':['h2','http/1.1'],
                                                                                             'certificates':[{'certificateFile':str(d/'cert.pem'),'usage':'verify'}]}}}]}
            (d/'client.json').write_text(json.dumps(client))
            class Handler(BaseHTTPRequestHandler):
                def do_GET(self):
                    self.send_response(200);self.end_headers();self.wfile.write(b'NUVRION_VLESS_OK')
                def log_message(self,*args):pass
            backend=HTTPServer(('127.0.0.1',backend_port),Handler)
            thread=threading.Thread(target=backend.serve_forever,daemon=True);thread.start()
            launch([XRAY,'run','-config',str(d/'client.json')],'xray-client.log');wait_for(lambda:ready(client_port))
            def proxy():
                return run(CURL,'--noproxy','','-fsS','--max-time','10','--socks5-hostname',f'127.0.0.1:{client_port}',f'http://127.0.0.1:{backend_port}/')
            assert proxy()=='NUVRION_VLESS_OK'
            print('PASS authenticated VLESS + Vision transports HTTP payload',flush=True)
            ng.send_signal(signal.SIGQUIT);ng.wait(timeout=10)
            assert proxy()=='NUVRION_VLESS_OK'
            print('PASS valid VLESS continues with nginx stopped',flush=True)
            ng=launch([NGINX,'-p',str(d)+'/', '-c',str(d/'nginx.conf'),'-g','daemon off;'],'nginx-restart.log')
            wait_for(lambda:(d/'h1.sock').is_socket() and (d/'h2.sock').is_socket())
            tls('--http1.1','200:1.1');tls('--http2','200:2')
            print('PASS fallback recovers after nginx restart without Xray restart',flush=True)
            backend.shutdown();backend.server_close()
        except Exception:
            for path in d.glob('*.log'):
                print(path.name, path.read_text(errors='replace')[-4500:])
            raise
        finally:
            for proc in reversed(processes):
                if proc.poll() is None:
                    proc.terminate()
                    try:proc.wait(timeout=5)
                    except subprocess.TimeoutExpired:proc.kill();proc.wait()
            for log in logs:log.close()


if __name__=='__main__':main()
