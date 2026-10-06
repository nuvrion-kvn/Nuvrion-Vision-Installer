"""Local game fixture. Its code and SQLite are the actual bundled application."""
import os
from pathlib import Path
import re
import socket
import subprocess
import time
ROOT=Path(__file__).resolve().parents[1]

def detect_nginx_version(binary):
    r=subprocess.run([binary,'-v'],capture_output=True,text=True,check=True)
    m=re.search(r'nginx/([0-9]+\.[0-9]+\.[0-9]+)',r.stdout+r.stderr)
    if not m:raise ValueError('Cannot determine nginx version')
    return m.group(1)

class GameFixture:
    def __init__(self,directory,tcp=False):
        self.directory=Path(directory);self.sock=self.directory/'game.sock';self.port=None
        env={**os.environ,'AUTH_PEPPER':'isolated-fixture-pepper-32-chars-never-production','SITE_ORIGIN':'https://node.example.com','GAME_DB':str(self.directory/'game.sqlite'),'GAME_SOCKET':str(self.sock)}
        if tcp:
            with socket.socket() as probe:probe.bind(('127.0.0.1',0));self.port=probe.getsockname()[1]
            wrapper=self.directory/'test-server.mjs'
            wrapper.write_text(f"import {{createGameServer,initGameDatabase}} from '{(ROOT/'site/server/dist/server.mjs').as_uri()}';\ninitGameDatabase(process.env.GAME_DB,'{ROOT/'site/server/dist/migrations'}');\ncreateGameServer().listen({self.port},'127.0.0.1');\n")
            script=wrapper
        else:script=ROOT/'site/server/dist/server.mjs'
        self.log=open(self.directory/'game.log','wb');self.process=subprocess.Popen([os.environ.get('NODE','node'),str(script)],env=env,stdout=self.log,stderr=self.log)
        for _ in range(100):
            if self.process.poll() is not None:raise RuntimeError((self.directory/'game.log').read_text())
            if tcp:
                try:
                    with socket.create_connection(('127.0.0.1',self.port),timeout=.1):break
                except OSError:pass
            elif self.sock.is_socket():break
            time.sleep(.05)
        else:raise RuntimeError('Game server startup timeout')
    def configuration(self,config):
        return config.replace('http://unix:/run/nuvrion-pokehabitat/game.sock','http://127.0.0.1:'+str(self.port) if self.port else 'http://unix:'+str(self.sock))
    def close(self):
        if self.process.poll() is None:
            self.process.terminate()
            try:self.process.wait(timeout=7)
            except subprocess.TimeoutExpired:self.process.kill();self.process.wait()
        self.log.close()
