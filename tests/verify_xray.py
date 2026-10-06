#!/usr/bin/env python3
"""Validate settings.flow with a real pinned Xray binary; never opens listeners."""
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
import runtime


def main():
    binary=Path(sys.argv[1]).resolve()
    env=dict(os.environ,XRAY_LOCATION_ASSET=str(binary.parent))
    with tempfile.TemporaryDirectory(prefix='cbv-flow-') as td:
        p=Path(td)
        subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1',
                        '-keyout',str(p/'key.pem'),'-out',str(p/'cert.pem'),'-subj','/CN=node.example.com'],
                       check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        profile=runtime.profile(runtime.validate(json.loads((ROOT/'tests/settings.example.json').read_text())))
        profile['inbounds'][0]['streamSettings']['tlsSettings']['certificates']=[{
            'keyFile':str(p/'key.pem'),'certificateFile':str(p/'cert.pem')}]
        profile['inbounds'][0]['settings']['clients']=[{'id':'a0b62caf-a772-4563-b763-58f8b1b7e14c'}]
        for value,expected in [('xtls-rprx-vision',True),('INVALID_FLOW_TEST',False)]:
            config=copy.deepcopy(profile)
            config['inbounds'][0]['settings']['flow']=value
            (p/'config.json').write_text(json.dumps(config))
            result=subprocess.run([str(binary),'run','-test','-config',str(p/'config.json')],
                                  env=env,capture_output=True,text=True,timeout=20)
            assert (result.returncode==0)==expected,result.stdout+result.stderr
            if not expected:
                assert 'settings.flow' in result.stdout+result.stderr,result.stdout+result.stderr
            print(f'PASS settings.flow={value}: '+('Configuration OK' if expected else 'rejected by settings.flow validation'))


if __name__=='__main__':main()
