"""Exercise only extracted numeric guards; never execute the tuning script."""
import os
from pathlib import Path
import re
import subprocess
import unittest

SOURCE = (Path(__file__).resolve().parents[1]/'vendor/nuvrion-auto-tuning.sh').read_text(encoding='utf-8')


class TuningNumbersTests(unittest.TestCase):
    def test_nofile_pair_validation_uses_decimal_and_rejects_overflow(self):
        function = re.search(r'^nofile_pair_ok\(\) \{\n.*?^\}', SOURCE, re.M|re.S).group()
        for pair, status in [('1048576/1048576',0), ('02000000/02000000',0),
                             ('unlimited/infinity',0), ('1024/1048576',1),
                             ('1048576/ignored/1048576',1), ('08/09',1),
                             ('18446744073709551617/1048576',1)]:
            with self.subTest(pair=pair):
                process = subprocess.run(['bash','-c',function+'\nNOFILE_TARGET=1048576; nofile_pair_ok "$PAIR"'],
                    env={**os.environ,'PAIR':pair},capture_output=True,text=True,timeout=5)
                self.assertEqual(process.returncode,status,process.stderr)
                self.assertEqual(process.stderr,'')

    def test_api_port_environment_cannot_wrap_integer_bounds(self):
        guard = SOURCE[SOURCE.index('PANEL_PORT_ENV=${NUVRION_PANEL_PORT:-}'):SOURCE.index('PANEL_PORT_FILE=')]
        # 2**64 + 2222 must not become the valid port 2222 through overflow.
        for value, expected in [('02222','2222'),('18446744073709553838',''),('08','8'),('0',''),('65536',''),('x','')]:
            with self.subTest(value=value):
                process = subprocess.run(['bash','-c','set -euo pipefail\nwarn(){ :; }\n'+guard+'\nprintf "%s" "$PANEL_PORT_ENV"'],
                    env={**os.environ,'NUVRION_PANEL_PORT':value},capture_output=True,text=True,timeout=5)
                self.assertEqual(process.returncode,0,process.stderr)
                self.assertEqual(process.stdout,expected)
                self.assertEqual(process.stderr,'')
