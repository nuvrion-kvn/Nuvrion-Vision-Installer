import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('recovery', ROOT / 'tools/fix-tc-nft109.py')
recovery = importlib.util.module_from_spec(spec)
spec.loader.exec_module(recovery)


class RecoveryTests(unittest.TestCase):
    def test_exact_old_to_new_and_repeat(self):
        new = (ROOT / 'src/nuvrion-traffic-control.py').read_bytes()
        old = new.replace(recovery.INSERT, b'', 1)
        self.assertEqual(recovery.corrected(old), new)
        self.assertEqual(recovery.corrected(new), new)

    def test_rejects_modified_revision(self):
        new = (ROOT / 'src/nuvrion-traffic-control.py').read_bytes()
        with self.assertRaises(ValueError):
            recovery.corrected(new + b'\n# user modification\n')
