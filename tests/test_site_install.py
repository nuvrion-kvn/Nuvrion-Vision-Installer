"""Local installation preserves player identity and refuses unsafe destinations."""
import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
spec=importlib.util.spec_from_file_location('site_install',ROOT/'src/site-install.py')
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)

class SiteInstallTests(unittest.TestCase):
    def test_installer_umask_and_resume_permissions(self):
        with tempfile.TemporaryDirectory() as td:
            bundle,node=self.setup_fixture(Path(td))
            for source,relative in [('public','pokemon/1.webp'),('server','migrations/0000.sql')]:
                path=bundle/source/relative;path.parent.mkdir();path.write_bytes(b'fixture')
            old=os.umask(0o077)
            try:
                module.install_site(bundle,'node.example.com',node)
                database=node/'var/lib/nuvrion-pokehabitat/game.sqlite'
                database.parent.mkdir(parents=True);database.write_bytes(b'private progress')
                for target in ['var/www/decoy','usr/local/lib/nuvrion-pokehabitat']:
                    root=node/target
                    for path in [root,*root.rglob('*')]:path.chmod(0o700 if path.is_dir() else 0o600)
                module.install_site(bundle,'node.example.com',node)
            finally:os.umask(old)
            for target in ['var/www/decoy','usr/local/lib/nuvrion-pokehabitat']:
                root=node/target
                for path in [root,*root.rglob('*')]:
                    self.assertEqual(path.stat().st_mode&0o777,0o755 if path.is_dir() else 0o644,str(path))
            self.assertEqual(database.read_bytes(),b'private progress')
            self.assertEqual(database.stat().st_mode&0o777,0o600)
            self.assertEqual(database.parent.stat().st_mode&0o777,0o700)
            self.assertEqual((node/'etc/nuvrion-pokehabitat.env').stat().st_mode&0o777,0o600)
    def setup_fixture(self,root):
        bundle=root/'bundle';(bundle/'public').mkdir(parents=True);(bundle/'server').mkdir()
        (bundle/'public/index.html').write_text('local atlas')
        (bundle/'server/server.mjs').write_text('local game')
        return bundle,root/'node'
    def test_resume_preserves_secret_and_player_database(self):
        with tempfile.TemporaryDirectory() as td:
            bundle,node=self.setup_fixture(Path(td));module.install_site(bundle,'node.example.com',node)
            secret=(node/'etc/nuvrion-pokehabitat.env').read_bytes()
            data=node/'var/lib/nuvrion-pokehabitat/game.sqlite';data.parent.mkdir(parents=True);data.write_bytes(b'player-progress-fixture')
            (bundle/'public/index.html').write_text('updated local atlas')
            module.install_site(bundle,'node.example.com',node)
            self.assertEqual((node/'etc/nuvrion-pokehabitat.env').read_bytes(),secret)
            self.assertEqual(data.read_bytes(),b'player-progress-fixture')
            self.assertEqual((node/'var/www/decoy/index.html').read_text(),'updated local atlas')
            self.assertEqual((node/'etc/nuvrion-pokehabitat.env').stat().st_mode&0o777,0o600)
    def test_destination_symlink_is_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);bundle,node=self.setup_fixture(root)
            (node/'var/www').mkdir(parents=True);(node/'var/www/decoy').symlink_to(root/'outside')
            (root/'outside').mkdir()
            with self.assertRaises(ValueError):module.install_site(bundle,'node.example.com',node)
            self.assertEqual(list((root/'outside').iterdir()),[])
    def test_changed_origin_requires_explicit_migration(self):
        with tempfile.TemporaryDirectory() as td:
            bundle,node=self.setup_fixture(Path(td));module.install_site(bundle,'node.example.com',node)
            with self.assertRaises(ValueError):module.install_site(bundle,'different.example.com',node)
    def test_source_symlink_is_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);bundle,node=self.setup_fixture(root);(bundle/'public/leak').symlink_to('/etc/passwd')
            with self.assertRaises(ValueError):module.install_site(bundle,'node.example.com',node)
