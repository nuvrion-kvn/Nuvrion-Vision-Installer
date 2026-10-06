import unittest
import tempfile
from test_shell import shell


class CleanupTests(unittest.TestCase):
    def run_cleanup(self, plan, agree=True, fail=False, changed=False):
        with tempfile.TemporaryDirectory() as tmp:
            return shell('''
ask_yes(){ [[ $AGREE == yes ]]; }
apt-get(){
  if [[ $1 == -s ]]; then
    [[ $FAIL != yes ]] || return 100
    if [[ $CHANGED == yes && -f $SEEN ]]; then echo 'Remv different [1]'; else printf '%s\\n' "$PLAN"; fi
    touch "$SEEN"
    return 0
  fi
  printf 'EXEC %s\\n' "$*"
}
cleanup_system_packages
''', {'PLAN':plan,'AGREE':'yes' if agree else 'no','FAIL':'yes' if fail else 'no','CHANGED':'yes' if changed else 'no','SEEN':tmp+'/seen'})

    def test_changed_plan_is_not_executed(self):
        p=self.run_cleanup('Remv libunused [1]',changed=True)
        self.assertEqual(p.returncode,0,p.stderr)
        self.assertNotIn('EXEC',p.stdout)

    def test_protected_removals_are_rejected(self):
        for package in ('linux-image-6.8.0-111-generic','grub-common','openssh-server','python3:amd64','docker-ce'):
            p=self.run_cleanup(f'Remv {package} [1]')
            self.assertEqual(p.returncode,0,p.stderr)
            self.assertNotIn('EXEC',p.stdout)

    def test_cleanup_empty_plan_only_cleans_cache(self):
        p=self.run_cleanup('')
        self.assertEqual(p.returncode,0,p.stderr)
        self.assertIn('autoclean',p.stdout)
        self.assertNotIn('-y autoremove',p.stdout)

    def test_cleanup_confirms_orphan_removal_and_protects_kernels(self):
        p=self.run_cleanup('Remv libunused [1]')
        self.assertEqual(p.returncode,0,p.stderr)
        self.assertIn('-y autoremove',p.stdout)
        self.assertIn('APT::NeverAutoRemove::=^linux-.*',p.stdout)
        self.assertNotIn('--purge',p.stdout)
        self.assertIn('autoclean',p.stdout)

    def test_cleanup_refusal_does_not_remove(self):
        p=self.run_cleanup('Remv libunused [1]',agree=False)
        self.assertNotIn('-y autoremove',p.stdout)
        self.assertIn('autoclean',p.stdout)

    def test_cleanup_failed_simulation_does_not_modify(self):
        p=self.run_cleanup('',fail=True)
        self.assertEqual(p.returncode,0,p.stderr)
        self.assertNotIn('EXEC',p.stdout)

    def test_cleanup_rejects_install_or_configure_actions(self):
        for plan in ('Inst pkg [1] (2 repo)','Conf pkg (2 repo)'):
            p=self.run_cleanup(plan)
            self.assertNotIn('EXEC',p.stdout)
