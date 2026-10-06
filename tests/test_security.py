"""Exercise security boundaries with fixtures; never change the real host."""
import contextlib
import io
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'src'))
import security_check as sec
import runtime

UFW = '''Status: active
Default: deny (incoming), allow (outgoing), deny (routed)
22/tcp                     ALLOW IN    Anywhere
443/tcp                    ALLOW IN    Anywhere
2222/tcp                   ALLOW IN    203.0.113.10
2222/tcp                   DENY IN     Anywhere
22/tcp (v6)                ALLOW IN    Anywhere (v6)
443/tcp (v6)               ALLOW IN    Anywhere (v6)
2222/tcp (v6)              DENY IN     Anywhere (v6)
'''


class SecurityTests(unittest.TestCase):
    def test_owned_traffic_control_is_embedded(self):
        installer = (ROOT/'src/installer.sh').read_text(encoding='utf-8')
        tuning = (ROOT/'vendor/nuvrion-auto-tuning.sh').read_text(encoding='utf-8')
        traffic_control = (ROOT/'src/nuvrion-traffic-control.py').read_text(encoding='utf-8')
        self.assertIn('VERSION = "1.0.0"', traffic_control)
        self.assertIn('input(confirmation_prompt(label + " [Д/Н; Enter — Н]: "))', traffic_control)
        self.assertIn('module.main(args)', installer)
        self.assertIn('settings = json.loads(settings_path.read_text', installer)
        self.assertIn('Автоматически использованы параметры текущего SSH-подключения', installer)
        self.assertIn('/usr/local/bin/nuvrion-traffic-control activate', installer)
        self.assertNotIn('DonMatteoVPN', installer + tuning)
        self.assertNotIn('TrafficGuard', installer + tuning + traffic_control)


    def test_install_prompt_and_final_component_report(self):
        installer = (ROOT/'src/installer.sh').read_text(encoding='utf-8')
        self.assertIn("confirm_install() { ask_yes 'Установить на машину Nuvrion Vision?'; }", installer)
        report = (ROOT/'src/component_report.py').read_text(encoding='utf-8')
        self.assertIn("ui.heading('ИТОГОВЫЙ ОТЧЁТ ПО КОМПОНЕНТАМ')", report)
        self.assertIn("installation_report \"$rc\"", installer)
        self.assertIn('component_report.py', installer)
        self.assertIn('"$BOLD" "$YELLOW" "$1"', installer)
        for component in ('Docker Engine', 'RemnaNode', 'API ноды (mTLS)', 'Xray Core',
                          'nginx и автономный сайт', 'TLS-сертификат',
                          'Nuvrion Traffic Control', 'Профиль TLS/443'):
            self.assertIn(component, report)

    def test_release_version_and_component_order(self):
        installer = (ROOT/'src/installer.sh').read_text(encoding='utf-8')
        self.assertIn('readonly NUVRION_VERSION=1.0.0', installer)
        self.assertNotIn('experimental', installer.lower())
        self.assertNotIn('эксперимент', installer.lower())
        sequence = [
            installer.rindex('\n    apply_tuning\n'),
            installer.rindex('\n    harden_host\n'),
            installer.rindex('\n    start_stack\n'),
            installer.rindex('\n    issue_certificate\n'),
            installer.rindex('\n    install_traffic_control\n'),
            installer.rindex("\n    step 'ИТОГИ УСТАНОВКИ / Проверка компонентов'"),
        ]
        self.assertEqual(sequence, sorted(sequence))

    def test_two_way_ping_protection_is_installed_and_checked(self):
        installer = (ROOT/'src/installer.sh').read_text(encoding='utf-8')
        helper = (ROOT/'src/nuvrion-two-way-ping.sh').read_text(encoding='utf-8')
        unit = (ROOT/'src/nuvrion-two-way-ping.service').read_text(encoding='utf-8')
        for rule in ('icmp type echo-request', 'icmp type timestamp-request',
                     'icmpv6 type echo-request'):
            self.assertIn(rule, helper)
        self.assertNotIn('echo-reply', helper)
        self.assertIn('DefaultDependencies=no', unit)
        self.assertIn('Before=network-pre.target', unit)
        self.assertIn('ConditionFileIsExecutable=', unit)
        self.assertIn('systemctl enable --now nuvrion-two-way-ping.service', installer)
        self.assertGreaterEqual(installer.count('check_two_way_ping'), 3)

    def test_application_version_is_independent_from_os_release(self):
        installer = (ROOT/'src/installer.sh').read_text(encoding='utf-8')
        self.assertIn('readonly NUVRION_VERSION=', installer)
        self.assertIn('os_identity() (', installer)
        self.assertIn("ID='' VERSION_ID='' VERSION_CODENAME='' UBUNTU_CODENAME=''", installer)

    def test_manager_source_has_no_payload_placeholder_or_payload_function(self):
        installer = (ROOT/'src/installer.sh').read_text(encoding='utf-8')
        self.assertNotIn('@PAYLOAD_SHA256@', installer)
        self.assertNotIn('\npayload() {', installer)
        self.assertEqual(installer.count('# Private child entry'), 1)

    def test_firewall_accepts_exact_panel_ip(self):
        sec.firewall(UFW, 2222, '203.0.113.10')

    def test_firewall_rejects_bypasses_and_open_acme(self):
        for rule in ('2222/tcp    ALLOW IN    Anywhere',
                     '2222/tcp (v6)    ALLOW IN    Anywhere (v6)',
                     '2222/tcp    ALLOW IN    203.0.113.99',
                     '2222/tcp    ALLOW IN    203.0.113.0/24',
                     '2000:3000/tcp    ALLOW IN    Anywhere',
                     '22,2222/tcp    LIMIT IN    Anywhere',
                     'Anywhere    ALLOW IN    203.0.113.10',
                     '80/tcp    ALLOW IN    Anywhere',
                     '80/tcp    ALLOW IN    203.0.113.10'):
            with self.subTest(rule=rule), self.assertRaises(sec.CheckFailure):
                sec.firewall(UFW+rule+'\n', 2222, '203.0.113.10')

    def test_firewall_rejects_missing_allow_and_inactive(self):
        for text in (UFW.replace('Status: active','Status: inactive'),
                     UFW.replace('deny (incoming)','allow (incoming)'),
                     UFW.replace('2222/tcp                   ALLOW IN    203.0.113.10','')):
            with self.assertRaises(sec.CheckFailure): sec.firewall(text,2222,'203.0.113.10')

    def test_cancel_after_collection_does_not_render_or_print_secret(self):
        answers=['node.example.com','','203.0.113.10','a@example.com','','','']
        output=io.StringIO()
        with patch('builtins.input',side_effect=answers), \
             patch.object(runtime.getpass,'getpass',return_value='SECRET_TEST_ONLY'), \
             patch.object(runtime,'validate_key'),patch.object(runtime,'render') as render, \
             contextlib.redirect_stdout(output),self.assertRaises(KeyboardInterrupt):
            runtime.collect('/unused')
        render.assert_not_called()
        self.assertNotIn('SECRET_TEST_ONLY',output.getvalue())

    def test_ssh_preserves_forwarding_and_rolls_back_conflicting_effective_config(self):
        source=(ROOT/'src/hardening.sh').read_text()
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            for name in ('node','etc/ssh/sshd_config.d','etc/sysctl.d','bin'):
                (root/name).mkdir(parents=True,exist_ok=True)
            (root/'node/.nuvrion-managed').touch()
            dropin=root/'etc/ssh/sshd_config.d/00-nuvrion-vision.conf'
            original='# existing owned configuration\n'
            harness=(source.replace('/opt/remnanode',str(root/'node'))
                    .replace('/etc/',str(root/'etc')+'/')
                    .replace('/run/sshd',str(root/'run/sshd')))
            (root/'bin/install').write_text('#!/bin/bash\nmkdir -p -- "${@: -1}"\n')
            (root/'bin/sshd').write_text('''#!/bin/bash
[[ $1 == -t ]] && exit 0
printf 'allowtcpforwarding %s\npasswordauthentication yes\npubkeyauthentication yes\npermitrootlogin prohibit-password\nkbdinteractiveauthentication no\nauthenticationmethods any\n' "${FORWARD_MODE:-yes}"
if grep -q '^MaxAuthTries' "$TEST_DROPIN"; then
  if [[ $AUTH_TRIES == signal ]]; then kill -TERM "$PPID"; exit 0; fi
  printf 'maxauthtries %s\nlogingracetime 30\nallowagentforwarding no\npermittunnel no\nx11forwarding no\ngatewayports no\n' "$AUTH_TRIES"
else
  printf 'maxauthtries 6\n'
fi
''')
            (root/'bin/systemctl').write_text('''#!/bin/bash
if [[ $1 == is-active ]]; then
  [[ $3 == "ssh.$SSH_TEST_MODE" ]]
  exit
fi
printf 'systemctl %s\n' "$*" >> "$TEST_EVENTS"
''')
            (root/'bin/sysctl').write_text('#!/bin/bash\nprintf "sysctl %s\\n" "$*" >> "$TEST_EVENTS"\n')
            for p in (root/'bin').iterdir(): p.chmod(0o700)
            for tries in ('3','6','signal'):
                dropin.write_text(original)
                events=root/'events';events.write_text('')
                env={**os.environ,'PATH':str(root/'bin')+':'+os.environ['PATH'],
                     'TEST_DROPIN':str(dropin),'TEST_EVENTS':str(events),'AUTH_TRIES':tries,
                     'FORWARD_MODE':'local','SSH_TEST_MODE':'service'}
                p=subprocess.run(['bash','-c',harness],env=env,capture_output=True,text=True,timeout=10)
                self.assertEqual(p.returncode==0,tries=='3',p.stderr)
                if tries=='3':
                    self.assertIn('systemctl try-reload-or-restart ssh.service',events.read_text())
                    self.assertNotIn('AllowTcpForwarding ', '\n'.join(x for x in dropin.read_text().splitlines() if not x.startswith('#')))
                else:
                    self.assertEqual(dropin.read_text(),original)
                    self.assertIn('systemctl try-reload-or-restart ssh.service',events.read_text())

            dropin.write_text(original)
            events.write_text('')
            env.update({'AUTH_TRIES':'3','SSH_TEST_MODE':'socket'})
            p=subprocess.run(['bash','-c',harness],env=env,capture_output=True,text=True,timeout=10)
            self.assertEqual(p.returncode,0,p.stderr)
            self.assertIn('systemctl daemon-reload',events.read_text())
            self.assertNotIn('try-reload-or-restart',events.read_text())

    def test_ssh_validation_recovers_missing_runtime_directory(self):
        source=(ROOT/'src/hardening.sh').read_text().split('SSH_DROPIN=')[0]
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            base=root/'node';base.mkdir()
            (base/'.nuvrion-managed').touch()
            runtime_dir=root/'run/sshd'
            bin_dir=root/'bin';bin_dir.mkdir()
            (bin_dir/'systemctl').write_text('#!/bin/bash\n[[ $* == "is-active --quiet ssh.service" ]]\n')
            (bin_dir/'install').write_text('#!/bin/bash\nmkdir -p -- "${@: -1}"\n')
            (bin_dir/'sshd').write_text('''#!/bin/bash
[[ -d $TEST_RUNTIME_DIR ]] || { echo 'Missing privilege separation directory' >&2; exit 255; }
[[ $1 == -T ]] && printf 'port 22\n'
exit 0
''')
            for stub in bin_dir.iterdir(): stub.chmod(0o700)
            harness=source.replace('/opt/remnanode',str(base)).replace('/run/sshd',str(runtime_dir))
            env={**os.environ,'PATH':str(bin_dir)+':'+os.environ['PATH'],
                 'TEST_RUNTIME_DIR':str(runtime_dir)}
            for _ in range(2):
                p=subprocess.run(['bash','-c',harness],env=env,capture_output=True,text=True,timeout=10)
                self.assertEqual(p.returncode,0,p.stderr)
                self.assertTrue(runtime_dir.is_dir())
                self.assertIn('port 22',(base/'backups/sshd-effective-before.txt').read_text())


if __name__ == '__main__': unittest.main(verbosity=2)
