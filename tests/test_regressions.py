"""Audit regressions: only fixtures, never host packages, firewall or services."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from test_shell import SOURCE, shell
from test_runtime import SETTINGS
import runtime

ROOT = Path(__file__).resolve().parents[1]


class AuditTests(unittest.TestCase):
    def test_game_api_waits_for_socket_after_active_service(self):
        with tempfile.TemporaryDirectory() as td:
            count=Path(td)/'count';count.write_text('0')
            p=shell("""systemctl(){ [[ "$*" == 'is-active --quiet nuvrion-pokehabitat.service' ]]; }
sleep(){ :; }
curl(){
  [[ " $* " == *" --unix-socket /run/nuvrion-pokehabitat/game.sock "* ]] || return 91
  [[ " $* " == *" --max-time 2 "* ]] || return 92
  local n; n=$(cat "$PROBE_COUNT"); n=$((n+1)); printf '%s' "$n" > "$PROBE_COUNT"
  if ((n==1)); then printf 000; return 7; fi
  if ((n==2)); then printf 503; return 0; fi
  printf 200
}
wait_game_api
echo READY
""",{'PROBE_COUNT':str(count)})
            self.assertEqual(p.returncode,0,p.stderr)
            self.assertEqual(count.read_text(),'3')
            self.assertIn('READY',p.stdout)
            self.assertEqual(p.stderr,'')

    def test_game_api_failure_is_bounded_and_reports_service_journal(self):
        for service,reply,exit_code in [(0,'000',7),(0,'503',0),(1,'200',0)]:
            with self.subTest(service=service,reply=reply):
                with tempfile.TemporaryDirectory() as td:
                    count=Path(td)/'count';count.write_text('0')
                    p=shell(f"""systemctl(){{ return {service}; }}
sleep(){{ local n; n=$(cat "$PROBE_COUNT"); printf '%s' "$((n+1))" > "$PROBE_COUNT"; }}
curl(){{ printf {reply}; return {exit_code}; }}
wait_game_api
echo UNEXPECTED
""",{'PROBE_COUNT':str(count)})
                    self.assertEqual(p.returncode,1)
                    self.assertEqual(count.read_text(),'9')
                    self.assertIn('journalctl -u nuvrion-pokehabitat.service',p.stderr)
                    self.assertNotIn('остановка на строке',p.stderr)
                    self.assertNotIn('UNEXPECTED',p.stdout)

    def test_python_utf8_overrides_disabled_environment(self):
        p = shell("python3 -c 'import sys; print(sys.flags.utf8_mode); print(chr(1055))'", {'PYTHONUTF8': '0'})
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(p.stdout, '1\nП\n')

    def test_http_probe_reports_transport_failure_without_generic_trap(self):
        for code in (7, 28, 60):
            p = shell(f'''curl(){{ return {code}; }}
result=$(probe_http 'сокет HTTP/1.1' http://localhost/) || exit 1
echo UNEXPECTED
''')
            self.assertEqual(p.returncode, 1)
            self.assertIn('Не удалось выполнить проверку: сокет HTTP/1.1', p.stderr)
            self.assertNotIn('остановка на строке', p.stderr)
            self.assertNotIn('UNEXPECTED', p.stdout)

    def test_http_probe_bounds_time_and_preserves_http_status(self):
        p = shell('''curl(){
  [[ " $* " == *" --connect-timeout 5 "* ]] || return 91
  [[ " $* " == *" --max-time 35 "* ]] || return 92
  printf 503
}
probe_http 'HTTP/2' http://localhost/
''')
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(p.stdout, '503')

    def test_os_fields_are_optional_and_do_not_leak(self):
        with tempfile.TemporaryDirectory() as td:
            release = Path(td)/'os-release'
            release.write_text('ID=debian\nVERSION="testing"\nLOGO=leaked\n')
            source = SOURCE.replace('/etc/os-release', str(release))
            p = subprocess.run(['bash', '-c', source + '\nLOGO=original; identity=$(os_identity); printf "%s|%s|%s" "$identity" "$LOGO" "$NUVRION_VERSION"'], capture_output=True, text=True)
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertEqual(p.stdout, 'debian::|original|1.0.0')

    def test_cli_rejects_extra_args(self):
        for cmd in ('--install', '--resume', '--check', '--show', '--preview', '--version'):
            p = shell(f'main {cmd} unexpected')
            self.assertEqual(p.returncode, 1)
            self.assertIn('не принимает дополнительные аргументы', p.stderr)

    def test_version_without_root(self):
        p = shell('require_server(){ exit 99; }; main --version')
        self.assertEqual(p.returncode, 0)
        self.assertEqual(p.stdout.strip(), '1.0.0')

    def test_cyrillic_answers_with_c_locale_and_redirected_stdout(self):
        with tempfile.TemporaryDirectory() as td:
            answer = Path(td)/'answer'; prompt = Path(td)/'prompt'
            source = SOURCE.replace('> /dev/tty', '> "$PROMPT_FILE"').replace('< /dev/tty', '< "$ANSWER_FILE"')
            for value, expected in [('Да', 'YES'), ('дА', 'YES'), ('yEs', 'YES'),
                                    ('НеТ', 'NO'), ('нЕТ', 'NO'), ('', 'NO')]:
                answer.write_text(value+'\n')
                p = subprocess.run(['bash', '-c', source + '\nif ask_yes "Проверка"; then echo YES; else echo NO; fi'],
                    capture_output=True, text=True, timeout=3,
                    env={**os.environ, 'PROMPT_FILE': str(prompt), 'ANSWER_FILE': str(answer)})
                self.assertEqual(p.returncode, 0, p.stderr)
                self.assertEqual(p.stdout.strip(), expected)
                self.assertIn('Проверка', prompt.read_text())

    def test_confirmation_prompt_is_bold_yellow(self):
        with tempfile.TemporaryDirectory() as td:
            answer = Path(td)/'answer'; prompt = Path(td)/'prompt'
            answer.write_text('д\n')
            source = SOURCE.replace('> /dev/tty', '> "$PROMPT_FILE"').replace('< /dev/tty', '< "$ANSWER_FILE"')
            p = subprocess.run(['bash', '-c', source + "\nBOLD=BOLD; YELLOW=YELLOW; RESET=RESET; ask_yes 'Проверка'"],
                capture_output=True, text=True, timeout=3,
                env={**os.environ, 'PROMPT_FILE': str(prompt), 'ANSWER_FILE': str(answer)})
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertIn('BOLDYELLOWПроверка [Д/Н; Enter — Н]: RESET', prompt.read_text())

    def test_report_statuses_start_in_one_column(self):
        p = subprocess.run([sys.executable, '-c', "import terminal_ui as ui; "
                            "[ui.row(name, 'ГОТОВО') for name in ['Система и пакеты', 'Docker Engine', 'Nuvrion Traffic Control']]"],
                           capture_output=True, text=True,
                           env={**os.environ, 'PYTHONPATH': str(ROOT/'src'), 'COLUMNS': '80'})
        self.assertEqual(p.returncode, 0, p.stderr)
        positions = {line.index('ГОТОВО') for line in p.stdout.splitlines()}
        self.assertEqual(positions, {36})

    def test_apt_removals_visible_and_not_executed(self):
        for plan in ('Remv old [1]', 'Inst new (2 test)\nInst old [1] (2 test)\nRemv removed [1]'):
            p = shell('''
ask_yes(){ echo ASKED; return 0; }
apt-get(){ [[ $1 == -s ]] && { printf '%s\n' "$PLAN"; return; }; echo EXECUTED; }
apt_confirmed full-upgrade
''', {'PLAN': plan})
            self.assertEqual(p.returncode, 1)
            self.assertIn('Удаляемые пакеты', p.stdout)
            self.assertIn(plan.splitlines()[-1], p.stdout)
            self.assertNotIn('EXECUTED', p.stdout)
            self.assertNotIn('ASKED', p.stdout)

    def test_apt_changed_plan_reuses_run_consent(self):
        with tempfile.TemporaryDirectory() as td:
            p = shell('''
ask_yes(){ echo CONSENT; return 0; }
apt-get(){
  if [[ $1 == -s ]]; then
    local n=0; [[ ! -f $COUNTER ]] || n=$(<"$COUNTER")
    n=$((n+1)); printf '%s' "$n" > "$COUNTER"
    if (( n == 1 )); then echo 'Inst pkg [1] (2 test)'; else echo 'Inst pkg [1] (3 test)'; fi
  else printf 'EXECUTED %s\n' "$*"; fi
}
apt_confirmed install --no-install-recommends pkg
''', {'COUNTER': str(Path(td)/'count')})
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertEqual(p.stdout.count('CONSENT'), 1)
            self.assertIn('--no-remove -y install --no-install-recommends pkg', p.stdout)

    def test_multiple_apt_plans_require_one_consent(self):
        p = shell('''
ask_yes(){ echo CONSENT; return 0; }
apt-get(){
  if [[ $1 == -s ]]; then echo 'Inst pkg (1 test)';
  else printf 'EXECUTED %s\n' "$*"; fi
}
apt_confirmed install first
apt_confirmed install second
''')
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(p.stdout.count('CONSENT'), 1)
        self.assertEqual(p.stdout.count('EXECUTED'), 2)

    def test_apt_cancel_and_failed_recheck(self):
        for consent, fail in ((1, 0), (0, 1)):
            with tempfile.TemporaryDirectory() as td:
                p = shell('''
ask_yes(){ return "$CONSENT"; }
apt-get(){
  if [[ $1 == -s ]]; then
    if [[ -f $COUNTER && $FAIL == 1 ]]; then return 100; fi
    touch "$COUNTER"; echo 'Inst pkg (1 test)'
  else echo EXECUTED; fi
}
apt_confirmed full-upgrade
''', {'CONSENT': str(consent), 'FAIL': str(fail), 'COUNTER': str(Path(td)/'count')})
                self.assertEqual(p.returncode, 1)
                self.assertNotIn('EXECUTED', p.stdout)

    def test_nat_query_errors_stop(self):
        for fail in ('iptables', 'ip6tables', 'nft'):
            p = shell('''
iptables(){ [[ $FAIL != iptables ]]; }; ip6tables(){ [[ $FAIL != ip6tables ]]; }
nft(){ [[ $FAIL != nft ]]; }
check_nat
echo CONTINUED
''', {'FAIL': fail})
            self.assertEqual(p.returncode, 1)
            self.assertNotIn('CONTINUED', p.stdout)

    def test_nat_sets_require_manual_review(self):
        p = shell('iptables(){ :; }; ip6tables(){ :; }; nft(){ echo "tcp dport { 443, 8443 } dnat to 192.0.2.1"; }; check_nat')
        self.assertEqual(p.returncode, 1)
        self.assertIn('DNAT/REDIRECT', p.stderr)

    def test_ssh_mixed_case_and_empty_lines(self):
        with tempfile.TemporaryDirectory() as td:
            config = Path(td)/'sshd_config'; config.write_text('\n# comment\nPoRt 2222\n')
            source = SOURCE.replace('/etc/ssh/sshd_config', str(config))
            p = subprocess.run(['bash', '-c', source + '\nss(){ :; }; sshd(){ echo "port 22"; }; systemctl(){ :; }; SSH_CONNECTION=""; check_ssh_collision 2222'], capture_output=True, text=True)
            self.assertEqual(p.returncode, 1)
            self.assertIn('как порт SSH', p.stderr)

    def test_hooks_after_removal(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)/'node'; base.mkdir()
            sources = [(ROOT/'src'/name).read_text().replace('/opt/remnanode', str(base)) for name in ('acme-pre.sh', 'acme-post.sh')]
            for source in sources:
                p = subprocess.run(['bash', '-c', source], capture_output=True, text=True)
                self.assertEqual(p.returncode, 0, p.stderr)
            (base/'.nuvrion-managed').touch()
            for source in sources:
                p = subprocess.run(['bash', '-c', source], capture_output=True, text=True)
                self.assertEqual(p.returncode, 1)
                self.assertIn('ОШИБКА', p.stderr)
            (base/'.nuvrion-managed').unlink()
            helper = base/'acme-firewall.sh'; helper.write_text('#!/bin/sh\nprintf "ACTION=%s\\n" "$1"\n'); helper.chmod(0o700)
            p = subprocess.run(['bash', '-c', sources[1]], capture_output=True, text=True)
            self.assertEqual(p.returncode, 0)
            self.assertIn('ACTION=close', p.stdout)

    def fixture(self, td):
        root = Path(td); work = root/'work'; work.mkdir()
        for p in (ROOT/'src').iterdir():
            if p.is_file(): shutil.copy2(p, work/p.name)
        shutil.copy2(ROOT/'src/installer.sh', work/'installer-manager.sh')
        shutil.copy2(ROOT/'vendor/nuvrion-auto-tuning.sh', work/'nuvrion-auto-tuning.sh')
        (work/'pokehabitat/public').mkdir(parents=True)
        (work/'pokehabitat/public/index.html').write_text('isolated site fixture')
        runtime.render(SETTINGS, work/'rendered')
        base = root/'node'
        source = SOURCE.replace('readonly BASE=/opt/remnanode', f'readonly BASE={base}')
        source = source.replace('/var/www/decoy', str(root/'public/decoy')).replace('/etc/systemd/system', str(root/'units'))
        (root/'units').mkdir()
        return root, work, base, source

    def test_atomic_publication_and_bootstrap_replay(self):
        with tempfile.TemporaryDirectory() as td:
            root, work, base, source = self.fixture(td)
            p = subprocess.run(['bash', '-c', source + f'\nWORK={work}\npublish_project\n'], capture_output=True, text=True)
            self.assertEqual(p.returncode, 0, p.stderr)
            for name in ('installer.sh', '.nuvrion-managed', '.bootstrap-pending'):
                self.assertTrue((base/name).is_file(), name)
            self.assertEqual((base/'node.env').stat().st_mode & 0o777, 0o600)
            self.assertFalse((root/'public/decoy').exists())
            stubs = '\ninstall_game_site(){ install -m 644 "$BASE/bootstrap/pokehabitat/public/index.html" '+str(root/'public/decoy/index.html')+'; }; apt_confirmed(){ :; }; nginx(){ echo "nginx version: nginx/1.24.0" >&2; }; systemctl(){ [[ $FAIL_BOOT != 1 ]]; }; bootstrap_project\n'
            for fail in ('1', '0'):
                p = subprocess.run(['bash', '-c', source + stubs], capture_output=True, text=True, env={**os.environ, 'FAIL_BOOT': fail})
                self.assertEqual(p.returncode == 0, fail == '0', p.stderr)
                self.assertEqual((base/'.bootstrap-pending').exists(), fail == '1')
            self.assertEqual((root/'public/decoy/index.html').stat().st_mode & 0o777, 0o644)
            self.assertEqual(json.loads((base/'settings.json').read_text())['nginx_version'], '1.24.0')

    def test_staging_failure_does_not_create_base(self):
        with tempfile.TemporaryDirectory() as td:
            root, work, base, source = self.fixture(td)
            (work/'installer-manager.sh').unlink()
            p = subprocess.run(['bash', '-c', source + f'\nWORK={work}\npublish_project\n'], capture_output=True, text=True)
            self.assertNotEqual(p.returncode, 0)
            self.assertFalse(base.exists())
            self.assertEqual(list(root.glob('node.staging.*')), [])

    def test_resume_preserves_pending_exit_code(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)/'node'; base.mkdir(); (base/'.nuvrion-managed').write_text('1.0.0\n')
            (base/'terminal_ui.py').touch()
            (base/'component_report.py').touch()
            source = SOURCE.replace('readonly BASE=/opt/remnanode', f'readonly BASE={base}').replace('/run/nuvrion-vision.lock', str(Path(td)/'lock'))
            for code in ('0', '2', '1'):
                p = subprocess.run(['bash', '-c', source + '''
require_server(){ :; }; check_ssh_collision(){ :; }; get_setting(){ echo 2222; }
python3(){ :; }; bootstrap_project(){ :; }; prepare_stack(){ :; }; apply_tuning(){ :; }
harden_host(){ :; }; start_stack(){ :; }; issue_certificate(){ :; }; install_traffic_control(){ :; }
bash(){ return "$CHECK_CODE"; }; systemd-analyze(){ :; }; show_result(){ :; }
main --resume
'''], env={**os.environ, 'CHECK_CODE': code}, capture_output=True, text=True)
                self.assertEqual(p.returncode, int(code), p.stderr)
                if code == '2': self.assertNotIn('ОШИБКА', p.stderr)
