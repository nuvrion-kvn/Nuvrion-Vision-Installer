"""Exercise shell control flow with command stubs, without touching host services."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
SOURCE=(ROOT/'src/installer.sh').read_text().split('# Private child entry')[0]


def shell(code,env=None):
    return subprocess.run(['bash','-c',SOURCE+'\n'+code],capture_output=True,text=True,
                          env={**os.environ,**(env or {})},timeout=10)


class ShellTests(unittest.TestCase):
    def test_package_preparation_requires_permission_before_apt_changes(self):
        result=shell('''
ask_yes(){ return 1; }
apt-get(){ echo "APT НЕ ДОЛЖЕН ЗАПУСКАТЬСЯ"; return 99; }
prepare_system_packages
''')
        self.assertNotEqual(result.returncode,0)
        self.assertNotIn('APT НЕ ДОЛЖЕН ЗАПУСКАТЬСЯ',result.stdout)
        self.assertIn('отменены',result.stderr)

    def test_package_preparation_checks_index_before_reporting_ready(self):
        with tempfile.TemporaryDirectory() as td:
            log=Path(td)/'apt.log'
            result=shell('''
package_installed(){ return 0; }
ask_yes(){ return 0; }
apt-get(){ printf '%s\\n' "$*" >> "$APT_LOG"; return 0; }
python3(){ :; }; openssl(){ :; }; curl(){ :; }; gpg(){ :; }; dig(){ :; }; sshd(){ :; }
ip(){ :; }; ss(){ :; }; certbot(){ :; }; ufw(){ :; }; nft(){ :; }
prepare_system_packages
''',{'APT_LOG':str(log)})
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertIn('DPkg::Lock::Timeout=600 update',log.read_text())
            self.assertIn('-s -o Dpkg::Options::=--force-confold --with-new-pkgs upgrade',log.read_text())
            self.assertIn('autoremove',log.read_text())
            self.assertIn('autoclean',log.read_text())
            self.assertIn('Проверка компонентов и обновлений завершена',result.stdout)

    def test_package_simulation_failure_is_not_reported_as_no_updates(self):
        result=shell('''
package_installed(){ return 0; }
ask_yes(){ return 0; }
apt-get(){
  if [[ $1 == -s ]]; then echo "сломанный индекс" >&2; return 100; fi
  return 0
}
prepare_system_packages
''')
        self.assertNotEqual(result.returncode,0)
        self.assertIn('Не удалось рассчитать доступные обновления APT',result.stderr)
        self.assertNotIn('обновлений нет',result.stdout)

    def test_package_preparation_precedes_payload_and_node_questions(self):
        main=SOURCE[SOURCE.index('main() {'):]
        install_branch=main[main.rindex('        --install)'):]
        self.assertLess(install_branch.index('prepare_system_packages'),install_branch.index('unpack'))
        self.assertLess(install_branch.index('prepare_system_packages'),install_branch.index('collect'))
        self.assertLess(install_branch.index('preflight'),install_branch.index('install_docker'))

    def test_installer_does_not_change_ip_family_settings(self):
        self.assertNotIn('disable_ipv6', SOURCE)
        self.assertNotIn('/etc/default/ufw', SOURCE)
        self.assertNotIn('configure_ipv4_only', SOURCE)

    def test_ssh_collision_before_firewall(self):
        result=shell('ss(){ :; }; sshd(){ printf "port 2222\\n"; }; check_ssh_collision 2222',{'SSH_CONNECTION':''})
        self.assertNotEqual(result.returncode,0)
        self.assertIn('совпадает с портом SSH',result.stderr)

    def test_socket_activated_ssh_from_session(self):
        result=shell('ss(){ :; }; sshd(){ printf "port 22\\n"; }; check_ssh_collision 2222',
                     {'SSH_CONNECTION':'203.0.113.5 55111 203.0.113.9 2222'})
        self.assertNotEqual(result.returncode,0)
        self.assertIn('совпадает с портом SSH',result.stderr)

    def test_socket_activated_ssh_from_systemd(self):
        result=shell('''
ss(){ :; }
sshd(){ printf "port 22\\n"; }
systemctl(){ [[ $1 == show ]] && printf "0.0.0.0:2222 (Stream) [::]:2222 (Stream)\\n"; }
check_ssh_collision 2222
''',{'SSH_CONNECTION':''})
        self.assertNotEqual(result.returncode,0)
        self.assertIn('используется ssh.socket',result.stderr)

    def test_unpack_failures_are_russian_and_single(self):
        cases=(
            ('payload(){ printf invalid; }', '0'*64, 'декодировать Base64'),
            ('payload(){ printf YQ==; }', '0'*64, 'Контрольная сумма'),
        )
        for payload,checksum,message in cases:
            with self.subTest(message=message):
                result=shell(f'''WORK=''; {payload}\nNUVRION_PAYLOAD_SHA256={checksum}\nunpack''')
                self.assertNotEqual(result.returncode,0)
                self.assertIn(message,result.stderr)
                self.assertEqual(result.stderr.count('✗ ОШИБКА:'),1)
                self.assertNotIn('Установка остановлена на строке',result.stderr)

    def test_distinct_ssh_and_api(self):
        result=shell('ss(){ :; }; sshd(){ printf "port 22\\n"; }; check_ssh_collision 2222',{'SSH_CONNECTION':''})
        self.assertEqual(result.returncode,0,result.stderr)

    def test_wait_api_retries_when_container_is_not_created_yet(self):
        with tempfile.TemporaryDirectory() as td:
            counter=Path(td)/'counter';counter.write_text('0')
            result=shell('''
get_setting(){ echo 2222; }
timeout(){ shift; "$@"; }
docker(){
  n=$(<"$COUNTER"); n=$((n+1)); printf '%s' "$n" > "$COUNTER"
  (( n >= 3 )) || return 1
  echo true
}
ss(){ echo LISTEN; }
sleep(){ :; }
wait_api
''',{'COUNTER':str(counter)})
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertEqual(counter.read_text(),'3')
            self.assertIn('слушает API',result.stdout)

    def test_nofile_numeric_and_unlimited(self):
        fn=(ROOT/'src/check-nofile.sh').read_text().split('# Read this shell')[0]
        for value,ok in [('unlimited',True),('1048576',True),('2097152',True),('1024',False),('',False),('broken',False)]:
            with self.subTest(value=value):
                r=subprocess.run(['sh','-c',fn+'\nlimit_ok "$1"','test',value],capture_output=True)
                self.assertEqual(r.returncode==0,ok)

    def test_acme_explicit_open_close_and_cleanup_on_failure(self):
        # Transform only constant filesystem roots in the harness; production code is unchanged.
        with tempfile.TemporaryDirectory() as td:
            base=Path(td)/'node';base.mkdir()
            le=Path(td)/'letsencrypt';(le/'renewal-hooks/deploy').mkdir(parents=True)
            log=Path(td)/'events'
            for name in ['acme-pre.sh','acme-post.sh','renew-hook.sh']:(base/name).write_text('#!/bin/sh\nexit 0\n')
            (base/'acme-firewall.sh').write_text('#!/bin/sh\nprintf "%s\\n" "$1" >> "$EVENT_LOG"\n')
            (base/'acme-firewall.sh').chmod(0o700)
            harness=SOURCE.replace('readonly BASE=/opt/remnanode',f'readonly BASE={base}').replace('/etc/letsencrypt',str(le))
            stubs='''
get_setting(){ case "$1" in domain) echo node.example.com;; email) echo admin@example.com;; esac; }
ss(){ :; }
openssl(){ :; }
systemctl(){ :; }
certbot(){
  case "$1" in
    certonly) echo certonly >> "$EVENT_LOG";;
    renew) echo dryrun >> "$EVENT_LOG"; if [[ $FAIL_RENEW == 2 ]]; then kill -TERM $$; fi; [[ $FAIL_RENEW == 0 ]] || return 9;;
  esac
}
timeout(){ [[ $1 != --foreground ]] || shift; shift; "$@"; }
issue_certificate
'''
            for fail,expected in [('0',['open','certonly','close','open','dryrun','close']),
                                  ('1',['open','certonly','close','open','dryrun','close']),
                                  ('2',['open','certonly','close','open','dryrun','close'])]:
                log.write_text('')
                proc=subprocess.run(['bash','-c',harness+'\n'+stubs],capture_output=True,text=True,
                                    env={**os.environ,'EVENT_LOG':str(log),'FAIL_RENEW':fail})
                self.assertEqual(proc.returncode==0,fail=='0',proc.stderr)
                self.assertEqual(log.read_text().splitlines(),expected)

    def test_acme_firewall_bypasses_traffic_control_only_for_port_80(self):
        source=(ROOT/'src/acme-firewall.sh').read_text()
        self.assertIn('nft insert rule inet nuvrion_tc ingress tcp dport 80',source)
        self.assertIn('remove_own_traffic_control_rules',source)
        self.assertNotIn('flush ruleset',source)


if __name__=='__main__':unittest.main(verbosity=2)
