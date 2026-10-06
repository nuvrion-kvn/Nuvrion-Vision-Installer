"""TZ audit regression tests. No host installation or firewall changes."""
import ast
import contextlib
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
import component_report as report
import runtime
import terminal_ui as ui

spec = importlib.util.spec_from_file_location('audit_tc', ROOT / 'src/nuvrion-traffic-control.py')
tc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tc)
VENDOR = (ROOT / 'vendor/nuvrion-auto-tuning.sh').read_text()


def function(name):
    return re.search(r'^' + name + r'\(\) \{\n.*?^\}', VENDOR, re.M | re.S)[0]


def state():
    return dict(schema=1, ssh_ports=[22], allow=['203.0.113.1'], manual=[],
                lists={'antiscanner': ['198.51.100.0/24'], 'government_networks': [], 'skipa': []},
                updated=1, logging=False)


def nft_fixture():
    """libnftables JSON structure, not a live-kernel integration test."""
    objects = [{'table': {'family': 'inet', 'name': tc.TABLE}},
               {'chain': dict(name='ingress', type='filter', hook='input', prio=-10, policy='accept')}]
    for name, version, elems in [('allow4', 4, ['203.0.113.1']), ('allow6', 6, []),
                                 ('block4', 4, [{'prefix': {'addr': '198.51.100.0', 'len': 24}}]),
                                 ('block6', 6, [])]:
        objects.append({'set': dict(name=name, type=f'ipv{version}_addr', elem=elems)})

    def rule(left, right, verdict='return', op='=='):
        objects.append({'rule': {'chain': 'ingress', 'expr': [
            {'match': dict(left=left, right=right, op=op)}, {verdict: None}]}})
    rule({'meta': {'key': 'iifname'}}, 'lo')
    rule({'ct': {'key': 'state'}}, {'set': ['related', 'established']}, op='in')
    rule({'payload': {'protocol': 'tcp', 'field': 'dport'}}, 22)
    for prefix, verdict in [('allow', 'return'), ('block', 'drop')]:
        for v, protocol in [(4, 'ip'), (6, 'ip6')]:
            rule({'payload': {'protocol': protocol, 'field': 'saddr'}}, '@' + prefix + str(v), verdict)
    return {'nftables': objects}


class AuditTZTests(unittest.TestCase):
    def test_owned_permission_failure_and_symlink_are_not_success(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / 'owned'
            path.touch()
            link = Path(td) / 'link'
            link.symlink_to(path)
            for name, result, expected in [(path, 0, '1'), (path, 9, '0'), (link, 0, '0')]:
                code = 'set -euo pipefail\nPERMISSIONS_OK=1\n' + function('normalize_owned_mode')
                code += '\nchmod(){ return "$2"; }\n'
                code = code.replace('return "$2"', f'return {result}')
                code += '\nnormalize_owned_mode 0600 "$1"\nprintf "%s" "$PERMISSIONS_OK"'
                p = subprocess.run(['bash', '-c', code, 'test', str(name)], capture_output=True, text=True)
                self.assertEqual(p.returncode, 0, p.stderr)
                self.assertEqual(p.stdout, expected)

    def test_platform_gate_matrix(self):
        from test_shell import SOURCE
        fn = re.search(r'^require_server\(\) \{\n.*?^\}', SOURCE, re.M | re.S)[0]
        fn = fn.replace('[[ -d /run/systemd/system ]]', 'true')
        fn = fn.replace('(( EUID == 0 ))', 'true')
        for system in ('ubuntu:22.04:jammy', 'ubuntu:24.04:noble', 'debian:12:bookworm', 'debian:13:trixie', 'alpine:3:'):
            for arch in ('x86_64', 'aarch64', 'i686'):
                script = fn + '\ndie(){ exit 1; }\nos_identity(){ echo "$TEST_OS"; }\nuname(){ echo "$TEST_ARCH"; }\nrequire_server'
                result = subprocess.run(['bash', '-c', script], capture_output=True,
                                        env={**os.environ, 'TEST_OS': system, 'TEST_ARCH': arch})
                self.assertEqual(result.returncode == 0, not system.startswith('alpine') and arch != 'i686')

    def test_report_unicode_alignment_and_mobile_wrapping(self):
        for size in (12, 24, 32, 40, 80, 120):
            stream = io.StringIO()
            with patch.object(ui, 'columns', return_value=size), contextlib.redirect_stdout(stream):
                for label in ('Система и пакеты', 'Docker Engine', 'Nuvrion Traffic Control', '\033[31mЯдро\033[0m', 'е\u0301界'):
                    ui.row(label, '[✓] Проверено; очень длинное состояние компонента')
                ui.heading('Итоговый отчёт по компонентам')
            lines = stream.getvalue().splitlines()
            self.assertTrue(all(ui.width(x) <= size for x in lines), (size, lines))
            positions = {ui.width(x.split('[✓]')[0]) for x in lines if '[✓]' in x}
            self.assertEqual(len(positions), 1)
            self.assertNotIn('\033', stream.getvalue())
        self.assertEqual(ui.width('\033[31mе\u0301界\033[0m'), 3)

    def test_component_report_does_not_green_failed_probes(self):
        with tempfile.TemporaryDirectory() as td, patch.object(report, 'BASE', Path(td)), \
             patch.object(report, 'PROFILE', Path(td) / 'missing'), \
             patch.object(report, 'capture', side_effect=ValueError('PRIVATE_TEST_SECRET')), \
             patch.object(report, 'zram', side_effect=ValueError()), patch.object(report, 'rps', return_value='нет'):
            rows = report.collect(1)
            self.assertFalse(any(kind == 'ok' for _, _, kind in rows))
            self.assertIn(('RemnaNode', 'Проверка не пройдена', 'error'), rows)
            stream = io.StringIO()
            with contextlib.redirect_stdout(stream):
                self.assertEqual(report.main(1), 1)
            self.assertNotIn('PRIVATE_TEST_SECRET', stream.getvalue())
            self.assertIn('ZRAM', stream.getvalue())

    def test_tc_rule_content_and_order(self):
        data = nft_fixture()
        def check(value):
            with patch.object(tc, 'run', return_value=types.SimpleNamespace(stdout=json.dumps(value))):
                return tc.live_rules_match(state())
        self.assertTrue(check(data))
        counter = copy.deepcopy(data)
        counter['nftables'][-1]['rule']['expr'].insert(1, {'counter': {'packets': 100, 'bytes': 8000}})
        self.assertTrue(check(counter))
        for mutate in (
            lambda x: x['nftables'].pop(),
            lambda x: x['nftables'][0]['table'].update(flags=['dormant']),
            lambda x: x['nftables'][1]['chain'].update(prio=0),
            lambda x: x['nftables'][2]['set'].update(elem=[]),
            lambda x: x['nftables'].append({'rule': {'chain': 'ingress', 'expr': [{'log': None}, {'accept': None}]}}),
            lambda x: x['nftables'].reverse(),
        ):
            invalid = copy.deepcopy(data)
            mutate(invalid)
            self.assertFalse(check(invalid))

    def test_tc_cli_exit_propagates_diagnostic_failure(self):
        tree = ast.parse((ROOT / 'src/nuvrion-traffic-control.py').read_text())
        guard = ast.Module(body=[tree.body[-1]], type_ignores=[])
        for result, expected in [(0, 0), (1, 1), (256, 1)]:
            namespace = dict(tc.__dict__, __name__='__main__', main=lambda: result)
            with self.assertRaises(SystemExit) as caught:
                exec(compile(guard, '<CLI guard>', 'exec'), namespace)
            self.assertEqual(caught.exception.code, expected)

    def test_nft109_ct_state_array_from_server(self):
        # Actual Ubuntu 24.04/nft 1.0.9 expression from the user's chain dump.
        for values, op, valid in [(['established', 'related'], 'in', True),
                                   (['related', 'established'], 'in', True),
                                   (['established'], 'in', False),
                                   (['established', 'related', 'new'], 'in', False),
                                   (['established', 'related'], '!=', False)]:
            data = nft_fixture()
            match = data['nftables'][7]['rule']['expr'][0]['match']
            self.assertEqual(match['left'], {'ct': {'key': 'state'}})
            match.update(right=values, op=op)
            with patch.object(tc, 'run', return_value=types.SimpleNamespace(stdout=json.dumps(data))):
                self.assertEqual(tc.live_rules_match(state()), valid, (values, op))

    def test_tc_json_command_has_no_dependency_prefix(self):
        lock = io.StringIO()
        with patch.object(tc.os, 'geteuid', return_value=0), patch('builtins.open', return_value=lock), \
             patch.object(tc.fcntl, 'flock'), patch.object(tc, 'execute', return_value=0), \
             patch.object(tc, 'ensure_dependencies') as deps:
            self.assertEqual(tc.main(['status', '--json']), 0)
            deps.assert_not_called()

    def test_tc_rejects_malformed_state_before_changes(self):
        for bad in ([], {}, {'schema': 1, 'lists': []}, {**state(), 'ssh_ports': [0]},
                    {**state(), 'allow': ['not-an-IP']}, {**state(), 'manual': ['0.0.0.0/0']}):
            with tempfile.TemporaryDirectory() as td:
                path = Path(td) / 'state.json'
                path.write_text(json.dumps(bad))
                with patch.object(tc, 'STATE', path), self.assertRaises(ValueError):
                    tc.load()

    def test_acme_rule_is_preserved_only_with_bounded_lease(self):
        with tempfile.TemporaryDirectory() as td:
            lease = Path(td) / 'lease'
            for timestamp, expected in [(990, True), (1, False), (1100, False), ('bad', False)]:
                lease.write_text(str(timestamp))
                stat = types.SimpleNamespace(st_uid=0)
                with patch.object(tc, 'Path', return_value=lease), patch.object(Path, 'stat', return_value=stat), \
                     patch.object(Path, 'exists', return_value=True), patch.object(Path, 'is_symlink', return_value=False), \
                     patch.object(tc.time, 'time', return_value=1000), \
                     patch.object(tc, 'present', return_value=True), patch.object(tc, 'run') as run:
                    # Expired at now=1000 requires a timestamp older than -200.
                    if timestamp == 1:
                        with patch.object(tc.time, 'time', return_value=2000):
                            tc.apply(state())
                    else:
                        tc.apply(state())
                    self.assertEqual('Nuvrion-Vision-ACME-temporary' in run.call_args.kwargs['data'], expected)

    def test_acme_query_failure_is_not_silently_ignored(self):
        source = (ROOT / 'src/acme-firewall.sh').read_text().split('case "${1:-}"')[0]
        source = source.replace('exec 9>/run/nuvrion-traffic-control.lock', ':').replace('flock -w 360 9', ':')
        for stubs, command in [('ufw(){ return 9; }', 'remove_own_rules'),
                               ('nft(){ return 9; }', 'remove_own_traffic_control_rules')]:
            p = subprocess.run(['bash', '-c', source + '\n' + stubs + '\n' + command], capture_output=True)
            self.assertNotEqual(p.returncode, 0)

    def test_nofile_requires_both_limits(self):
        for pair, good in [('unlimited/unlimited', True), ('1048576/infinity', True),
                           ('1024/unlimited', False), ('unlimited/1024', False), ('bad/1048576', False),
                           ('1048576/1048576', True), ('1024/1024', False)]:
            p = subprocess.run(['bash', '-c', 'set -euo pipefail\nNOFILE_TARGET=1048576\n' +
                                function('nofile_pair_ok') + '\nnofile_pair_ok "$1"', 'test', pair])
            self.assertEqual(p.returncode == 0, good, pair)

    def test_failed_ssh_allow_stops_before_firewall_enable(self):
        source = 'set -euo pipefail\n' + function('protect_ssh_before_ufw') + '''
SSH_PORTS=(22 22222)
UFW_BIN=ufw
ufw(){ [[ $1 != allow ]] || return 9; echo ENABLED; }
protect_ssh_before_ufw
ufw --force enable
'''
        p = subprocess.run(['bash', '-c', source], capture_output=True, text=True)
        self.assertNotEqual(p.returncode, 0)
        self.assertNotIn('ENABLED', p.stdout)
        self.assertIn('не удалось разрешить SSH', p.stderr)

    def test_zram_initialized_device_is_never_reset(self):
        block = VENDOR.split('current=\\$(cat "\\$SYS/disksize"', 1)[1].split('\nif [[ -w \\$SYS/comp_algorithm', 1)[0]
        block = ('current=\\$(cat "\\$SYS/disksize"' + block).replace('\\$', '$')
        with tempfile.TemporaryDirectory() as td:
            disk = Path(td) / 'disksize'
            disk.write_text('1048576')
            source = '''set -euo pipefail
SYS=$1
DEV=/dev/fixture-zram
SWAPON_BIN=try_swapon
TIMEOUT_BIN=bounded
bounded(){ shift 2; "$@"; }
try_swapon(){ echo SWAPON; return 9; }
active_zram(){ :; }
''' + block + '\necho REFORMAT\n'
            p = subprocess.run(['bash', '-c', source, 'test', td], capture_output=True, text=True)
            self.assertEqual(p.returncode, 9)
            self.assertEqual(p.stdout.strip(), 'SWAPON')
            self.assertEqual(disk.read_text(), '1048576')
        self.assertIn('zram_restart_unit nuvrion-zram.service', VENDOR)

    def test_repeat_tuning_preserves_owned_kernel_ceiling(self):
        block = VENDOR.split('NR_OPEN_TARGET=1048576', 1)[1].split('# ============================================================', 1)[0]
        block = 'NR_OPEN_TARGET=1048576' + block
        with tempfile.TemporaryDirectory() as td:
            conf = Path(td) / 'profile'
            for prior, expected in [('', '0:0'), ('fs.nr_open = 1048576\nfs.file-max = 1048576\n', '1:1')]:
                conf.write_text(prior)
                code = 'set -euo pipefail\nCONF=$1\nnum_or_zero(){ echo "$1"; }\nsysctl(){ echo 1048576; }\n'
                p = subprocess.run(['bash', '-c', code + block + '\nprintf "%s:%s" "$MANAGE_NR_OPEN" "$MANAGE_FILE_MAX"', 'test', str(conf)],
                                   capture_output=True, text=True)
                self.assertEqual(p.returncode, 0, p.stderr)
                self.assertEqual(p.stdout, expected)

    def test_completed_resume_only_checks(self):
        from test_shell import SOURCE
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            (base / '.nuvrion-managed').write_text('1.0.0')
            (base / '.installation-complete').touch()
            (base / 'component_report.py').touch()
            (base / 'terminal_ui.py').touch()
            source = SOURCE.replace('readonly BASE=/opt/remnanode', f'readonly BASE={base}')
            source = source.replace('/run/nuvrion-vision.lock', str(base / 'lock'))
            stubs = '''
require_server(){ :; }
bash(){ echo CHECK; return 2; }
installation_report(){ echo REPORT; }
show_result(){ echo PROFILE; }
bootstrap_project(){ echo MUTATION; }
prepare_stack(){ echo MUTATION; }
apply_tuning(){ echo MUTATION; }
main --resume
'''
            p = subprocess.run(['bash', '-c', source + stubs], capture_output=True, text=True)
            self.assertEqual(p.returncode, 2, p.stderr)
            self.assertNotIn('MUTATION', p.stdout)
            self.assertIn('REPORT', p.stdout)

    def test_atomic_runtime_write_cleans_failed_replace(self):
        with tempfile.TemporaryDirectory() as td:
            dest = Path(td) / 'settings.json'
            dest.write_text('original')
            with patch.object(runtime.os, 'replace', side_effect=OSError('failure')), self.assertRaises(OSError):
                runtime.write(dest, 'new')
            self.assertEqual(dest.read_text(), 'original')
            self.assertEqual(list(Path(td).iterdir()), [dest])


if __name__ == '__main__':
    unittest.main()
