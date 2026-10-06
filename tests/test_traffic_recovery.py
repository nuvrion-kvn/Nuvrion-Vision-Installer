"""Recovery and filtering regressions; nftables and services are never changed."""
import importlib.util
import io
import json
from argparse import Namespace
from pathlib import Path
import tempfile
import unittest
from unittest.mock import mock_open, patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('embedded_control', ROOT/'src/nuvrion-traffic-control.py')
c = importlib.util.module_from_spec(spec)
spec.loader.exec_module(c)


class TrafficRecoveryTests(unittest.TestCase):
    def state(self):
        return dict(schema=1, ssh_ports=[22], allow=['198.51.100.9'],
                    lists={name:['198.51.100.0/24'] for name in c.SOURCES},
                    manual=[], updated=1, logging=True)

    def test_recovery_does_not_parse_missing_or_corrupt_state(self):
        for failure in (FileNotFoundError('state.json'), ValueError('corrupt JSON')):
            for command, pending in [('disable', False), ('rollback', True), ('restore', True)]:
                with self.subTest(command=command, failure=failure), tempfile.TemporaryDirectory() as folder:
                    root = Path(folder)
                    if pending:
                        (root/'pending').touch()
                    with patch.object(c, 'ROOT', root), patch.object(c, 'load', side_effect=failure) as load, \
                         patch.object(c, 'disable') as disable:
                        c.execute(Namespace(command=command))
                    load.assert_not_called()
                    disable.assert_called_once_with(**({'units':False} if command == 'restore' else {}))

    def test_completed_activation_is_not_undone_by_queued_rollback(self):
        with tempfile.TemporaryDirectory() as folder, patch.object(c, 'ROOT', Path(folder)), \
             patch.object(c, 'load', side_effect=ValueError('corrupt JSON')) as load, \
             patch.object(c, 'disable') as disable:
            c.execute(Namespace(command='rollback'))
        load.assert_not_called()
        disable.assert_not_called()

    def test_recovery_main_does_not_require_download_dependencies(self):
        for command in ('disable', 'rollback', 'restore'):
            with self.subTest(command=command), patch.object(c.os, 'geteuid', return_value=0), \
                 patch('builtins.open', mock_open()), patch.object(c.fcntl, 'flock'), \
                 patch.object(c, 'ensure_dependencies', side_effect=ValueError('missing CA')) as deps, \
                 patch.object(c, 'execute') as execute:
                c.main([command])
            deps.assert_not_called()
            self.assertEqual(execute.call_args.args[0].command, command)

    def test_aggregate_default_route_is_rejected_before_nft(self):
        for halves in [('0.0.0.0/1','128.0.0.0/1'), ('::/1','8000::/1')]:
            for across_manual in (True, False):
                state = self.state()
                names = list(c.SOURCES)
                state['lists'][names[0]] = [halves[0]]
                if across_manual:
                    state['manual'] = [halves[1]]
                else:
                    state['lists'][names[1]] = [halves[1]]
                with self.subTest(halves=halves, manual=across_manual), \
                     patch.object(c, 'present', return_value=True), patch.object(c, 'run') as run, \
                     self.assertRaisesRegex(ValueError, 'покрывает весь'):
                    c.apply(state)
                run.assert_not_called()

    def test_download_parser_rejects_indirect_default_route(self):
        for value in ('0.0.0.0/1\n128.0.0.0/1', '::/1\n8000::/1'):
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, 'покрывает весь'):
                c.networks(value)

    def test_state_rejects_nonfinite_timestamp(self):
        for value in (float('nan'), float('inf'), float('-inf'), True, -1):
            with self.subTest(value=value), tempfile.TemporaryDirectory() as folder:
                path = Path(folder)/'state.json'
                path.write_text(json.dumps(dict(self.state(), updated=value)), encoding='utf-8')
                with patch.object(c, 'STATE', path), self.assertRaises(ValueError):
                    c.load()
