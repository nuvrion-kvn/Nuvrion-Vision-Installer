"""Pending ZRAM requires real boot/module files and an enabled service."""
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
import component_report as report


class ZramReportTests(unittest.TestCase):
    kernel = '6.8.0-146-generic'

    def fixture(self, root):
        marker = root / 'var/lib/nuvrion-tuning/zram-pending-kernel'
        marker.parent.mkdir(parents=True)
        marker.write_text(self.kernel + '\n')
        image = root / 'boot' / ('vmlinuz-' + self.kernel)
        image.parent.mkdir(); image.touch()
        module = root / 'lib/modules' / self.kernel / 'kernel/drivers/block/zram/zram.ko.zst'
        module.parent.mkdir(parents=True); module.touch()
        return marker, image, module

    def capture(self, *args, **kwargs):
        return {('uname', '-r'): '6.8.0-88-generic',
                ('systemctl', 'is-enabled', 'nuvrion-zram.service'): 'enabled'}[args]

    def test_prepared_kernel_is_pending_and_report_is_read_only(self):
        with tempfile.TemporaryDirectory() as td, patch.object(report, 'capture', self.capture):
            root = Path(td); self.fixture(root)
            before = {str(p.relative_to(root)): p.read_bytes() for p in root.rglob('*') if p.is_file()}
            self.assertEqual(report.pending_zram_kernel(root), 'Ожидает перезагрузки в ядро ' + self.kernel)
            self.assertEqual(before, {str(p.relative_to(root)): p.read_bytes() for p in root.rglob('*') if p.is_file()})

    def test_missing_image_module_or_service_is_not_ready(self):
        for item in ('image', 'module', 'service'):
            with self.subTest(item=item), tempfile.TemporaryDirectory() as td:
                root = Path(td); marker, image, module = self.fixture(root)
                if item == 'image': image.unlink()
                if item == 'module': module.unlink()
                def capture(*args, **kwargs):
                    return 'disabled' if item == 'service' and args[0] == 'systemctl' else self.capture(*args)
                with patch.object(report, 'capture', capture), self.assertRaises(ValueError):
                    report.pending_zram_kernel(root)

    def test_running_or_older_or_different_flavour_kernel_is_not_pending(self):
        for current in (self.kernel, '6.8.0-147-generic', '6.8.0-88-aws'):
            with self.subTest(current=current), tempfile.TemporaryDirectory() as td:
                root = Path(td); self.fixture(root)
                with patch.object(report, 'capture', return_value=current), self.assertRaises(ValueError):
                    report.pending_zram_kernel(root)

    def test_invalid_kernel_marker_is_not_used_as_a_path(self):
        for kernel in ('', '../../etc/passwd', 'not-a-kernel'):
            with self.subTest(kernel=kernel), tempfile.TemporaryDirectory() as td:
                root = Path(td); marker, _, _ = self.fixture(root); marker.write_text(kernel)
                with patch.object(report, 'capture', self.capture), self.assertRaises(ValueError):
                    report.pending_zram_kernel(root)

    def test_marker_for_an_older_new_kernel_is_stale(self):
        with tempfile.TemporaryDirectory() as td, patch.object(report, 'capture', self.capture):
            root = Path(td); self.fixture(root)
            (root / 'lib/modules/6.8.0-147-generic').mkdir()
            (root / 'boot/vmlinuz-6.8.0-147-generic').touch()
            with self.assertRaises(ValueError): report.pending_zram_kernel(root)

    def test_active_swap_takes_precedence_over_pending_marker(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); (root / 'proc').mkdir(); (root / 'sys/block/zram0').mkdir(parents=True)
            (root / 'proc/swaps').write_text('Filename Type Size Used Priority\n/dev/zram0 partition 760832 0 100\n')
            (root / 'sys/block/zram0/disksize').write_text(str(743 * 1048576))
            def fixture_path(path):
                p = Path(path)
                return root / p.relative_to('/') if p.is_absolute() else p
            with patch.object(report, 'Path', side_effect=fixture_path), \
                 patch.object(report, 'pending_zram_kernel', side_effect=AssertionError('must not read stale marker')):
                self.assertEqual(report.zram(), 'Активен; 743 МБ; приоритет 100')

    def test_inactive_prepared_swap_is_a_warning_not_active(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); (root / 'proc').mkdir(); (root / 'proc/swaps').write_text('Filename Type Size Used Priority\n')
            with patch.object(report, 'Path', side_effect=lambda path: root / Path(path).relative_to('/')), \
                 patch.object(report, 'pending_zram_kernel', return_value='Ожидает перезагрузки'):
                self.assertEqual(report.zram(), ('Ожидает перезагрузки', 'warn'))
