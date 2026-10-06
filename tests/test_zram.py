"""Run isolated Bash regressions; never source or run the whole installer.

Host paths in extracted functions are redirected into each test directory.
Generated setup tests use ordinary fixture files in place of block devices.
APT, systemctl, modprobe and swap operations are fakes. This is not a VPS test.
"""
from pathlib import Path
import os, re, subprocess, shutil, tempfile, unittest

ROOT = Path(__file__).resolve().parents[1]
BASH = os.environ.get('BASH_BIN') or shutil.which('bash')
source = (ROOT/'vendor/nuvrion-auto-tuning.sh').read_text(encoding='utf-8')
block = source[source.index('refresh_zram_bins() {'):source.index('# Шаг 1. Фактическая проверка')]
COMMON = r'''
set -euo pipefail
export PATH="/usr/bin:/bin:$PATH"
warn() { echo "WARN: $*"; }
info() { echo "INFO: $*"; }
ok() { echo "OK: $*"; }
num_or_zero() { echo "${1:-0}"; }
STATE_DIR=state; RUN_ID=test; mkdir -p state
TIMEOUT_BIN=$(command -v timeout)
SYSTEMCTL_BIN=fake-systemctl; MODPROBE_BIN=fake-modprobe
SWAPON_BIN=fake-swapon; SWAPOFF_BIN=fake-swapoff; MKSWAP_BIN=fake-mkswap
FINDMNT_BIN=''; APT_GET_BIN=fake-apt; DPKG_QUERY_BIN=fake-dpkg
RAM_MB=1024; INSTALL_ZRAM_PACKAGES=1
ZRAM_STATUS='не проверен'; ZRAM_MANAGED_BY_NUVRION=0
ZRAM_REPAIRED=0; ZRAM_SIZE_MB=0; ZRAM_ACTIVE_DEV=''
export PATH="$PWD/bin:$PATH"
mkdir -p bin fs/run/systemd/system
'''

def execute(name, body, pre=''):
    folder = Path(tempfile.mkdtemp(prefix='nuvrion-zram-'))
    b = block
    for path in ['/lib/modules', '/boot', '/run/systemd/system', '/usr/local/sbin', '/etc/os-release']:
        b = b.replace(path, 'fs'+path)
    script = COMMON + pre + '\n' + b + r'''
ZRAM_SETUP=setup.sh; ZRAM_SERVICE=zram.service
refresh_zram_bins() { :; }
''' + body
    (folder/'test.sh').write_text(script, encoding='utf-8', newline='\n')
    result = subprocess.run([BASH, 'test.sh'], cwd=folder, capture_output=True, text=True, encoding='utf-8', timeout=30)
    assert result.returncode == 0, f'{name}: {result.returncode}\n{result.stdout}\n{result.stderr}'
    return folder


class ZramTests(unittest.TestCase):
    pass

def run(name, body, pre=''):
    def test(self):
        folder = execute(name, body, pre)
        shutil.rmtree(folder)
    setattr(ZramTests, 'test_' + name.replace('-', '_'), test)

run('installed-package-skips-apt', r'''
zram_pkg_installed() { return 0; }
zram_apt() { echo unexpected-apt; return 99; }
apt_install_zram_packages kmod
[[ $ZRAM_APT_UPDATED == 0 ]]
''')
run('cached-package-no-update', r'''
zram_pkg_installed() { return 1; }
zram_pkg_has_candidate() { return 0; }
zram_apt() { printf '%s\n' "$*" >>calls; }
apt_install_zram_packages kmod
[[ $(wc -l <calls) == 1 ]]
grep -q '^install .*--no-remove kmod$' calls
''')
run('missing-package-updates-once', r'''
zram_pkg_installed() { return 1; }
zram_pkg_has_candidate() { return 1; }
zram_apt() { printf '%s\n' "$*" >>calls; [[ $1 == update ]]; }
if apt_install_zram_packages missing; then exit 10; fi
if apt_install_zram_packages missing2; then exit 11; fi
[[ $(grep -cx update calls) == 1 && $ZRAM_APT_UPDATED == 1 ]]
[[ $(grep -c '^install ' calls) == 2 ]]
''')
run('candidate-check-consumes-producer-output', r'''
cat >bin/apt-cache <<'EOF'
#!/usr/bin/env python3
import os, sys
assert os.environ['LC_ALL'] == 'C'
print('linux-modules-extra-6.8.0-61-generic:\n  Installed: (none)\n  Candidate: 6.8.0-61.64', flush=True)
try:
    for _ in range(20000):
        sys.stdout.write('    6.8.0-61.64 500 http://archive.ubuntu.com/ubuntu noble-updates/main amd64 Packages\n')
    sys.stdout.flush()
except BrokenPipeError:
    os._exit(141)
open('policy-completed', 'w').close()
EOF
chmod +x bin/apt-cache
export LC_ALL=C.UTF-8
zram_pkg_has_candidate linux-modules-extra-6.8.0-61-generic
[[ -f policy-completed && $LC_ALL == C.UTF-8 ]]
''')
run('candidate-none-is-logged', r'''
cat >bin/apt-cache <<'EOF'
#!/usr/bin/env bash
printf 'missing:\n  Installed: (none)\n  Candidate: (none)\n'
EOF
chmod +x bin/apt-cache
if zram_pkg_has_candidate missing; then exit 10; fi
grep -q 'Candidate: (none)' "$ZRAM_APT_LOG"
''')
run('candidate-output-with-command-error-is-not-success', r'''
cat >bin/apt-cache <<'EOF'
#!/usr/bin/env bash
printf '  Candidate: 6.8.0-61.64\n'
echo cache-error >&2
exit 100
EOF
chmod +x bin/apt-cache
if zram_pkg_has_candidate broken; then exit 10; fi
grep -q 'код 100' "$ZRAM_APT_LOG"
grep -q cache-error "$ZRAM_APT_LOG"
''')
run('candidate-command-timeout-is-logged', r'''
cat >bin/apt-cache <<'EOF'
#!/usr/bin/env bash
exec sleep 5
EOF
chmod +x bin/apt-cache
zram_timeout() { shift; timeout 0.1 "$@"; }
if zram_pkg_has_candidate slow; then exit 10; fi
grep -q 'код 124' "$ZRAM_APT_LOG"
''')
run('unconfirmed-candidate-does-not-block-working-install', r'''
zram_pkg_installed() { return 1; }
zram_pkg_has_candidate() { return 1; }
zram_apt() { printf '%s\n' "$*" >>calls; }
apt_install_zram_packages linux-modules-extra-6.8.0-61-generic
[[ $(wc -l <calls) == 2 && $ZRAM_APT_UPDATED == 1 ]]
grep -q '^install .*--no-remove linux-modules-extra-6.8.0-61-generic$' calls
''')
run('failed-cache-refresh-does-not-block-working-install', r'''
zram_pkg_installed() { return 1; }
zram_pkg_has_candidate() { return 1; }
zram_apt() { printf '%s\n' "$*" >>calls; [[ $1 != update ]]; }
apt_install_zram_packages kmod
[[ $(wc -l <calls) == 2 && $ZRAM_APT_BLOCKED == 0 ]]
''')
run('unconfirmed-candidate-keeps-auto-install-opt-out', r'''
INSTALL_ZRAM_PACKAGES=0
zram_pkg_has_candidate() { touch forbidden; return 1; }
zram_apt() { touch forbidden; }
if apt_install_zram_packages kmod; then exit 10; fi
[[ ! -e forbidden ]]
''')
run('apt-timeout-stops-subsequent-installs', r'''
zram_timeout() { echo "$*" >>calls; return 124; }
if zram_apt install -y kmod; then exit 10; fi
[[ $ZRAM_APT_BLOCKED == 1 ]]
if zram_apt update; then exit 11; fi
[[ $(wc -l <calls) == 1 ]]
''')
run('apt-environment-and-options', r'''
cat >bin/fake-apt <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$DEBIAN_FRONTEND $NEEDRESTART_MODE $NEEDRESTART_SUSPEND" >env.log
printf '%s\n' "$@" >args.log
EOF
chmod +x bin/fake-apt
export NEEDRESTART_MODE=a
zram_apt install -y --no-remove kmod
[[ $(cat env.log) == 'noninteractive l 1' ]]
grep -qx DPkg::Lock::Timeout=300 args.log
grep -qx Dpkg::Options::=--force-confold args.log
[[ $NEEDRESTART_MODE == a ]]
''')
run('timeout-required', r'''
TIMEOUT_BIN=''
if zram_timeout 1 touch forbidden; then exit 10; fi
[[ ! -e forbidden ]]
''')
run('real-timeout-returns-124', r'''
if zram_timeout 0.1 sleep 5; then exit 10; else rc=$?; fi
[[ $rc == 124 ]]
''')
run('service-timeout-cancels-no-retry', r'''
zram_systemctl() {
    echo "$*" >>calls
    [[ $1 != restart ]] || return 124
}
if zram_restart_unit zramswap.service; then exit 10; fi
[[ $(wc -l <calls) == 2 ]]
grep -qx 'restart zramswap.service' calls
grep -qx -- '--no-block stop zramswap.service' calls
''')
run('ordinary-service-error-no-stop', r'''
zram_systemctl() { echo "$*" >>calls; return 1; }
if zram_restart_unit zramswap.service; then exit 10; fi
[[ $(wc -l <calls) == 1 ]]
''')
kernel_pre = r'''
uname() { echo 6.8.0-60-generic; }
make_kernel() {
    mkdir -p "fs/lib/modules/$1/kernel/drivers/block/zram" fs/boot
    touch "fs/lib/modules/$1/kernel/drivers/block/zram/zram.ko.zst"
    touch "fs/boot/vmlinuz-$1"
}
'''
run('older-kernel-not-deferred', kernel_pre+r'''
make_kernel 6.8.0-59-generic
if zram_in_newer_kernel; then exit 10; fi
[[ -z $ZRAM_PENDING_KERNEL ]]
''')
run('newer-kernel-with-image-deferred', kernel_pre+r'''
make_kernel 6.8.0-61-generic
zram_in_newer_kernel
[[ $ZRAM_PENDING_KERNEL == 6.8.0-61-generic ]]
''')
run('kernel-without-image-not-deferred', kernel_pre+r'''
make_kernel 6.8.0-61-generic
rm fs/boot/vmlinuz-6.8.0-61-generic
if zram_in_newer_kernel; then exit 10; fi
''')
run('reboot-marker-alone-not-deferred', r'''
mkdir -p fs/etc fs/run; echo ID=ubuntu >fs/etc/os-release; touch fs/run/reboot-required
zram_module_present() { return 1; }
zram_modprobe() { return 1; }
apt_install_zram_packages() { echo "$*" >calls; return 1; }
if ensure_zram_kernel_module; then exit 10; fi
[[ $ZRAM_DEFERRED == 0 && -s calls ]]
''')
ubuntu_next = kernel_pre+r'''
mkdir -p fs/etc; echo ID=ubuntu >fs/etc/os-release
make_kernel 6.8.0-61-generic
rm fs/lib/modules/6.8.0-61-generic/kernel/drivers/block/zram/zram.ko.zst
zram_module_present() { return 1; }
zram_modprobe() { return 1; }
ensure_zram_userspace_tools() { return 0; }
zram_systemctl() { echo "$*" >>services; }
'''
run('unconfirmed-cache-prepares-future-module-through-real-helpers', ubuntu_next+r'''
cat >bin/apt-cache <<'EOF'
#!/usr/bin/env bash
printf 'linux-modules-extra-6.8.0-61-generic:\n  Candidate: (none)\n'
EOF
cat >bin/fake-apt <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >>apt-calls
if [[ $* == *' install '* ]]; then
    touch fs/lib/modules/6.8.0-61-generic/kernel/drivers/block/zram/zram.ko.zst
fi
EOF
chmod +x bin/apt-cache bin/fake-apt
zram_pkg_installed() { return 1; }
create_or_repair_nuvrion_zram
[[ $(wc -l <apt-calls) == 2 ]]
grep -q 'install .*--no-remove linux-modules-extra-6.8.0-61-generic' apt-calls
[[ $ZRAM_DEFERRED_READY == 1 ]]
[[ $(cat state/zram-pending-kernel) == 6.8.0-61-generic ]]
[[ $(cat services) == $'daemon-reload\nenable nuvrion-zram.service' ]]
''')
run('newer-kernel-missing-module-is-prepared-before-reboot', ubuntu_next+r'''
apt_install_zram_packages() {
    echo "$*" >>packages
    touch fs/lib/modules/6.8.0-61-generic/kernel/drivers/block/zram/zram.ko.zst
}
create_or_repair_nuvrion_zram
[[ $(cat packages) == linux-modules-extra-6.8.0-61-generic ]]
[[ $ZRAM_DEFERRED_READY == 1 && $ZRAM_PENDING_KERNEL == 6.8.0-61-generic ]]
[[ $(cat state/zram-pending-kernel) == 6.8.0-61-generic ]]
[[ $(stat -c %a state/zram-pending-kernel) == 600 ]]
[[ -f setup.sh && -f zram.service ]]
[[ $(cat services) == $'daemon-reload\nenable nuvrion-zram.service' ]]
''')
run('newest-bootable-kernel-wins-over-older-ready-kernel', ubuntu_next+r'''
make_kernel 6.8.0-62-generic
rm fs/lib/modules/6.8.0-62-generic/kernel/drivers/block/zram/zram.ko.zst
# An older new kernel already has ZRAM, but the newest bootable one does not.
touch fs/lib/modules/6.8.0-61-generic/kernel/drivers/block/zram/zram.ko.zst
apt_install_zram_packages() {
    echo "$*" >>packages
    touch fs/lib/modules/6.8.0-62-generic/kernel/drivers/block/zram/zram.ko.zst
}
create_or_repair_nuvrion_zram
[[ $(cat packages) == linux-modules-extra-6.8.0-62-generic ]]
[[ $ZRAM_DEFERRED_READY == 1 && $ZRAM_PENDING_KERNEL == 6.8.0-62-generic ]]
''')
for failure in (1, 124):
    run('newer-kernel-install-failure-no-old-kernel-fallback-'+str(failure), ubuntu_next+r'''
apt_install_zram_packages() { echo "$*" >>packages; return '''+str(failure)+r'''; }
if create_or_repair_nuvrion_zram; then exit 10; fi
[[ $(cat packages) == linux-modules-extra-6.8.0-61-generic ]]
[[ $ZRAM_DEFERRED == 0 && $ZRAM_DEFERRED_READY == 0 ]]
[[ ! -e state/zram-pending-kernel && ! -e services && ! -e zram.service ]]
''')
run('successful-apt-without-module-is-not-deferred', ubuntu_next+r'''
apt_install_zram_packages() { echo "$*" >>packages; return 0; }
if create_or_repair_nuvrion_zram; then exit 10; fi
[[ $ZRAM_DEFERRED == 0 && $ZRAM_DEFERRED_READY == 0 ]]
[[ ! -e state/zram-pending-kernel && ! -e services ]]
''')
run('newer-kernel-apt-timeout-blocks-further-installs', ubuntu_next+r'''
zram_pkg_installed() { return 1; }
zram_pkg_has_candidate() { return 0; }
zram_timeout() { echo "$*" >>packages; return 124; }
if ensure_zram_kernel_module; then exit 10; fi
[[ $ZRAM_APT_BLOCKED == 1 && $ZRAM_DEFERRED == 0 ]]
[[ $(wc -l <packages) == 1 ]]
grep -q 'linux-modules-extra-6.8.0-61-generic' packages
! grep -q 'linux-modules-extra-6.8.0-60-generic' packages
''')
run('newer-kernel-auto-install-disabled', ubuntu_next+r'''
INSTALL_ZRAM_PACKAGES=0
apt_install_zram_packages() { touch forbidden; return 0; }
if ensure_zram_kernel_module; then exit 10; fi
[[ $ZRAM_DEFERRED == 0 && ! -e forbidden ]]
''')
run('newer-kernel-non-ubuntu-no-module-install', ubuntu_next+r'''
echo ID=debian >fs/etc/os-release
apt_install_zram_packages() { touch forbidden; return 0; }
if ensure_zram_kernel_module; then exit 10; fi
[[ $ZRAM_DEFERRED == 0 && ! -e forbidden ]]
''')
run('working-current-module-does-not-install-new-extras', ubuntu_next+r'''
zram_module_present() { return 0; }
apt_install_zram_packages() { touch forbidden; return 0; }
ensure_zram_kernel_module
[[ $ZRAM_DEFERRED == 0 && ! -e forbidden ]]
''')
run('different-kernel-flavour-is-not-selected', kernel_pre+r'''
make_kernel 6.8.0-99-aws
make_kernel 6.8.0-98-lowlatency
if zram_latest_bootable_kernel; then exit 10; fi
[[ -z $ZRAM_PENDING_KERNEL ]]
''')
run('latest-kernel-needs-boot-image', kernel_pre+r'''
make_kernel 6.8.0-61-generic
make_kernel 6.8.0-62-generic
rm fs/boot/vmlinuz-6.8.0-62-generic
zram_in_newer_kernel
[[ $ZRAM_PENDING_KERNEL == 6.8.0-61-generic ]]
''')
run('module-path-must-be-file', kernel_pre+r'''
make_kernel 6.8.0-61-generic
rm fs/lib/modules/6.8.0-61-generic/kernel/drivers/block/zram/zram.ko.zst
mkdir fs/lib/modules/6.8.0-61-generic/kernel/drivers/block/zram/zram.ko.zst
if zram_in_newer_kernel; then exit 10; fi
[[ -z $ZRAM_PENDING_KERNEL ]]
''')

defer = r'''
ensure_zram_userspace_tools() { return 0; }
ensure_zram_kernel_module() { ZRAM_DEFERRED=1; ZRAM_PENDING_KERNEL=6.8.0-61-generic; return 1; }
write_nuvrion_zram_units() { touch "$ZRAM_SERVICE"; }
'''
run('deferred-enable-failure-is-not-success', defer+r'''
zram_systemctl() { [[ $1 != enable ]]; }
if create_or_repair_nuvrion_zram; then exit 10; fi
[[ $ZRAM_DEFERRED_READY == 0 ]]
''')
run('deferred-write-failure-is-not-success', defer+r'''
write_nuvrion_zram_units() { return 1; }
zram_systemctl() { touch forbidden; }
if create_or_repair_nuvrion_zram; then exit 10; fi
[[ $ZRAM_DEFERRED_READY == 0 && ! -e forbidden ]]
''')
run('deferred-success-does-not-start', defer+r'''
zram_systemctl() { echo "$*" >>calls; }
create_or_repair_nuvrion_zram
[[ $ZRAM_DEFERRED_READY == 1 ]]
[[ $(wc -l <calls) == 2 ]]
[[ $(cat state/zram-pending-kernel) == 6.8.0-61-generic ]]
! grep -q restart calls
''')
external = r'''
ensure_zram_userspace_tools() { return 0; }
ensure_zram_kernel_module() { return 0; }
sleep() { :; }
has_zramswap_config() { return 0; }
get_active_zram() { [[ ! -f restarted ]] || echo /dev/zram0; return 0; }
zram_systemctl() { echo "$*" >>calls; [[ $1 != restart ]] || touch restarted; return 0; }
'''
run('zramswap-active-exited-is-restarted', external+r'''
repair_known_external_zram
grep -qx 'restart zramswap.service' calls
! grep -q -- '--now' calls
[[ $ZRAM_REPAIRED == 1 ]]
''')
run('generator-starts-swap-unit', external+r'''
has_zramswap_config() { return 1; }
has_generator_zram_config() { return 0; }
apt_install_zram_packages() { return 0; }
repair_known_external_zram
grep -qx 'restart dev-zram0.swap' calls
''')
run('generate-service-and-setup', r'''
ZRAM_SIZE_MB=256
write_nuvrion_zram_units
bash -n setup.sh
grep -qx TimeoutStartSec=90 zram.service
grep -qx TimeoutStopSec=15 zram.service
''')
generated = source.split('cat >"$ZRAM_SETUP" <<EOF || return 1\n', 1)[1].split('\nEOF', 1)[0]
for name, value in {'MODPROBE_BIN':'modprobe', 'SWAPON_BIN':'swapon', 'MKSWAP_BIN':'mkswap',
                    'TIMEOUT_BIN':'timeout', 'ZRAM_SIZE_MB':'256'}.items():
    generated = generated.replace('${'+name+'}', value)
generated = generated.replace('\\$', '$')
for path in ['/sys', '/dev']:
    generated = generated.replace(path, 'fs'+path)
generated = generated.replace('[[ -b $DEV', '[[ -f $DEV')
setup_pre = r'''
mkdir -p fs/sys/block/zram0 fs/dev
echo 0 >fs/sys/block/zram0/disksize
echo '[lzo] lz4 zstd' >fs/sys/block/zram0/comp_algorithm
cat >bin/modprobe <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
cat >bin/findmnt <<'EOF'
#!/usr/bin/env bash
exit 1
EOF
cat >bin/mkswap <<'EOF'
#!/usr/bin/env bash
echo mkswap >>operations
EOF
cat >bin/swapon <<'EOF'
#!/usr/bin/env bash
if [[ $1 == --show=NAME ]]; then
    [[ ! -e active ]] || echo fs/dev/zram0
else
    echo swapon >>operations
    touch active
fi
exit 0
EOF
chmod +x bin/*
'''
for name, extra, expected in [
    ('setup-waits-for-device', '(sleep 0.5; touch fs/dev/zram0) &', 'mkswap\nswapon'),
    ('setup-preserves-existing-device', 'touch fs/dev/zram0; echo 123456 >fs/sys/block/zram0/disksize', 'swapon'),
    ('setup-already-active-no-mutations', 'touch fs/dev/zram0 active', ''),
]:
    body = setup_pre+extra+"\ncat >setup-test.sh <<'TEST_SETUP'\n"+generated+"\nTEST_SETUP\nbash setup-test.sh\n"
    body += "[[ $(cat operations 2>/dev/null || true) == '"+expected+"' ]]\n"
    run(name, body)
if __name__ == '__main__':
    unittest.main()
