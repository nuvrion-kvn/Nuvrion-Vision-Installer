#!/usr/bin/env python3
# Nuvrion · release 1.0.0
"""Build a reproducible single-file installer without accessing the network."""
import base64
import gzip
import hashlib
import io
from pathlib import Path
import tarfile

ROOT = Path(__file__).resolve().parent
TUNING_SHA256 = 'bec4c83770ffa2700dc670836639b02049100923833d916b25531d41cd064ab6'
TRAFFIC_CONTROL_SHA256 = '3328933ded3f5ac47db57749e62782f34d42c1c7dfbe0caf14bfa3ce14c9a339'


def build():
    vendor = ROOT/'vendor/nuvrion-auto-tuning.sh'
    assert hashlib.sha256(vendor.read_bytes()).hexdigest() == TUNING_SHA256, 'Tuning snapshot changed'
    traffic_control = ROOT/'src/nuvrion-traffic-control.py'
    assert hashlib.sha256(traffic_control.read_bytes()).hexdigest() == TRAFFIC_CONTROL_SHA256, 'Traffic Control snapshot changed'
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w', format=tarfile.USTAR_FORMAT) as tar:
        files = [(p.name,p) for p in sorted((ROOT/'src').iterdir()) if p.name != 'installer.sh' and p.is_file()]
        # The installed management copy does not need the large embedded payload.
        # Keeping it inside the verified archive makes process substitution safe:
        # Bash never has to copy its already-consumed /dev/fd input.
        files.append(('installer-manager.sh', ROOT/'src/installer.sh'))
        files.append(('nuvrion-auto-tuning.sh', vendor))
        # Complete browser application, artwork, game engine and SQL migrations.
        # Dependencies are bundled; no npm/Cloudflare/PokeAPI is used on the node.
        for source, target in [('site/dist', 'pokehabitat/public'), ('site/server/dist', 'pokehabitat/server')]:
            directory = ROOT/source
            assert directory.is_dir(), f'Build the autonomous site first: {source}'
            files.extend((target+'/'+p.relative_to(directory).as_posix(), p)
                         for p in sorted(directory.rglob('*'), key=lambda p: p.relative_to(directory).as_posix()) if p.is_file())
        for name, path in files:
            data = path.read_bytes()
            info = tarfile.TarInfo(name)
            info.size, info.mode, info.mtime = len(data), 0o600, 0
            tar.addfile(info, io.BytesIO(data))
    payload = gzip.compress(output.getvalue(), compresslevel=9, mtime=0)
    # Python 3.11/3.12 may use the host OS byte when mtime=0.
    # RFC 1952: 255 means unknown OS; normalize it for cross-platform builds.
    payload = payload[:9] + b'\xff' + payload[10:]
    encoded = base64.encodebytes(payload).decode('ascii')
    payload_hash = hashlib.sha256(payload).hexdigest()
    func = (f"readonly NUVRION_PAYLOAD_SHA256='{payload_hash}'\n\n"
            + "payload() {\n    cat <<'NUVRION_PAYLOAD'\n"
            + encoded + 'NUVRION_PAYLOAD\n}\n\n')
    source = (ROOT/'src/installer.sh').read_text(encoding='utf-8')
    assert '@PAYLOAD_SHA256@' not in source, 'Obsolete payload placeholder in manager source'
    marker = '# Private child entry'
    assert source.count(marker) == 1, 'Payload insertion marker missing or duplicated'
    source = source.replace(marker, func + marker)
    assert source.count('payload() {') == 1, 'Payload function was not injected'
    assert f"readonly NUVRION_PAYLOAD_SHA256='{payload_hash}'" in source, 'Payload hash was not injected'
    manager = (ROOT/'src/installer.sh').read_text(encoding='utf-8')
    assert '@PAYLOAD_SHA256@' not in manager, 'Payload placeholder leaked into manager'
    assert 'payload() {' not in manager, 'Manager must not contain the embedded archive'
    dest = ROOT/'nuvrion-vision-install.sh'
    dest.write_text(source, encoding='utf-8', newline='\n')
    dest.chmod(0o755)
    (ROOT/'SHA256SUMS').write_text(hashlib.sha256(dest.read_bytes()).hexdigest() + '  ' + dest.name + '\n', encoding='utf-8', newline='\n')
    print(f'{dest.name}: {dest.stat().st_size} bytes')


if __name__ == '__main__':
    build()
