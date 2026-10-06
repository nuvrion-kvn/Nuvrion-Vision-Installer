#!/usr/bin/env python3
# Nuvrion · release 1.0.0
"""Install bundled public files and game code; never overwrite player data."""
import json
import os
from pathlib import Path
import secrets
import sys


def install_site(bundle, domain, prefix=Path('/')):
    bundle, prefix = Path(bundle), Path(prefix)
    for source, target in [('public', 'var/www/decoy'), ('server', 'usr/local/lib/nuvrion-pokehabitat')]:
        destination = prefix / target
        if destination.is_symlink():
            raise ValueError('Site installation directory must not be a symlink')
        destination.mkdir(parents=True, exist_ok=True, mode=0o755)
        # The root installer uses umask 077. Public assets and service code
        # must still be readable by www-data and nuvrion-game on resumes.
        destination.chmod(0o755)
        for path in sorted((bundle / source).rglob('*')):
            if path.is_symlink():
                raise ValueError('Bundled site must not contain symlinks')
            relative = path.relative_to(bundle / source)
            target_path = destination / relative
            if target_path.is_symlink():
                raise ValueError('Site destination must not contain symlinks')
            if path.is_dir():
                target_path.mkdir(exist_ok=True, mode=0o755)
                target_path.chmod(0o755)
            elif path.is_file():
                target_path.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
                data = path.read_bytes()
                temporary = target_path.with_name(target_path.name + '.install')
                fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
                try:
                    with os.fdopen(fd, 'wb') as stream:
                        os.fchmod(stream.fileno(), 0o644)
                        stream.write(data);stream.flush();os.fsync(stream.fileno())
                    os.replace(temporary, target_path)
                finally:
                    temporary.unlink(missing_ok=True)
    env = prefix / 'etc/nuvrion-pokehabitat.env'
    env.parent.mkdir(parents=True, exist_ok=True)
    if not env.exists():
        # O_EXCL prevents a resume race from rotating the pepper or following links.
        fd = os.open(env, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w') as stream:
            stream.write(f'AUTH_PEPPER={secrets.token_hex(32)}\nSITE_ORIGIN=https://{domain}\n')
            stream.flush();os.fsync(stream.fileno())
    if env.is_symlink() or env.stat().st_mode & 0o077:
        raise ValueError('Game authentication file must have mode 0600')
    if f'SITE_ORIGIN=https://{domain}\n' not in env.read_text():
        raise ValueError('Saved game origin does not match this node')
    print('✓ Автономный PokéHabitat установлен; данные игроков не перезаписываются.')


if __name__ == '__main__':
    base = Path(sys.argv[1])
    settings = json.loads((base / 'settings.json').read_text())
    install_site(base / 'bootstrap/pokehabitat', settings['domain'])
