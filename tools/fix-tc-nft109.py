#!/usr/bin/env python3
# Nuvrion · release 1.0.0
"""Точечное исправление диагностики. Не вызывает nft, systemctl или APT."""
import fcntl
import hashlib
import os
from pathlib import Path
import signal
import stat
import sys
import tempfile

OLD = '7bb39726a72643bf7cad65ed9d8297944391fac943f7e12a9efacfd9d5963f4a'
NEW = '1726074533b2ef24f4be6b1039564575cbf2df304c077c51c16fe8ceb2654320'
REVISIONS = {OLD: NEW, 'a93f6ba2198a644b0a5372de8a9fd0e073a17f2703cfb713eed758a85c14bfbd': '0abc48bbf6ffa58e187e77d95303fe9d010927143f4157f5f166f0d50bd9b9b7', '02a5afd37c4a1119ec3d47641f5204b3fddd9e65a62d887f63c864abf44db028': 'f329e9296dde568c86a42df3ff5b46318deafb2fce6c476f5496110c6bb67763', '9c30dcd1cf7fae3d65be9440afc61cfbb7c758357abb87b98bf9f015fbc9af18': '32ef49a37554c87062f47275c8de17fae34b16ade6c60bfb732e534f6e5f5c7a'}
BEFORE = b'                    if m["op"] in ("==", "in"):\n'
INSERT = b'''                    # nft 1.0.9: ct state membership is a bare JSON array.
                    # Only normalize this known expression, not concatenations.
                    if (m.get("left") == {"ct": {"key": "state"}} and
                            m.get("op") == "in" and isinstance(m.get("right"), list)):
                        m["right"] = {"set": m["right"]}
'''
TARGETS = (Path('/opt/remnanode/nuvrion-traffic-control.py'),
           Path('/usr/local/bin/nuvrion-traffic-control'))
BACKUPS = Path('/opt/remnanode/backups')


def corrected(data):
    digest = hashlib.sha256(data).hexdigest()
    if digest in REVISIONS.values():
        return data
    target = REVISIONS.get(digest)
    if target is None or data.count(BEFORE) != 1:
        raise ValueError('Другая ревизия Traffic Control: автоматическая замена запрещена.')
    result = data.replace(BEFORE, INSERT + BEFORE, 1)
    if hashlib.sha256(result).hexdigest() != target:
        raise ValueError('Контрольная сумма исправления не совпала.')
    compile(result, '<Traffic Control>', 'exec')
    return result


def atomic(path, data, mode):
    fd, temporary = tempfile.mkstemp(prefix='.tc-nft109-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            os.fchmod(stream.fileno(), mode)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def interrupted(signum, _frame):
    raise SystemExit(128 + signum)


def main():
    if os.geteuid() != 0:
        raise ValueError('Запустите от root.')
    os.umask(0o077)
    locks = []
    try:
        for name in ('nuvrion-vision.lock', 'nuvrion-traffic-control.lock'):
            fd = os.open('/run/' + name, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
            locks.append(fd)
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        entries = []
        for path in TARGETS:
            st = path.lstat()
            if not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or st.st_gid != 0 or st.st_mode & 0o022:
                raise ValueError('Небезопасный тип, владелец или права файла: ' + str(path))
            before = path.read_bytes()
            entries.append((path, before, corrected(before), stat.S_IMODE(st.st_mode)))
        if all(before == after for _, before, after, _ in entries):
            print('Исправление уже установлено; файлы не изменены.')
            return
        if BACKUPS.is_symlink():
            raise ValueError('Каталог резервных копий является ссылкой.')
        BACKUPS.mkdir(mode=0o700, exist_ok=True)
        st = BACKUPS.stat()
        if st.st_uid != 0 or st.st_mode & 0o077:
            raise ValueError('Небезопасные права каталога резервных копий.')
        backup = Path(tempfile.mkdtemp(prefix='tc-nft109-', dir=BACKUPS))
        for path, before, _, _ in entries:
            atomic(backup / path.name, before, 0o600)
        print('Резервные копии: ' + str(backup), flush=True)
        signal.signal(signal.SIGTERM, interrupted)
        signal.signal(signal.SIGINT, interrupted)
        changed = []
        try:
            for path, before, after, mode in entries:
                if before != after:
                    # Include the target before replace: interruption can arrive just after rename.
                    changed.append((path, before, mode))
                    atomic(path, after, mode)
        except BaseException:
            for path, before, mode in reversed(changed):
                atomic(path, before, mode)
            raise
        print('Исправлена только проверка JSON nftables. Правила и службы не изменялись.')
    finally:
        for fd in reversed(locks):
            os.close(fd)


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError) as exc:
        print('Ошибка: ' + str(exc), file=sys.stderr)
        sys.exit(1)
