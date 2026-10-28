"""Record file identity at installation; refuse unrecognized or changed files on removal."""
import hashlib
import json
import os
from pathlib import Path
import stat
import sys

MARKER = '.mintvault-installation.json'
MODULES = '__init__ __main__ cli crypto exceptions fs_utils gui i18n models settings vault'.split()


def open_directory(path):
    path = Path(path)
    if not path.is_absolute() or '..' in path.parts:
        raise ValueError('Installation paths must be absolute and contain no ..')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def fingerprint(fd, name):
    file_fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
    try:
        st = os.fstat(file_fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid():
            raise ValueError('Unrecognized installation file')
        h = hashlib.sha256()
        while chunk := os.read(file_fd, 262144):
            h.update(chunk)
        return [st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, h.hexdigest()]
    finally:
        os.close(file_fd)


def main():
    mode = sys.argv[1:]
    if mode not in (['record'], ['remove'], ['remove', '--dry-run']):
        raise ValueError('Invalid manifest command')
    if mode == ['remove']:
        raise ValueError('Automatic uninstall is disabled: concurrent replacement can delete unrelated files. Use --dry-run for inspection.')
    root = Path(os.environ.get('MINTVAULT_INSTALL_DIR', str(Path.home() / '.local/share/mintvault')))
    bin_dir = Path(os.environ.get('MINTVAULT_BIN_DIR', str(Path.home() / '.local/bin')))
    desktop_dir = Path(os.environ.get('MINTVAULT_DESKTOP_DIR', str(Path.home() / '.local/share/applications')))
    if root in (Path('/'), Path.home()):
        raise ValueError('Unsafe installation root')
    groups = [
        (root / 'mintvault', [name + '.py' for name in MODULES]),
        (root, ['requirements.txt', 'run_mintvault.sh', 'installation_manifest.py', 'uninstall.sh']),
        (bin_dir, ['mintvault']), (desktop_dir, ['mintvault.desktop']),
    ]
    root_fd = open_directory(root)
    try:
        root_st = os.fstat(root_fd)
        identity = [str(root), root_st.st_dev, root_st.st_ino, str(bin_dir), str(desktop_dir)]
        if mode == ['record']:
            records = []
            for directory, names in groups:
                fd = open_directory(directory)
                try:
                    for name in names:
                        records.append([str(directory), name, fingerprint(fd, name)])
                finally:
                    os.close(fd)
            data = json.dumps({'identity': identity, 'files': records}).encode()
            # O_NOFOLLOW prevents overwriting an unrelated symlink at the marker path.
            fd = os.open(MARKER, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=root_fd)
            with os.fdopen(fd, 'wb') as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            os.fsync(root_fd)
            return
        fd = os.open(MARKER, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=root_fd)
        with os.fdopen(fd) as f:
            data = json.load(f)
        if data['identity'] != identity:
            raise ValueError('Installation identity or configured paths differ; nothing removed')
        allowed = {(str(directory), name) for directory, names in groups for name in names}
        for directory, name, expected in data['files']:
            if (directory, name) not in allowed:
                raise ValueError('Invalid installation manifest')
        for directory, name, expected in data['files']:
            fd = open_directory(directory)
            try:
                try:
                    current = fingerprint(fd, name)
                except FileNotFoundError:
                    continue
                if current != expected:
                    print(f'Preserved changed file: {directory}/{name}')
                    continue
                print(f'Would remove: {directory}/{name}')
            finally:
                os.close(fd)
        # Keep the record for review and to allow a repeated cleanup of unchanged files.
    finally:
        os.close(root_fd)


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError) as exc:
        raise SystemExit(f'Refusing unrecognized installation: {exc}')
