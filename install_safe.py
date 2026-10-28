"""Fresh installation with exclusive file creation; never overwrite existing files."""
import os
from pathlib import Path
import sys
from installation_manifest import MODULES, MARKER, open_directory

source = Path(sys.argv[1])
root = Path(os.environ['MINTVAULT_INSTALL_DIR'])
bin_dir = Path(os.environ['MINTVAULT_BIN_DIR'])
desktop = Path(os.environ['MINTVAULT_DESKTOP_DIR'])
if root in (Path('/'), Path.home()):
    raise SystemExit('Unsafe installation root')
# Avoid shell syntax injection in the launcher and ambiguity in desktop Exec.
if any(c in str(root) + str(bin_dir) for c in '\n\r"$`\\'):
    raise SystemExit('Unsupported characters in installation path')
launcher = f'#!/usr/bin/env bash\nexport PYTHONPATH="{root}:$' + '{PYTHONPATH:-}"\nexec python3 -m mintvault "$@"\n'
shortcut = f'[Desktop Entry]\nVersion=1.0\nType=Application\nName=MintVault\nExec="{bin_dir}/mintvault" gui %f\nIcon=security-high\nTerminal=false\nCategories=Utility;Security;\n'
files = [(root / 'mintvault', n + '.py', (source / 'mintvault' / (n + '.py')).read_bytes(), 0o644) for n in MODULES]
files += [(root, n, (source / n).read_bytes(), 0o755 if n.endswith('.sh') else 0o644) for n in ('requirements.txt', 'run_mintvault.sh', 'installation_manifest.py', 'uninstall.sh')]
files += [(bin_dir, 'mintvault', launcher.encode(), 0o755), (desktop, 'mintvault.desktop', shortcut.encode(), 0o644)]
fds = {}
try:
    for directory in {x[0] for x in files} | {root}:
        fds[directory] = open_directory(directory)
    for directory, name, _, _ in files + [(root, MARKER, b'', 0o600)]:
        try:
            os.stat(name, dir_fd=fds[directory], follow_symlinks=False)
        except FileNotFoundError:
            continue
        raise FileExistsError(f'Refusing existing installation target: {directory / name}')
    for directory, name, content, mode in files:
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode, dir_fd=fds[directory])
        with os.fdopen(fd, 'wb') as out:
            out.write(content)
            out.flush()
            os.fsync(out.fileno())
        os.fsync(fds[directory])
finally:
    for fd in fds.values():
        os.close(fd)
# Record using the installed manifest; if recording fails files remain, never remove unknown data.
os.execv(sys.executable, [sys.executable, str(root / 'installation_manifest.py'), 'record'])
