"""Build the classroom source ZIP without environments or generated files."""
from pathlib import Path
import hashlib
import zipfile

ROOT = Path(__file__).resolve().parents[1]
FILES = [
    'app.py', 'StartLab.cmd', 'README.md', 'INSTRUCTOR.md', 'VERIFY.md',
    'LICENSE', 'THIRD_PARTY.md', '.gitignore',
    'static/index.html', 'static/app.js', 'static/style.css',
    'static/icon.svg', 'static/manifest.webmanifest',
    'tests/test_app.py', 'tests/test_distribution.py', 'tests/browser_checks.py',
    'checks/package.py',
]


def main():
    missing = [name for name in FILES if not (ROOT / name).is_file()]
    if missing:
        raise SystemExit('Missing required source files: ' + ', '.join(missing))
    folder = ROOT / 'dist'
    folder.mkdir(exist_ok=True)
    target = folder / 'PocketVulnLab.zip'
    with zipfile.ZipFile(target, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
        for name in FILES:
            archive.write(ROOT / name, 'PocketVulnLab/' + name)
    with zipfile.ZipFile(target) as archive:
        assert archive.testzip() is None
        assert len(archive.namelist()) == len(FILES)
    print(target)
    print(f'{len(FILES)} source files; {target.stat().st_size} bytes')
    print('SHA256: ' + hashlib.sha256(target.read_bytes()).hexdigest())


if __name__ == '__main__':
    main()
