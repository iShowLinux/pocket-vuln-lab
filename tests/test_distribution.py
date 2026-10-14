"""Checks the student-facing launcher and clean source archive."""
from pathlib import Path
import os
import subprocess
import sys
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[1]


class DistributionChecks(unittest.TestCase):
    @unittest.skipUnless(os.name == 'nt', 'Windows launcher')
    def test_windows_launcher_runs_the_real_cli(self):
        launcher = ROOT / 'StartLab.cmd'
        self.assertTrue(launcher.is_file(), 'Windows launcher has not been implemented')
        result = subprocess.run(['cmd.exe', '/d', '/c', str(launcher), '--help'], capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('--lan', result.stdout)
        self.assertIn('127.0.0.1', result.stdout)

    def test_source_archive_contains_only_deliverable_files(self):
        builder = ROOT / 'checks' / 'package.py'
        self.assertTrue(builder.is_file(), 'Archive builder has not been implemented')
        result = subprocess.run([sys.executable, str(builder)], capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        with zipfile.ZipFile(ROOT / 'dist' / 'PocketVulnLab.zip') as archive:
            self.assertIsNone(archive.testzip())
            names = archive.namelist()
            for name in ['app.py', 'StartLab.cmd', 'README.md', 'INSTRUCTOR.md', 'static/app.js', 'static/index.html', 'tests/test_app.py']:
                self.assertIn('PocketVulnLab/' + name, names)
            self.assertFalse(any('.venv/' in n or '__pycache__' in n or '/artifacts/' in n or '/dist/' in n for n in names))
            self.assertEqual(len(names), len(set(names)))


if __name__ == '__main__':
    unittest.main(verbosity=2)
