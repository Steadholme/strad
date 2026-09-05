import importlib.util
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
spec = importlib.util.spec_from_file_location('missing_dependency_checks', ROOT / 'l2_missing_dependencies.py')
checks = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checks)


class MissingDependencyEvidenceTests(unittest.TestCase):
    def test_exact_backend_missing_error_is_recognized(self):
        self.assertTrue(checks.missing_ghidra_confirmed([{'stage': 'child_bootstrap', 'code': 'ENOENT',
            'message': "ENOENT: lstat '/opt/ghidra/support/analyzeHeadless'"}]))

    def test_log_prefix_or_unrelated_startup_failure_cannot_pass(self):
        for value in [
            {'stage': 'config', 'code': 'ENOENT', 'message': '/opt/ghidra/support/analyzeHeadless'},
            {'stage': 'child_bootstrap', 'code': 'EACCES', 'message': '/opt/ghidra/support/analyzeHeadless'},
            {'stage': 'child_bootstrap', 'code': 'ENOENT', 'message': '/unrelated/file'},
            {'stage': 'spool', 'message': 'MISSING_GHIDRA_DIAGNOSTIC'},
        ]:
            with self.subTest(value=value):
                self.assertFalse(checks.missing_ghidra_confirmed([value]))


if __name__ == '__main__':
    unittest.main()
