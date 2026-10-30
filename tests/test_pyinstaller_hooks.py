import os
import runpy
import shutil
import tempfile
import unittest
from contextlib import ExitStack
from unittest import mock

try:
    import PyInstaller.utils.hooks as pyi_hooks
except ImportError:
    pyi_hooks = None

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_HOOKS = os.path.join(ROOT, 'nylib', '__pyinstaller')
_WINUTILS = os.path.join(ROOT, 'nylib', 'winutils')

# hook file, package it locates, the .cpp files copied into the temp package, the spied build calls
_CASES = {
    'breakpoint': ('hook-nylib.winutils.breakpoint.py', 'nylib.winutils.breakpoint',
                   ['veh/veh_backend.cpp', 'debugger/debugger_backend.cpp'],
                   ['nylib.winutils.breakpoint.veh.build_backend', 'nylib.winutils.breakpoint.debugger.build_backend']),
    'python_loader': ('hook-nylib.winutils.python_loader.py', 'nylib.winutils.python_loader',
                      ['python_loader.cpp'], ['nylib.winutils.python_loader.build_loader']),
}
_MSVC = 'nylib.winutils.msvc.msvc14_find_vc2017'


def _listing(path):
    return sorted(os.path.relpath(os.path.join(d, f), path) for d, _, fs in os.walk(path) for f in fs)


@unittest.skipIf(pyi_hooks is None, 'PyInstaller is not installed')
class PyInstallerHookTests(unittest.TestCase):
    def run_hook(self, key, msvc):
        """Run one hook against a temp package with .cpp files and no DLLs; returns (warnings, spies, files before, files after, hook globals)."""
        fname, pkg, cpps, builds = _CASES[key]
        with tempfile.TemporaryDirectory() as tmp, ExitStack() as st:
            pkg_dir = os.path.join(tmp, 'pkg')
            for rel in cpps:
                dst = os.path.join(pkg_dir, *rel.split('/'))
                os.makedirs(os.path.dirname(dst), exist_ok=True)
                shutil.copy(os.path.join(_WINUTILS, key, *rel.split('/')), dst)
            open(os.path.join(pkg_dir, '__init__.py'), 'w').close()
            st.enter_context(mock.patch.object(pyi_hooks, 'get_module_file_attribute', lambda name: os.path.join(pkg_dir, '__init__.py')))
            msvc_mock = mock.Mock(side_effect=msvc) if isinstance(msvc, BaseException) else mock.Mock(return_value=msvc)
            st.enter_context(mock.patch(_MSVC, msvc_mock))
            spies = {n: st.enter_context(mock.patch(n)) for n in builds}
            spies['ensure_msvc'] = st.enter_context(mock.patch('nylib.winutils.ensure_env.ensure_msvc'))
            before = _listing(tmp)
            with self.assertLogs(pyi_hooks.logger.name, level='DEBUG') as cm:
                g = runpy.run_path(os.path.join(_HOOKS, fname))
            warnings = [r.getMessage() for r in cm.records if r.levelname == 'WARNING']
            return warnings, spies, before, _listing(tmp), g

    def test_absent_msvc_builds_nothing_and_warns(self):
        for key, (fname, pkg, cpps, builds) in _CASES.items():
            for absent in ((None, None), OSError('boom')):
                with self.subTest(hook=key, finder=repr(absent)):
                    warnings, spies, before, after, g = self.run_hook(key, absent)
                    for name, spy in spies.items():
                        spy.assert_not_called()
                    self.assertEqual(before, after)
                    self.assertEqual(g['binaries'], [])
                    self.assertEqual(len(g['datas']), len(cpps))
                    self.assertEqual(len(warnings), len(cpps))
                    for rel, w in zip(sorted(cpps), sorted(warnings)):
                        dll = os.path.basename(rel)[:-4] + '.dll'
                        self.assertIn(dll, w)
                        self.assertIn(f'hook-nylib.winutils.{key}: ', w)
                        self.assertIn('MSVC is not installed; not building it', w)
                    if key == 'python_loader':
                        self.assertTrue(all('nylib.winutils.python_loader.build_loader()' in w for w in warnings))
                    if key == 'breakpoint':
                        self.assertTrue(any('nylib.winutils.breakpoint.veh.build_backend()' in w for w in warnings))
                        self.assertTrue(any('nylib.winutils.breakpoint.debugger.build_backend()' in w for w in warnings))

    def test_present_msvc_builds_each_missing_dll_once(self):
        for key, (fname, pkg, cpps, builds) in _CASES.items():
            with self.subTest(hook=key):
                warnings, spies, before, after, g = self.run_hook(key, (15, 'C:/msvc'))
                for n in builds:
                    spies[n].assert_called_once()
                    self.assertTrue(str(spies[n].call_args.args[0]).endswith('.dll'))
                spies['ensure_msvc'].assert_not_called()
                self.assertEqual(warnings, [])


if __name__ == '__main__':
    unittest.main()
