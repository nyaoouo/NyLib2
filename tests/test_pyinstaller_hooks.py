import importlib.machinery
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
                    self.assertEqual(g['datas'], [])
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

    def test_finder_error_is_logged_at_debug(self):
        for key in _CASES:
            with self.subTest(hook=key):
                with mock.patch.object(pyi_hooks.logger, 'debug') as debug:
                    self.run_hook(key, OSError('boom'))
                self.assertTrue(any('boom' in str(c.args) for c in debug.call_args_list))

    def test_present_msvc_builds_each_missing_dll_once(self):
        for key, (fname, pkg, cpps, builds) in _CASES.items():
            with self.subTest(hook=key):
                warnings, spies, before, after, g = self.run_hook(key, (15, 'C:/msvc'))
                for n in builds:
                    spies[n].assert_called_once()
                    self.assertTrue(str(spies[n].call_args.args[0]).endswith('.dll'))
                spies['ensure_msvc'].assert_not_called()
                self.assertEqual(warnings, [])


@unittest.skipIf(pyi_hooks is None, 'PyInstaller is not installed')
class PyimguiStubTests(unittest.TestCase):
    maxDiff = None

    def run_hook(self, package, frontend):
        with tempfile.TemporaryDirectory() as tmp:
            core = os.path.join(tmp, 'pyimgui.cp3XX-win_amd64.pyd')
            pkg_dir = os.path.join(tmp, 'pyimgui')
            native = 'dx11' + importlib.machinery.EXTENSION_SUFFIXES[0]
            files = [native, 'dx12.cp39-win_amd64.pyd', '__init__.pyi', 'esp.py',
                     f'{frontend}/__init__.pyi', f'{frontend}/nested/types.pyi', 'dx12/__init__.pyi',
                     'vk/__init__.pyi', 'imgui/__init__.pyi', 'imgui/ctx.pyi',
                     '__pycache__/x.cpython-314.pyc', '__pycache__/x.pyi', 'unknown/__init__.pyi']
            open(core, 'w').close()
            for rel in files:
                dst = os.path.join(pkg_dir, *rel.split('/'))
                os.makedirs(os.path.dirname(dst), exist_ok=True)
                open(dst, 'w').close()
            with mock.patch.object(pyi_hooks, 'get_module_file_attribute', return_value=core) as locate:
                with self.assertLogs(pyi_hooks.logger.name, level='DEBUG') as cm:
                    g = runpy.run_path(os.path.join(_HOOKS, f'hook-{package}.py'))
            locate.assert_called_once_with(package)
            dest = os.path.join('nylib', 'pyimgui') if package == 'nylib.pyimgui' else 'pyimgui'
            expected = ['__init__.pyi', 'esp.py', f'{frontend}/__init__.pyi',
                        f'{frontend}/nested/types.pyi', 'imgui/__init__.pyi', 'imgui/ctx.pyi']
            self.assertCountEqual(g['datas'], [(os.path.join(pkg_dir, *rel.split('/')),
                                               os.path.dirname(os.path.join(dest, *rel.split('/'))))
                                              for rel in expected])
            self.assertEqual(g['binaries'], [(os.path.join(pkg_dir, native), dest)])
            hidden = ['nylib.pyimgui.dx11', 'pyimgui.dx11'] if package == 'nylib.pyimgui' else ['pyimgui.dx11']
            self.assertEqual(g['hiddenimports'], hidden)
            debug = [r.getMessage() for r in cm.records if r.levelname == 'DEBUG']
            self.assertCountEqual(debug, [f'hook-{package}: skipping stub folder {folder}, its frontend was not collected'
                                          for folder in ('dx12', 'vk', '__pycache__', 'unknown')])
            info = [r.getMessage() for r in cm.records if r.levelname == 'INFO']
            self.assertEqual(info, [f'hook-{package}: skipping dx12.cp39-win_amd64.pyd, built for another Python ABI'])

    def test_only_collected_frontend_and_core_stubs(self):
        for package in ('nylib.pyimgui', 'pyimgui'):
            with self.subTest(hook=package):
                self.run_hook(package, 'dx11')

    def test_frontend_folder_matches_case_insensitively(self):
        for package in ('nylib.pyimgui', 'pyimgui'):
            with self.subTest(hook=package):
                self.run_hook(package, 'DX11')


@unittest.skipIf(pyi_hooks is None, 'PyInstaller is not installed')
class IconsHookTests(unittest.TestCase):
    def test_only_font_resources_are_collected(self):
        icons = os.path.join(ROOT, 'nylib', 'imguiutils', 'icons')
        with ExitStack() as st:
            st.enter_context(mock.patch.object(pyi_hooks, 'is_package', return_value=True))
            st.enter_context(mock.patch.object(pyi_hooks, 'get_all_package_paths', return_value=[icons]))
            st.enter_context(mock.patch.object(pyi_hooks, 'collect_submodules', return_value=[]))
            g = runpy.run_path(os.path.join(_HOOKS, 'hook-nylib.imguiutils.icons.py'))
        resources = os.path.join(icons, 'fa', 'resources')
        dest = os.path.join('nylib', 'imguiutils', 'icons', 'fa', 'resources')
        self.assertCountEqual(g['datas'], [(os.path.join(resources, name), dest)
                                          for name in ('fa-regular-400.ttf', 'fa-solid-900.ttf')])


@unittest.skipIf(pyi_hooks is None, 'PyInstaller is not installed')
class KeystoneHookTests(unittest.TestCase):
    def test_excludes_distutils_and_preserves_binaries(self):
        binaries = [('keystone/keystone.dll', 'keystone')]
        with mock.patch.object(pyi_hooks, 'collect_dynamic_libs', return_value=binaries) as collect:
            g = runpy.run_path(os.path.join(_HOOKS, 'hook-keystone.py'))
        collect.assert_called_once_with('keystone')
        self.assertEqual(g['excludedimports'], ['distutils'])
        self.assertEqual(g['binaries'], binaries)


if __name__ == '__main__':
    unittest.main()
