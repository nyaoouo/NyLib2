import ast
import os
import subprocess
import sys
import tempfile
import types
import unittest
from modulefinder import ModuleFinder
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_PIP_PY = os.path.join(ROOT, 'nylib', 'utils', 'pip.py')


def _names(node):
    if isinstance(node, ast.Import): return [a.name for a in node.names]
    if isinstance(node, ast.ImportFrom): return [node.module or ''] + ['.'.join((node.module or '', a.name)) for a in node.names]
    return []


def _is_pip(name):
    return name.split('.')[0] in ('pip', 'ensurepip')


def _fake_pip(code):
    mods = {n: types.ModuleType(n) for n in ('pip', 'pip._internal', 'pip._internal.commands', 'pip._internal.cli', 'pip._internal.cli.status_codes')}
    mods['pip._internal.cli.status_codes'].SUCCESS = 0
    for n, m in mods.items():  # link children as attributes, as real imports do
        if '.' in n: setattr(mods[n.rpartition('.')[0]], n.rpartition('.')[2], m)
    calls = []

    def create_command(name):
        return types.SimpleNamespace(main=lambda args: calls.append((name, args)) or code)

    mods['pip._internal.commands'].create_command = create_command
    return mods, calls


class PipUrllibTests(unittest.TestCase):
    def test_import_leaves_urllib_request_and_ssl_unloaded(self):
        child = r'''
import os, sys
import nylib.utils.pip as nypip
assert os.path.normcase(os.path.abspath(nypip.__file__)) == os.path.normcase(os.path.join(os.getcwd(), 'nylib', 'utils', 'pip.py')), nypip.__file__
print('urllib.request' in sys.modules, 'ssl' in sys.modules)
'''
        result = subprocess.run([sys.executable, '-B', '-c', child], cwd=ROOT, capture_output=True, text=True, timeout=300)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), 'False False')

    def test_no_import_statement_names_urllib_request_or_error(self):
        with open(_PIP_PY, encoding='utf-8') as f:
            tree = ast.parse(f.read())
        bad = [(n.lineno, x) for n in ast.walk(tree) for x in _names(n) if x in ('urllib.request', 'urllib.error')]
        self.assertEqual(bad, [])


class FreezePipTests(unittest.TestCase):
    def test_closure_of_pip_module_excludes_pip(self):
        with tempfile.TemporaryDirectory() as tmp:
            script = os.path.join(tmp, 'app.py')
            with open(script, 'w') as f:
                f.write('import nylib.utils.pip\n')
            finder = ModuleFinder(path=[ROOT] + sys.path)
            finder.run_script(script)
        self.assertIn('nylib.utils.pip', finder.modules)
        self.assertEqual(sorted(n for n in finder.modules if _is_pip(n)), [])

    def test_no_import_statement_names_pip(self):
        with open(_PIP_PY, encoding='utf-8') as f:
            tree = ast.parse(f.read())
        bad = [(n.lineno, x) for n in ast.walk(tree) for x in _names(n) if _is_pip(x)]
        self.assertEqual(bad, [])

    def test_install_through_fake_pip(self):
        from nylib.utils import pip as nypip
        for code, ok in ((0, True), (1, False)):
            mods, calls = _fake_pip(code)
            with mock.patch.dict(sys.modules, mods), mock.patch.dict(os.environ, {'PIP_NO_INDEX': '1'}), \
                    mock.patch.object(nypip, 'set_pip_default_index', lambda *a, **k: True):
                if ok:
                    self.assertTrue(nypip.install('x'))
                else:
                    with self.assertRaises(RuntimeError):
                        nypip.install('x')
            self.assertEqual(calls, [('install', ['x'])])

    def test_bootstrap_falls_back_to_ensurepip(self):
        from nylib.utils import pip as nypip
        mods, _ = _fake_pip(0)
        ensurepip = types.ModuleType('ensurepip')
        ensurepip.bootstrap = mock.Mock(side_effect=lambda: sys.modules.__setitem__('pip', mods['pip']))
        with mock.patch.dict(sys.modules, {'pip': None, 'ensurepip': ensurepip}):
            nypip.boostrap_pip()
        ensurepip.bootstrap.assert_called_once_with()


if __name__ == '__main__':
    unittest.main()
