"""Static AST hygiene gate for nylib/ue: no nylib.winapi, no raw ctypes memory
access, no third-party imports, Process used only through the sanctioned surface.
"""
import ast
import pathlib
import subprocess
import sys
import tempfile
import unittest

FORBIDDEN_IDENTIFIERS = frozenset({
    'string_at', 'wstring_at', 'memmove', 'from_address', 'read_memoryview', 'CAccessorLocal',
    'windll', 'WinDLL', 'oledll', 'OleDLL', 'CDLL',
})
_PROCESS_CALL_TARGETS = frozenset({
    'nylib.process.Process',
    'nylib.process.Process.from_name',
    'nylib.process.Process.from_id',
})
_CTYPE_BINDING_MODULE = 'nylib/ue/engine/accessor.py'
_REPO_ROOT = pathlib.Path(__file__).resolve().parents[3]


def _dotted_dir(module_path: str) -> str:
    return module_path.rsplit('/', 1)[0].replace('/', '.') if '/' in module_path else ''


def _resolve_relative(module_part, level, package_name):
    bits = package_name.rsplit('.', level - 1) if level > 1 else [package_name]
    base = bits[0]
    if module_part:
        return f'{base}.{module_part}' if base else module_part
    return base


def check(source_text: str, module_path: str) -> list[str]:
    """AST-scan one module's source for the nylib/ue hygiene rules; returns formatted findings."""
    tree = ast.parse(source_text, filename=module_path)
    package_name = _dotted_dir(module_path)
    findings = []

    process_names = {'Process'}  # bare `Process` is always assumed to mean the class
    module_alias = {}

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                dotted = alias.name
                if alias.asname:
                    module_alias[alias.asname] = dotted
                if dotted == 'nylib.winapi' or dotted.startswith('nylib.winapi.'):
                    findings.append(f'{module_path}:{node.lineno}: import resolves to nylib.winapi ({dotted})')
                if dotted == '_winapi':
                    findings.append(f'{module_path}:{node.lineno}: import resolves to nylib.winapi ({dotted})')
                top = dotted.split('.', 1)[0]
                if top not in sys.stdlib_module_names and top != 'nylib':
                    findings.append(f'{module_path}:{node.lineno}: import of non-stdlib, non-nylib module {top!r}')
        elif isinstance(node, ast.ImportFrom):
            resolved_from = _resolve_relative(node.module, node.level, package_name) if node.level else (node.module or '')
            for alias in node.names:
                bound_name = alias.asname or alias.name
                candidate = f'{resolved_from}.{alias.name}' if resolved_from else alias.name
                if alias.name in FORBIDDEN_IDENTIFIERS:
                    findings.append(f'{module_path}:{node.lineno}: use of forbidden identifier {alias.name!r}')
                if (alias.name == 'winapi' or candidate == 'nylib.winapi' or candidate.startswith('nylib.winapi.')
                        or resolved_from == '_winapi'):
                    findings.append(f'{module_path}:{node.lineno}: import resolves to nylib.winapi ({candidate})')
                top = (resolved_from or candidate).split('.', 1)[0]
                if top not in sys.stdlib_module_names and top != 'nylib':
                    findings.append(f'{module_path}:{node.lineno}: import of non-stdlib, non-nylib module {top!r}')
                if alias.name == 'Process':
                    process_names.add(bound_name)
                module_alias.setdefault(bound_name, candidate)

    def canonical(node):
        if isinstance(node, ast.Name):
            if node.id in process_names:
                return 'nylib.process.Process'
            return module_alias.get(node.id, node.id)
        if isinstance(node, ast.Attribute):
            base = canonical(node.value)
            return f'{base}.{node.attr}' if base is not None else None
        return None

    parent_map = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            parent_map[child] = node

    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and node.id in FORBIDDEN_IDENTIFIERS:
            findings.append(f'{module_path}:{node.lineno}: use of forbidden identifier {node.id!r}')
        elif isinstance(node, ast.Attribute) and node.attr in FORBIDDEN_IDENTIFIERS:
            findings.append(f'{module_path}:{node.lineno}: use of forbidden identifier {node.attr!r}')
        elif isinstance(node, ast.Call):
            target = None
            if isinstance(node.func, ast.Attribute) and node.func.attr == 'Process':
                base = canonical(node.func.value)
                target = f'{base}.Process' if base is not None else '<expr>.Process'
            else:
                callee = canonical(node.func)
                if callee in _PROCESS_CALL_TARGETS:
                    target = callee
            if target is not None and module_path != 'nylib/ue/memory.py':
                findings.append(f'{module_path}:{node.lineno}: call to Process outside nylib/ue/memory.py ({target})')
            if module_path != _CTYPE_BINDING_MODULE:  # G1: nylib.ctype objects are bound to memory only through view()
                for kw in node.keywords:
                    if kw.arg in ('_address_', '_accessor_'):
                        findings.append(f'{module_path}:{node.lineno}: {kw.arg} passed outside {_CTYPE_BINDING_MODULE}; use view()')
        elif isinstance(node, ast.Attribute) and node.attr == 'current' and canonical(node.value) == 'nylib.process.Process':
            parent = parent_map.get(node)
            if isinstance(parent, ast.Attribute) and parent.value is node and parent.attr in ('process_id', 'handle'):
                continue
            if module_path == 'nylib/ue/calls.py' and isinstance(parent, ast.Attribute) and parent.value is node and parent.attr == 'call':
                continue
            if (module_path == 'nylib/ue/memory.py' and isinstance(parent, ast.Compare)
                    and any(isinstance(op, (ast.Is, ast.IsNot)) for op in parent.ops)
                    and (parent.left is node or node in parent.comparators)):
                continue
            findings.append(f'{module_path}:{node.lineno}: use of Process.current')

        if isinstance(node, ast.Attribute):
            can = canonical(node)
            if can == 'nylib.winapi' or (can is not None and can.startswith('nylib.winapi.')):
                findings.append(f'{module_path}:{node.lineno}: use of nylib.winapi ({can})')

    return findings


def _iter_product_files():
    root = _REPO_ROOT / 'nylib' / 'ue'
    for p in sorted(root.rglob('*.py')):
        rel = p.relative_to(_REPO_ROOT).as_posix()
        if rel.startswith('nylib/ue/tests/'):
            continue
        yield rel


def _module_path_for(raw: str) -> str:
    resolved = pathlib.Path(raw).resolve()
    try:
        rel = resolved.relative_to(_REPO_ROOT)
        return rel.as_posix()
    except ValueError:
        return resolved.as_posix()


def _run_files_mode(argv: list[str]) -> int:
    if not argv:
        print('no paths given', file=sys.stderr)
        return 2
    findings = []
    for raw in argv:
        p = pathlib.Path(raw)
        if not p.is_file() or p.suffix != '.py':
            print(f'not an existing .py file: {raw}', file=sys.stderr)
            return 2
        module_path = _module_path_for(raw)
        try:
            findings.extend(check(p.read_text(encoding='utf-8-sig'), module_path))
        except SyntaxError as e:
            findings.append(f'{module_path}:{e.lineno}: syntax error: {e.msg}')
    for line in findings:
        print(line)
    return 1 if findings else 0


class HygieneScanTests(unittest.TestCase):
    def test_full_tree_scan(self):
        visited = []
        findings = []
        for rel in _iter_product_files():
            visited.append(rel)
            findings.extend(check((_REPO_ROOT / rel).read_text(encoding='utf-8'), rel))
        self.assertGreaterEqual(len(visited), 1)
        self.assertIn('nylib/ue/memory.py', visited)
        self.assertIn(_CTYPE_BINDING_MODULE, visited)
        self.assertEqual(findings, [])


class HygieneCheckTests(unittest.TestCase):
    def test_flags_winapi_import(self):
        findings = check('from nylib import winapi\n', 'nylib/ue/x.py')
        self.assertTrue(any('winapi' in f for f in findings))

    def test_flags_winapi_relative_import(self):
        findings = check('from ...winapi import ReadProcessMemory\n', 'nylib/ue/x/y.py')
        self.assertTrue(any('winapi' in f for f in findings))

    def test_flags_winapi_submodule_import(self):
        findings = check('import nylib.winapi.kernel32\n', 'nylib/ue/x.py')
        self.assertTrue(any('winapi' in f for f in findings))

    def test_flags_private_winapi_stdlib_import(self):
        findings = check('import _winapi\n', 'nylib/ue/x.py')
        self.assertTrue(any('_winapi' in f for f in findings))

    def test_flags_winapi_reexport_from_other_package(self):
        findings = check('from nylib.process import winapi\n', 'nylib/ue/x.py')
        self.assertTrue(any('winapi' in f for f in findings))

    def test_flags_third_party_import(self):
        findings = check('import numpy\n', 'nylib/ue/x.py')
        self.assertTrue(any('numpy' in f for f in findings))

    def test_flags_third_party_import_from(self):
        findings = check('from numpy import array\n', 'nylib/ue/x.py')
        self.assertTrue(any('numpy' in f for f in findings))

    def test_flags_forbidden_identifier(self):
        findings = check('import ctypes\nctypes.string_at(1, 2)\n', 'nylib/ue/x.py')
        self.assertTrue(any('string_at' in f for f in findings))

    def test_flags_forbidden_identifier_as_name(self):
        findings = check('from ctypes import string_at\nstring_at(1, 2)\n', 'nylib/ue/x.py')
        self.assertTrue(any('string_at' in f for f in findings))

    def test_flags_forbidden_identifier_bare_name_use(self):
        # no import involved, isolating the bare-Name-usage branch from the import-alias branch
        findings = check('string_at = None\nstring_at(1, 2)\n', 'nylib/ue/x.py')
        self.assertTrue(any('string_at' in f for f in findings))

    def test_flags_forbidden_identifier_aliased_import(self):
        findings = check('from ctypes import string_at as sa\nsa(1, 2)\n', 'nylib/ue/x.py')
        self.assertTrue(any('string_at' in f for f in findings))

    def test_flags_wstring_at(self):
        findings = check('import ctypes\nctypes.wstring_at(1, 2)\n', 'nylib/ue/x.py')
        self.assertTrue(any('wstring_at' in f for f in findings))

    def test_flags_windll(self):
        findings = check('import ctypes\nctypes.windll.kernel32.ReadProcessMemory(0)\n', 'nylib/ue/x.py')
        self.assertTrue(any('windll' in f for f in findings))

    def test_flags_memmove(self):
        findings = check('import ctypes\nctypes.memmove(1, 2, 3)\n', 'nylib/ue/x.py')
        self.assertTrue(any('memmove' in f for f in findings))

    def test_flags_process_call(self):
        findings = check('p = Process(1)\n', 'nylib/ue/pipeline.py')
        self.assertTrue(any('Process' in f for f in findings))

    def test_flags_process_from_id(self):
        findings = check('Process.from_id(1)\n', 'nylib/ue/pipeline.py')
        self.assertTrue(any('Process' in f for f in findings))

    def test_flags_process_call_via_any_attribute_base(self):
        findings = check('from . import memory\nmemory.Process(1)\n', 'nylib/ue/pipeline.py')
        self.assertTrue(any('Process' in f for f in findings))

    def test_flags_process_alias_from_any_module(self):
        findings = check('from .memory import Process as P\nP(1)\n', 'nylib/ue/pipeline.py')
        self.assertTrue(any('Process' in f for f in findings))

    def test_flags_process_current_read_u64(self):
        findings = check('Process.current.read_u64(0)\n', 'nylib/ue/pipeline.py')
        self.assertTrue(any('Process.current' in f for f in findings))

    def test_flags_process_current_via_alias(self):
        findings = check('from nylib.process import Process as P\nP.current.read(1, 4)\n', 'nylib/ue/runtime/objects.py')
        self.assertTrue(any('Process.current' in f for f in findings))

    def test_flags_process_current_call_outside_calls_py(self):
        findings = check('Process.current.call(1)\n', 'nylib/ue/runtime/session.py')
        self.assertTrue(any('Process.current' in f for f in findings))

    def test_flags_process_current_as_argument(self):
        findings = check('f(Process.current)\n', 'nylib/ue/pipeline.py')
        self.assertTrue(any('Process.current' in f for f in findings))

    def test_flags_process_current_read_in_memory_py(self):
        findings = check('Process.current.read(1, 4)\n', 'nylib/ue/memory.py')
        self.assertTrue(any('Process.current' in f for f in findings))

    def test_flags_process_current_is_comparison_outside_memory_py(self):
        findings = check('if p is Process.current: pass\n', 'nylib/ue/pipeline.py')
        self.assertTrue(any('Process.current' in f for f in findings))

    def test_allows_process_current_call_in_calls_py(self):
        findings = check('Process.current.call(pe, a, b, c)\n', 'nylib/ue/calls.py')
        self.assertEqual(findings, [])

    def test_allows_process_current_process_id(self):
        findings = check('x = Process.current.process_id\n', 'nylib/ue/pipeline.py')
        self.assertEqual(findings, [])

    def test_allows_process_current_is_comparison_in_memory_py(self):
        findings = check('if process is Process.current: pass\n', 'nylib/ue/memory.py')
        self.assertEqual(findings, [])

    def test_allows_process_constructor_in_memory_py(self):
        findings = check('p = Process(pid, da=0x410)\n', 'nylib/ue/memory.py')
        self.assertEqual(findings, [])

    def test_g1_flags_address_keyword_outside_accessor_py(self):
        findings = check('t = TArray(_address_=p)\n', 'nylib/ue/engine/unreal.py')
        self.assertTrue(any('_address_' in f for f in findings))

    def test_g1_flags_accessor_keyword_outside_accessor_py(self):
        findings = check('t = FString(_accessor_=acc)\n', 'nylib/ue/runtime/objects.py')
        self.assertTrue(any('_accessor_' in f for f in findings))

    def test_g1_allows_ctype_binding_in_accessor_py(self):
        findings = check('def view(cls, address, accessor):\n    return cls(_address_=address, _accessor_=accessor)\n',
                         'nylib/ue/engine/accessor.py')
        self.assertEqual(findings, [])


class HygieneCliTests(unittest.TestCase):
    def _run(self, args):
        return subprocess.run(
            [sys.executable, '-m', 'nylib.ue.tests.test_hygiene', '--files', *args],
            cwd=_REPO_ROOT, capture_output=True, text=True,
        )

    def test_cli_flags_third_party_import(self):
        with tempfile.NamedTemporaryFile('w', suffix='.py', delete=False) as f:
            f.write('import numpy\n')
            path = f.name
        try:
            result = self._run([path])
            self.assertEqual(result.returncode, 1)
            self.assertIn('numpy', result.stdout)
        finally:
            pathlib.Path(path).unlink()

    def test_cli_passes_clean_file(self):
        with tempfile.NamedTemporaryFile('w', suffix='.py', delete=False) as f:
            f.write('import os\n')
            path = f.name
        try:
            result = self._run([path])
            self.assertEqual(result.returncode, 0)
        finally:
            pathlib.Path(path).unlink()

    def test_cli_bom_file_is_read_correctly(self):
        with tempfile.NamedTemporaryFile('wb', suffix='.py', delete=False) as f:
            f.write(b'\xef\xbb\xbfimport os\n')
            path = f.name
        try:
            result = self._run([path])
            self.assertEqual(result.returncode, 0)
        finally:
            pathlib.Path(path).unlink()

    def test_cli_syntax_error_becomes_finding(self):
        with tempfile.NamedTemporaryFile('w', suffix='.py', delete=False) as f:
            f.write('def f(:\n')
            path = f.name
        try:
            result = self._run([path])
            self.assertEqual(result.returncode, 1)
            self.assertIn('syntax error', result.stdout)
            self.assertNotIn('Traceback', result.stderr)
        finally:
            pathlib.Path(path).unlink()

    def test_cli_no_path_is_error(self):
        result = self._run([])
        self.assertEqual(result.returncode, 2)
        self.assertIn('no paths given', result.stderr)

    def test_cli_missing_path_is_error(self):
        result = self._run(['nylib/ue/does_not_exist.py'])
        self.assertEqual(result.returncode, 2)
        self.assertIn('not an existing .py file', result.stderr)

    def test_cli_non_py_path_is_error(self):
        with tempfile.NamedTemporaryFile('w', suffix='.txt', delete=False) as f:
            f.write('hello\n')
            path = f.name
        try:
            result = self._run([path])
            self.assertEqual(result.returncode, 2)
            self.assertIn('not an existing .py file', result.stderr)
        finally:
            pathlib.Path(path).unlink()


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == '--files':
        sys.exit(_run_files_mode(sys.argv[2:]))
    unittest.main()
