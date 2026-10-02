"""Tests for scripts/ida/ue_dumper_import.py's planner in plain CPython: the golden idmap equivalence, the build
check, stdlib-only and copied-naming guards, and env-gated comparisons on real snapshots.
"""
import ast
import collections
import hashlib
import importlib.util
import os
import pathlib
import re
import sys
import tempfile
import unittest

from nylib.ue import flags, model, names
from nylib.ue.exports import idmap
from nylib.ue.flags import EObjectFlags
from nylib.ue.snapshot import Snapshot, write_snapshot
from nylib.ue.tests import oracle, real
from nylib.ue.tests.test_exports import PKG, _Golden, _cls, _obj

_REPO = pathlib.Path(__file__).resolve().parents[3]
_SCRIPT = _REPO / 'scripts' / 'ida' / 'ue_dumper_import.py'
_R6_TYPES = frozenset((
    'UObject', 'UField', 'UStruct', 'UClass', 'UFunction', 'UEnum', 'FName', 'FField', 'FFieldVariant', 'FProperty',
    'FFieldClass', 'FByteProperty', 'FBoolProperty', 'FObjectPropertyBase', 'FClassProperty', 'FStructProperty',
    'FArrayProperty', 'FDelegateProperty', 'FMapProperty', 'FSetProperty', 'FEnumProperty', 'FFieldPathProperty',
    'FOptionalProperty', 'TUObjectArray', 'FUObjectItem', 'FWeakObjectPtr', 'FUniqueObjectGuid', 'FScriptInterface',
    'FScriptDelegate', 'FFieldPath',
))
_ORACLE_GLOBALS = {'GObjects': 'OFFSET_GOBJECTS', 'GNames': 'OFFSET_GNAMES', 'GWorld': 'OFFSET_GWORLD',
                   'ProcessEvent': 'OFFSET_PROCESSEVENT', 'AppendString': 'OFFSET_APPENDSTRING'}


def _ascii_ident(kind: str, name: str) -> str:
    """Stand-in for IDA 9.3's `validate_name`: every non-ASCII code point becomes `_`."""
    return re.sub(r'[^\x00-\x7f]', '_', name)


def _type_ident(name: str) -> str:
    """R3's IDA type name of a spelled specialisation, under `_ascii_ident`."""
    if (v := _ascii_ident('type', name)) == name:
        return name
    return _ascii_ident('type', name.replace('<', '_').replace('>', '').replace(', ', '_').replace('*', 'Ptr'))


def _member_type_error(p, spec, planned: dict, widths: dict, udts: dict) -> str | None:
    """Why the planned member `spec` of property `p` is not the type R4 gives it, or None (unchecked kinds pass)."""
    t = p.type
    named = lambda path, prefix, default: default if path is None else planned.get(path) or prefix + names.make_name_valid(
        re.split('[.:]', path)[-1])
    want = None
    if t.kind == 'ObjectProperty':
        want = ('ptr', ('named', named(t.cls, 'U', 'UObject')))
    elif t.kind == 'ClassProperty':
        want = ('ptr', ('named', 'UClass'))
    elif t.kind == 'StructProperty':
        want = ('named', planned.get(t.struct, f'<no record {t.struct}>'))
    elif t.kind in ('ByteProperty', 'EnumProperty') and t.enum is not None and widths.get(t.enum) == p.size:
        want = ('named', planned[t.enum])
    elif t.kind == 'InterfaceProperty':
        base = _type_ident(f"TScriptInterface<{named(t.cls, 'I', 'IInterface')}>")
        inner = spec[1] if spec[0] == 'array' else spec
        u = udts.get(inner[1]) if inner[0] == 'named' else None
        if u is None or not (inner[1] == base or inner[1].startswith(base + '__')) or u['size'] != p.size or (
                p.size == 0x10 and [m[0] for m in u['members']] != ['ObjectPointer', 'InterfacePointer']):
            return f'{spec!r} is not the {p.size:#x}-byte {base}'
        return None
    if want is None:
        return None
    if p.array_dim > 1:
        want = ('array', want, p.array_dim)
    return None if tuple(spec) == want else f'{spec!r} != {want!r}'


def _load_importer():
    if not (_REPO / 'scripts').is_dir():
        raise unittest.SkipTest('no scripts/ folder (installed nylib): the importer is not shipped')
    if not _SCRIPT.is_file():
        raise AssertionError(f'{_SCRIPT} is missing')
    spec = importlib.util.spec_from_file_location('ue_dumper_import', _SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def setUpModule():
    global uei
    uei = _load_importer()


def _write(root: str, objects, types) -> str:
    partial = write_snapshot(os.path.join(root, 'snap'), {}, {}, list(objects), list(types), [])['partial']
    folder = partial[:-len('.partial')]
    os.rename(partial, folder)
    return folder


def _int(name: str, offset: int, size: int = 4, flags_: int = 0):
    kind = {1: 'Int8Property', 4: 'IntProperty'}[size]
    return model.PropertyRecord(name=name, offset=offset, size=size, array_dim=1, flags=flags_,
                                type=model.PropType(prop=kind, kind=kind))


def _write_golden(root: str) -> str:
    g = _Golden()
    partial = write_snapshot(os.path.join(root, 'snap'), g.meta_main, {}, list(g.table), g.types_list, g.fields_list)['partial']
    final = partial[:-len('.partial')]
    os.rename(partial, final)
    return final


class IdmapEquivalenceTests(unittest.TestCase):
    def test_golden(self):
        with tempfile.TemporaryDirectory() as root:
            folder = _write_golden(root)
            with uei.load_snapshot(folder) as view:
                records = uei.name_records(view)
            self.assertEqual(records, [(0x1000, '_ZN2UA5execFEv'), (0x2000, 'UA_VFT'), (0x4000, 'UC_VFT'), (0x4000, 'UD_VFT')])
            with Snapshot.load(folder) as snap:
                ours = oracle.parse_idmap(pathlib.Path(idmap.write(snap, os.path.join(root, 'out'))))
            self.assertEqual(records, ours)


class TypeLookupTests(unittest.TestCase):
    def test_colon_in_function_name(self):
        names_ = ('Task: Update All Attribute', 'CSW::SetBrushAtKeyFrame')
        fns = {n: model.FunctionRecord(path=f'/G/BP.BP_C:{n}', name=n, package='/G/BP', flags=0, params_size=n.count(':'),
                                       params=[], exec_rva=None) for n in names_}
        cls = model.ClassRecord(path='/G/BP.BP_C', name='BP_C', cpp_name='UBP_C', package='/G/BP', super=None, size=8,
                                 min_alignment=8, properties=[], functions=fns)
        with tempfile.TemporaryDirectory() as root:
            partial = write_snapshot(os.path.join(root, 'snap'), {}, {}, [], [cls], [])['partial']
            folder = partial[:-len('.partial')]
            os.rename(partial, folder)
            with uei.load_snapshot(folder) as view:
                for n in names_:
                    self.assertEqual(view.type(f'/G/BP.BP_C:{n}')['params_size'], n.count(':'), n)
                self.assertIsNone(view.type('/G/BP.BP_C:Task: missing'))


class TypePlanTests(unittest.TestCase):
    def _types(self, records, ident=None) -> dict:
        with tempfile.TemporaryDirectory() as root, uei.load_snapshot(_write(root, [], records)) as view:
            return uei.plan(view, core_types=False, ident=ident or uei._plain_ident)['types']

    def test_member_in_super_tail_padding_is_kept(self):
        base = model.StructRecord(path='/S/P.Base', name='Base', cpp_name='FBase', package='/S/P', super=None, size=0x10,
                                  min_alignment=4, properties=[_int('a', 0), _int('b', 4), _int('c', 8, 1)])
        for off, kept, base_size in ((0xC, True, 0xC), (0x8, False, 0x9)):
            child = model.StructRecord(path='/S/P.Child', name='Child', cpp_name='FChild', package='/S/P', super='/S/P.Base',
                                       size=0x10, min_alignment=4, properties=[_int('x', off)])
            with self.subTest(offset=off):
                tp = self._types([base, child])
                u = next(u for u in tp['udts'] if u['name'] == 'FChild')
                self.assertEqual([m[:3] for m in u['members']], [('x', off * 8, 32)] if kept else [])
                self.assertEqual(tp['members_dropped'], 0 if kept else 1)
                self.assertEqual(u['base_size'], base_size)

    def test_ident_collisions_stay_unique(self):
        recs = [model.ClassRecord(path=f'/Game/P.{n}', name=n, cpp_name=n, package='/Game/P', super=None, size=8,
                                  min_alignment=8, properties=[]) for n in ('A测试_C', 'A试验_C')]
        tp = self._types(recs, ident=lambda kind, n: re.sub(r'[^\x00-\x7f]', '_', n))
        planned = {u['path']: u['name'] for u in tp['udts'] if u['path']}
        self.assertEqual(sorted(planned), sorted(r.path for r in recs))
        self.assertEqual(len(set(planned.values())), 2)
        self.assertEqual(tp['records'], 2)

    def test_struct_udt_size_rounds_up_to_min_alignment(self):
        s = model.StructRecord(path='/S/P.S', name='S', cpp_name='FS', package='/S/P', super=None, size=0x6B, min_alignment=8,
                               properties=[_int('a', 0)])
        c = model.ClassRecord(path='/S/P.C', name='C', cpp_name='UC', package='/S/P', super=None, size=0x6B, min_alignment=8,
                              properties=[])
        sizes = {u['name']: u['size'] for u in self._types([s, c])['udts']}
        self.assertEqual((sizes['FS'], sizes['UC']), (0x70, 0x6B))

    def test_interface_member_is_16_bytes(self):
        t = model.PropType(prop='InterfaceProperty', kind='InterfaceProperty', cls='/S/P.Iface')
        rec = model.StructRecord(path='/S/P.S', name='S', cpp_name='FS', package='/S/P', super=None, size=0x18, min_alignment=8,
                                 properties=[model.PropertyRecord(name='I', offset=8, size=0x10, array_dim=1, flags=0, type=t)])
        udts = {u['name']: u for u in self._types([rec])['udts']}
        member = udts['FS']['members'][0]
        self.assertEqual(member[:3], ('I', 64, 128))
        self.assertEqual([m[:3] for m in udts[member[3][1]]['members']], [('ObjectPointer', 0, 64), ('InterfacePointer', 64, 64)])


class RecordFormatGuardTests(unittest.TestCase):
    """The netnode record values and the type digest's encoding are formats stored in users' IDBs."""
    LONG = 'é\ud800' + 'x' * 1998
    PAIR, ONE = re.compile(r'[0-9a-f]{64}\n[0-9a-f]{64}'), re.compile(r'[0-9a-f]{64}')

    def test_type_key_and_h(self):
        h = hashlib.sha256('USmokeLeaf'.encode('utf-8')).digest()
        self.assertEqual(uei._type_key('USmokeLeaf'), int.from_bytes(h[:8], 'little') >> 1)
        self.assertEqual(uei._digest('a\ud800'), hashlib.sha256(b'a\xed\xa0\x80').hexdigest())

    def test_record_values_are_fixed_size(self):
        values = {'N': uei._name_record(self.LONG, self.LONG + 'y'), 'P': uei._hash_record(self.LONG),
                  'C': uei._hash_record(self.LONG + '\n' + self.LONG), 'T': uei._type_record(self.LONG, uei._type_digest(['other', self.LONG]))}
        for tag, v in values.items():
            with self.subTest(tag=tag):
                self.assertLessEqual(len(v.encode('ascii')), 129)
                self.assertRegex(v, (self.ONE if tag in 'PC' else self.PAIR).pattern + r'\Z')
        self.assertEqual(values['T'].split('\n')[0], hashlib.sha256(self.LONG.encode('utf-8', 'surrogatepass')).hexdigest())

    def test_type_digest_encoding_is_pinned(self):
        x = ['udt', 8, False, 0x41, 'nylib.ue: /S/P.é\ud800\x01', True, [['m', 0, 32, 'int', 0, 0, '', 'hex']]]
        pinned = b'["udt",8,false,65,"nylib.ue: /S/P.\\u00e9\\ud800\\u0001",true,[["m",0,32,"int",0,0,"","hex"]]]'
        self.assertEqual(uei._canonical(x), pinned)
        self.assertEqual(uei._type_digest(x), 'e4b9ea97cf3372300029a20ae25afbca4d03a53b16c2f22152426396bde1c18a')


class BuildCheckGuardTests(unittest.TestCase):
    SHA_A, SHA_B = 'a' * 64, 'B' * 64

    def meta(self, sha=None, ts=None, size=None):
        module = {k: v for k, v in (('pe_timestamp', ts), ('size', size)) if v is not None}
        return {'target': {'exe': 'Game.exe', 'exe_sha256': sha, 'module': module}}

    def test_sha256_and_pe_pass(self):
        self.assertEqual(uei.check_build(self.meta(self.SHA_A), {'sha256': self.SHA_A.upper()})[0], 'sha256')
        self.assertEqual(uei.check_build(self.meta(self.SHA_A, '0x10', '0x2000'),
                                         {'sha256': self.SHA_B, 'pe_timestamp': 0x10, 'size_of_image': 0x2000})[0], 'pe')

    def test_mismatch_never_passes(self):
        for ts, size in ((0x11, 0x2000), (0x10, 0x3000), (0x11, 0x3000)):
            verdict, text = uei.check_build(self.meta(self.SHA_A, '0x10', '0x2000'),
                                            {'sha256': self.SHA_B, 'pe_timestamp': ts, 'size_of_image': size})
            self.assertEqual(verdict, 'mismatch')
            self.assertIn('not built from', text)

    def test_nothing_comparable_is_unknown(self):
        cases = [
            ({}, {}), (None, None), ('x', ['y']), ({'target': 5}, {'sha256': 5}),
            (self.meta(self.SHA_A), {}),
            (self.meta(self.SHA_A), {'sha256': self.SHA_B}),
            (self.meta(None, '0x10', '0x2000'), {'pe_timestamp': 0x10}),
            (self.meta('not-hex', '0x10', None), {'sha256': 'not-hex', 'pe_timestamp': 0x10, 'size_of_image': 0x2000}),
            (self.meta(None, '16', '0x2000'), {'pe_timestamp': 16, 'size_of_image': 0x2000}),
            (self.meta(None, '0x10', '0x2000'), {'pe_timestamp': True, 'size_of_image': 0x2000}),
            (self.meta(None, '0x10', '0x2000'), {'pe_timestamp': -1, 'size_of_image': 0x2000}),
        ]
        for meta, idb in cases:
            with self.subTest(meta=meta, idb=idb):
                self.assertEqual(uei.check_build(meta, idb)[0], 'unknown')


class SelfContainedGuardTests(unittest.TestCase):
    def test_stdlib_and_ida_only(self):
        tree = ast.parse(_SCRIPT.read_text(encoding='utf-8'), filename=str(_SCRIPT))
        bad = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                mods = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom):
                mods = [('.' * node.level) + (node.module or '')]
            else:
                continue
            for mod in mods:
                top = mod.split('.', 1)[0]
                if mod.startswith('.') or not (top in sys.stdlib_module_names or top in ('idaapi', 'idc', 'idautils')
                                               or top.startswith('ida_')):
                    bad.append(f'line {node.lineno}: {mod}')
        self.assertEqual(bad, [])


class NameRuleGuardTests(unittest.TestCase):
    def test_tables_and_make_name_valid(self):
        self.assertEqual(uei._XID_RANGES, names._XID_RANGES)
        for start in range(0, 0x110000, 0x1000):
            chunk = ''.join(map(chr, range(start, start + 0x1000)))
            self.assertEqual(uei.make_name_valid('A' + chunk), names.make_name_valid('A' + chunk), hex(start))
        for s in ('', 'bool', 'NULL', '9Lives', 'テスト・名', 'a b'):
            self.assertEqual(uei.make_name_valid(s), names.make_name_valid(s))
        with self.assertRaises(TypeError):
            uei.make_name_valid(None)

    def test_function_flag_names(self):
        ours = sorted(uei._EFUNCTION_FLAGS, key=lambda x: x[1])
        want = sorted(((m.name, int(m.value)) for m in flags.EFunctionFlags if int(m.value) and int(m.value) & (int(m.value) - 1) == 0),
                      key=lambda x: x[1])
        self.assertEqual(ours, want)

    def test_mangle_exec(self):
        self.assertEqual(uei.mangle_exec('AActor', 'K2_DestroyActor'), '_ZN6AActor19execK2_DestroyActorEv')
        self.assertEqual(uei.mangle_exec('UテストA', 'F名'), names.mangle_exec('UテストA', 'F名'))
        with self.assertRaises(TypeError):
            uei.mangle_exec('AActor', b'x')


class CommentLengthGuardTests(unittest.TestCase):
    """Planned comments stay within IDA's comment byte cap."""

    def _exec_plan(self, functions: dict) -> dict:
        objects, classes = [_obj(0, 0x1000, outer_index=-1, name=PKG)], []
        for i, (letter, fns) in enumerate(functions.items(), 1):
            objects.append(_obj(i, 0x2000 + i, name=letter))
            classes.append(_cls(letter, functions={n: model.FunctionRecord(
                path=f'{PKG}.{letter}:{n}', name=n, package=PKG, flags=int(flags.EFunctionFlags.Native), params_size=0,
                params=params, exec_rva=0x1000) for n, params in fns.items()}))
        with tempfile.TemporaryDirectory() as root, uei.load_snapshot(_write(root, objects, classes)) as view:
            return uei.plan(view)

    def test_exec_comment_capped(self):
        params = [_int(f'SomeVeryLongParameterNameForTheCommentCap{i:03d}', 4 * i, flags_=0x80) for i in range(60)]
        _rva, text, _is_exec = self._exec_plan({'A': {'F': params}})['comments'][0]
        self.assertTrue(text.startswith(f'UFunction {PKG}.A:F\n'), text[:80])
        self.assertLessEqual(len(text.encode('utf-8')), uei._COMMENT_BYTE_LIMIT)

    def test_surrogate_path_with_duplicates(self):
        _rva, text, _is_exec = self._exec_plan({'A': {'F\ud800': []}, 'B': {'G': []}})['comments'][0]
        self.assertTrue(text.startswith(f'UFunction {PKG}.A:F�\n'), text[:80])
        self.assertIn('also: _ZN2UB5execGEv', text)

    def test_also_line_untruncated_when_it_fits(self):
        self.assertEqual(uei._also_line(['A_VFT', 'B_VFT'], 0), 'also: A_VFT, B_VFT')

    def test_also_line_truncates_whole_names_with_a_count(self):
        names_ = [f'UMaterialExpressionSomethingVeryLongName{i:03d}_VFT' for i in range(80)]
        line = uei._also_line(names_, 0)
        self.assertLessEqual(len(line.encode('utf-8')), uei._COMMENT_BYTE_LIMIT)
        self.assertRegex(line, r'\(\+\d+ more\)$')
        self.assertEqual(uei._also_line(names_, 0), line)  # deterministic

    def test_many_duplicate_vtable_names_stay_under_the_ida_cap(self):
        n = 80
        objects = [_obj(0, 0x1000, outer_index=-1, name=PKG)]
        classes = []
        for i in range(n):
            ci = 2 * i + 1
            letter = f'SomeVeryLongReflectedClassName{i:03d}'
            objects.append(_obj(ci, 0x2000 + i, name=letter))
            objects.append(_obj(ci + 1, 0x3000 + i, flags=EObjectFlags.ClassDefaultObject,
                                 class_index=ci, vtable_rva=0x4000, name=f'Default__{letter}'))
            classes.append(_cls(letter))
        table = model.ObjectTable(objects)
        with tempfile.TemporaryDirectory() as root:
            partial = write_snapshot(os.path.join(root, 'snap'), {}, {}, list(table), classes, [])['partial']
            folder = partial[:-len('.partial')]
            os.rename(partial, folder)
            with uei.load_snapshot(folder) as view:
                p = uei.plan(view)
        _rva, text, _is_exec = next(c for c in p['comments'] if c[0] == 0x4000)
        self.assertLessEqual(len(text.encode('utf-8')), uei._COMMENT_BYTE_LIMIT)

    def test_surrogate_in_vtable_also_name(self):
        objects, classes = [_obj(0, 0x1000, outer_index=-1, name=PKG)], []
        for i, letter in enumerate(('A', 'B\ud800'), 1):
            objects.append(_obj(2 * i - 1, 0x2000 + i, name=letter))
            objects.append(_obj(2 * i, 0x3000 + i, flags=EObjectFlags.ClassDefaultObject, class_index=2 * i - 1, vtable_rva=0x4000,
                                name=f'Default__{letter}'))
            classes.append(_cls(letter))
        with tempfile.TemporaryDirectory() as root, uei.load_snapshot(_write(root, list(model.ObjectTable(objects)), classes)) as view:
            p = uei.plan(view)
        _rva, text, _is_exec = next(c for c in p['comments'] if c[0] == 0x4000)
        self.assertEqual(text, 'also: UB�_VFT')


def _newest_snapshot(ours: str) -> str | None:
    found = []
    base_depth = ours.rstrip(os.sep).count(os.sep)
    for dirpath, dirnames, filenames in os.walk(ours):
        if dirpath.count(os.sep) - base_depth >= 3:
            dirnames[:] = []
        if 'meta.json' in filenames and not os.path.basename(dirpath).rstrip('. ').lower().endswith('.partial'):
            found.append(dirpath)
    return max(found, key=lambda d: os.path.getmtime(os.path.join(d, 'meta.json'))) if found else None


class RealSnapshotTests(unittest.TestCase):
    def test_sessions(self):
        if real.captures_root() is None:
            self.skipTest('NYLIB_UE_CAPTURES is not set')
        from nylib.ue.tests import port
        pairs = []
        for s in real.iter_sessions():
            ours = os.path.join(s.dir, 'ours')
            if os.path.isdir(ours) and (snap := _newest_snapshot(ours)) is not None:
                pairs.append((s, snap))
        missing = [t for t in real.required_targets() if t not in {s.target for s, _snap in pairs}]
        self.assertEqual(missing, [], 'required targets without a snapshot under <session>/ours/')
        for s, snap in pairs:
            with self.subTest(target=s.target, session=os.path.basename(s.dir)):
                self._check(s, snap, port.ACCEPTED)

    def _check_plan_audit(self, view, snapshot):
        """The plan vs. the snapshot `Snapshot.load` reads, independent of the importer's own reader; asserts once, on every violation."""
        full = uei.plan(view, ident=_ascii_ident)
        tp = full['types']
        bad = collections.defaultdict(list)
        for key in ('members_dropped', 'members_untyped'):
            if tp[key]:
                bad[f'types.{key} is not 0'].append(tp[key])
        udts_by_path = collections.defaultdict(list)
        for u in tp['udts']:
            if u['path'] is not None:
                udts_by_path[u['path']].append(u)
        enums_by_path = collections.defaultdict(list)
        for e in tp['enums']:
            if e['path'] is not None:
                enums_by_path[e['path']].append(e)
        class_struct = [r for r in snapshot.types() if isinstance(r, model.StructRecord)]
        enum_recs = [r for r in snapshot.types() if isinstance(r, model.EnumRecord)]
        for r in class_struct:
            if len(udts_by_path.get(r.path, ())) != 1:
                bad['class or struct record without exactly one planned UDT'].append(f'{r.path}: {len(udts_by_path.get(r.path, ()))}')
        if tp['records'] != len(class_struct):
            bad['types.records differs from the class and struct records'].append(f"{tp['records']} != {len(class_struct)}")
        for r in enum_recs:
            if len(enums_by_path.get(r.path, ())) != 1:
                bad['enum record without exactly one planned enum'].append(f'{r.path}: {len(enums_by_path.get(r.path, ()))}')
        planned = {path: us[0]['name'] for path, us in udts_by_path.items()} | {path: es[0]['name'] for path, es in enums_by_path.items()}
        widths = {path: es[0]['width'] for path, es in enums_by_path.items()}
        by_name = {u['name']: u for u in tp['udts']}
        for r in class_struct:
            us = udts_by_path.get(r.path)
            if not us:
                continue
            by_lo = {lo: (nbits, spec) for _n, lo, nbits, spec in us[0]['members']}
            for p in r.properties:
                where = f'{r.path}: {p.name} @0x{p.offset:x} size 0x{p.size:x}'
                bit = p.type.bit
                lo, want = (p.offset * 8 + bit, 1) if bit is not None and p.array_dim == 1 else (p.offset * 8, p.size * p.array_dim * 8)
                if (m := by_lo.get(lo)) is None:
                    bad['property not planned at its offset'].append(where)
                elif m[0] > want:
                    bad['member longer than its property'].append(f'{where}: {m[0]} bits')
                elif m[0] < want:
                    bad['member shorter than its property'].append(f'{where}: {m[0]} bits')
                elif (why := _member_type_error(p, m[1], planned, widths, by_name)) is not None:
                    bad['member type differs from R4'].append(f'{where}: {why}')
            if not isinstance(r, model.ClassRecord):
                align = max(r.min_alignment, 1)
                if us[0]['size'] != -(-r.size // align) * align:
                    bad['struct UDT size is not size rounded up to min_alignment'].append(f"{r.path}: 0x{us[0]['size']:x}")
        rec_by_cpp = collections.defaultdict(list)
        for r in class_struct:
            rec_by_cpp[r.cpp_name].append(r)
        for (t, m), (off, sz) in uei.core_members(view).items():
            u = by_name.get(t)
            if u is None:
                bad['core member with no planned type'].append(f'{t}.{m}')
            elif not any(mn == m and ml == off * 8 and mb == sz * 8 for mn, ml, mb, _s in u['members']):
                rr = [r for r in rec_by_cpp.get(t, ()) if r.package == '/Script/CoreUObject']
                if not (rr and any(pp.offset == off for pp in rr[0].properties)):
                    bad['core member not planned and no reflected property overrides it'].append(f'{t}.{m} @0x{off:x}')
        for rva, ctext, _is_exec in full['comments']:
            if len(ctext.encode('utf-8')) > uei._COMMENT_BYTE_LIMIT:
                bad['comment longer than _COMMENT_BYTE_LIMIT'].append(f'0x{rva:x}')
        if bad:
            self.fail('plan audit: ' + '; '.join(f'{k}: {len(v)}' for k, v in bad.items()) + '\n'
                      + '\n'.join(f'  {k}, first 5: {v[:5]}' for k, v in bad.items()))

    def _check(self, s, snap: str, accepted: dict):
        oracle_dir = pathlib.Path(s.dir, 'oracle', s.data['oracle']['folder'])
        skip = {item for (target, check, item) in accepted if target == s.target and check == 'offsets'}
        with uei.load_snapshot(snap) as view, Snapshot.load(snap) as snapshot, tempfile.TemporaryDirectory() as tmp:
            records = uei.name_records(view)
            self.assertEqual(records, oracle.parse_idmap(pathlib.Path(idmap.write(snapshot, tmp))))
            theirs = [rel for rel in s.data['oracle']['files'] if rel.startswith('IDAMappings/') and rel.endswith('.idmap')]
            drift = oracle.compare_idmap(records, oracle.parse_idmap(oracle_dir / theirs[0]))
            self.assertTrue(drift.ok, f'{drift.reason}: {drift.samples}')
            self._check_plan_audit(view, snapshot)
            text = lambda rel: (oracle_dir / rel).read_text(encoding='utf-8')
            want = {**oracle.parse_predefined_members(text('CppSDK/SDK/Basic.hpp')),
                    **oracle.parse_predefined_members(text('CppSDK/SDK/CoreUObject_classes.hpp'))}
            keep = lambda d: {k: v for k, v in d.items() if k[0] in _R6_TYPES and f'{k[0]}.{k[1]}' not in skip}
            self.assertEqual(keep(uei.core_members(view)), keep(want))
            info = oracle.parse_offsets_info(oracle_dir / 'Dumpspace' / 'OffsetsInfo.json')
            ours = uei.global_records(view)
            meta_globals = view.meta.get('globals') or {}
            for g, key in _ORACLE_GLOBALS.items():
                if g == 'AppendString' and (meta_globals.get('AppendString') or {}).get('kind') == 'ToString':
                    key = 'OFFSET_TOSTRING'
                if f'OffsetsInfo.{key}' in skip or not info.get(key):
                    continue
                self.assertEqual(ours.get(g), info[key], f'{g} vs OffsetsInfo {key}')


if __name__ == '__main__':
    unittest.main()
