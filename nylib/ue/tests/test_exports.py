"""Golden-byte tests for nylib.ue.exports: GObjects dumps, idmap V1, the usmap stub, and
parse-back through tests.oracle's Dumper-7 parsers.

The golden snapshot is hand-built (flat: every non-CDO object is a direct child of one package,
so `ObjectTable.full_name`/`.path` reduce to a formula computed here by hand, independent of
calling those methods) so expected bytes are literals, not round-trips through the code under test.
"""
import os
import struct
import tempfile
import unittest

from nylib.ue import model
from nylib.ue.flags import EFunctionFlags, EObjectFlags, EPropertyFlags
from nylib.ue.snapshot import Snapshot, write_snapshot
from nylib.ue.exports import DEFAULT_EXPORTS, EXPORT_SPECS, export_path, gobjects, idmap, run_export, usmap
from nylib.ue.tests import oracle

PKG = '/Game/MyPkg'


def _obj(index, address, flags=0, class_index=-1, outer_index=0, name='N', vtable_rva=None):
    return model.ObjectRecord(index=index, address=address, flags=flags, class_index=class_index,
                               outer_index=outer_index, name=name, vtable_rva=vtable_rva)


def _fn(path, name, flags=0, exec_rva=None, params=()):
    return model.FunctionRecord(path=path, name=name, package=PKG, flags=flags, params_size=0,
                                 params=list(params), exec_rva=exec_rva)


def _cls(letter, super_=None, functions=None):
    return model.ClassRecord(path=f'{PKG}.{letter}', name=letter, cpp_name=f'U{letter}', package=PKG,
                              super=super_, size=8, min_alignment=8, properties=[],
                              cast_flags=0, cdo=f'{PKG}.Default__{letter}', interfaces=[],
                              functions=functions or {})


class _Golden:
    """One shared hand-built world: 4 classes (A, B<A, C, D), their CDOs, a struct, an enum, a
    package-level delegate and a non-ASCII-named object; 13 objects total, index order below.
    """

    def __init__(self):
        self.objects = [
            _obj(0, 0x1000, outer_index=-1, name=PKG),
            _obj(1, 0x2000, name='A'),
            _obj(2, 0x2100, name='B'),
            _obj(3, 0x2200, name='C'),
            _obj(4, 0x2300, name='D'),
            _obj(5, 0x2400, name='S'),
            _obj(6, 0x2500, name='Enum1'),
            _obj(7, 0x2600, name='Dlgt'),
            _obj(8, 0x2700, name='テスト'),  # Japanese: 'test'
            _obj(9, 0x3000, flags=EObjectFlags.ClassDefaultObject, class_index=1, vtable_rva=0x2000, name='Default__A'),
            _obj(10, 0x3100, flags=EObjectFlags.ClassDefaultObject, class_index=2, vtable_rva=0x2000, name='Default__B'),
            _obj(11, 0x3200, flags=EObjectFlags.ClassDefaultObject, class_index=3, vtable_rva=0x4000, name='Default__C'),
            _obj(12, 0x3300, flags=EObjectFlags.ClassDefaultObject, class_index=4, vtable_rva=0x4000, name='Default__D'),
        ]
        self.table = model.ObjectTable(self.objects)

        fn_f = _fn(f'{PKG}.A:F', 'F', flags=EFunctionFlags.Native, exec_rva=0x1000)          # Native, kept
        fn_g = _fn(f'{PKG}.A:G', 'G', flags=0, exec_rva=0x2222)                              # not Native: skipped
        fn_h = _fn(f'{PKG}.A:H', 'H', flags=EFunctionFlags.Native, exec_rva=None)             # no exec thunk: skipped
        fn_j = _fn(f'{PKG}.B:J', 'J', flags=EFunctionFlags.Native, exec_rva=0x1000)           # dup RVA: skipped

        cls_a = _cls('A', functions={'F': fn_f, 'G': fn_g, 'H': fn_h})
        cls_b = _cls('B', super_=f'{PKG}.A', functions={'J': fn_j})
        cls_c = _cls('C')
        cls_d = _cls('D')

        prop_struct = model.PropertyRecord(
            name='Field1', offset=0x10, size=8, array_dim=1, flags=0,
            type=model.PropType(prop='StructProperty', kind='StructProperty', struct='SomeStruct'))
        prop_bool = model.PropertyRecord(
            name='Flag1', offset=0x18, size=1, array_dim=1, flags=0,
            type=model.PropType(prop='BoolProperty', kind='BoolProperty', field_size=1, byte_offset=0x18,
                                 byte_mask=1, field_mask=1))
        struct_s = model.StructRecord(path=f'{PKG}.S', name='S', cpp_name='FS', package=PKG, super=None,
                                       size=0x20, min_alignment=8, properties=[prop_struct, prop_bool])

        enum1 = model.EnumRecord(path=f'{PKG}.Enum1', name='Enum1', cpp_name='EEnum1', package=PKG,
                                  underlying_size=1, underlying_size_from='reflection', underlying_signed=False,
                                  values=[('A', 0), ('B', 1)])

        param_parm = model.PropertyRecord(
            name='ParamA', offset=0, size=4, array_dim=1, flags=EPropertyFlags.Parm,
            type=model.PropType(prop='IntProperty', kind='IntProperty'))
        param_local = model.PropertyRecord(
            name='LocalB', offset=4, size=4, array_dim=1, flags=0,
            type=model.PropType(prop='FloatProperty', kind='FloatProperty'))
        delegate = _fn(f'{PKG}.Dlgt', 'Dlgt', params=[param_parm, param_local])

        self.types_list = [cls_a, cls_b, cls_c, cls_d, struct_s, enum1, delegate]
        self.fields_list = [(5, [0x9000]), (7, [0x9100, 0x9200])]  # S: 1 addr / 2 props (mismatch); Dlgt: 2/2

        self.meta_main = {'target': {'stem': 'TestStem'}, 'globals': {'GObjects': {'num_elements': 999}}}
        self.meta_no_stem = {'globals': {'GObjects': {'num_elements': 999}}}
        self.meta_fallback_nonint = {'target': {'stem': 'TestStem'}, 'globals': {'GObjects': {'num_elements': 'x'}}}
        self.meta_fallback_missing = {'target': {'stem': 'TestStem'}}

        self.snapshot_main = Snapshot(self.meta_main, {}, self.table, self.types_list, fields=self.fields_list)
        self.snapshot_no_stem = Snapshot(self.meta_no_stem, {}, self.table, self.types_list, fields=self.fields_list)
        self.snapshot_fallback_nonint = Snapshot(self.meta_fallback_nonint, {}, self.table, self.types_list,
                                                  fields=self.fields_list)
        self.snapshot_fallback_missing = Snapshot(self.meta_fallback_missing, {}, self.table, self.types_list,
                                                   fields=self.fields_list)

        # Flat hierarchy (every object's outer is the package): full_name is
        # f'{cls_part} {short_name(package)}.{short_name(index)}' by the model.py formula, computed
        # here by hand rather than through ObjectTable.full_name.
        self.rows = [
            (0, 0x1000, 'None MyPkg'),
            (1, 0x2000, 'None MyPkg.A'),
            (2, 0x2100, 'None MyPkg.B'),
            (3, 0x2200, 'None MyPkg.C'),
            (4, 0x2300, 'None MyPkg.D'),
            (5, 0x2400, 'None MyPkg.S'),
            (6, 0x2500, 'None MyPkg.Enum1'),
            (7, 0x2600, 'None MyPkg.Dlgt'),
            (8, 0x2700, 'None MyPkg.テスト'),
            (9, 0x3000, 'A MyPkg.Default__A'),
            (10, 0x3100, 'B MyPkg.Default__B'),
            (11, 0x3200, 'C MyPkg.Default__C'),
            (12, 0x3300, 'D MyPkg.Default__D'),
        ]
        self.props_rows = {
            5: [(0x10, 0x9000, 'StructProperty', 'Field1')],
            7: [(0, 0x9100, 'IntProperty', 'ParamA'), (4, 0x9200, 'FloatProperty', 'LocalB')],
        }
        self.idmap = [(0x1000, '_ZN2UA5execFEv'), (0x2000, 'UA_VFT'), (0x4000, 'UC_VFT'), (0x4000, 'UD_VFT')]

    def row_text(self, index, address, name) -> str:
        return f'[{index:08X}] {{{address:#x}}} {name}\r\n'

    def prop_text(self, offset, address, prop, name) -> str:
        return f'[{offset:08X}] {{{address:#x}}}     {prop} {name}\r\n'

    def header(self, stem, count) -> str:
        stem_part = f'{stem}\r\n\r\n' if stem else ''
        return f'Object dump by nylib.ue (Dumper-7 format)\r\n\r\n{stem_part}Count: {count}\r\n\r\n\r\n'

    def dump_text(self, stem, count, with_properties) -> str:
        text = self.header(stem, count)
        for index, address, name in self.rows:
            text += self.row_text(index, address, name)
            if with_properties:
                for offset, addr, prop, pname in self.props_rows.get(index, []):
                    text += self.prop_text(offset, addr, prop, pname)
        return text

    def idmap_bytes(self) -> bytes:
        out = b''
        for rva, name in self.idmap:
            nb = name.encode('utf-8')
            out += struct.pack('<IH', rva, len(nb)) + nb
        return out


class GObjectsGoldenTests(unittest.TestCase):
    def setUp(self):
        self.g = _Golden()

    def test_header(self):
        with tempfile.TemporaryDirectory() as d:
            path = gobjects.write_objects(self.g.snapshot_main, d)
            with open(path, 'rb') as f:
                data = f.read()
            self.assertTrue(data.startswith(self.g.header('TestStem', 999).encode('utf-8')))

    def test_header_empty_stem_is_five_lines(self):
        with tempfile.TemporaryDirectory() as d:
            path = gobjects.write_objects(self.g.snapshot_no_stem, d)
            with open(path, 'rb') as f:
                data = f.read()
            self.assertTrue(data.startswith(self.g.header('', 999).encode('utf-8')))

    def test_header_count_falls_back_on_non_int(self):
        with tempfile.TemporaryDirectory() as d:
            path = gobjects.write_objects(self.g.snapshot_fallback_nonint, d)
            with open(path, 'rb') as f:
                data = f.read()
            self.assertTrue(data.startswith(self.g.header('TestStem', 13).encode('utf-8')))

    def test_header_count_falls_back_on_missing_globals(self):
        with tempfile.TemporaryDirectory() as d:
            path = gobjects.write_objects(self.g.snapshot_fallback_missing, d)
            with open(path, 'rb') as f:
                data = f.read()
            self.assertTrue(data.startswith(self.g.header('TestStem', 13).encode('utf-8')))

    def test_header_count_falls_back_on_bool(self):
        # bool is an int subtype (F1) but is explicitly excluded as a Count source.
        meta = {'target': {'stem': 'TestStem'}, 'globals': {'GObjects': {'num_elements': True}}}
        snap = Snapshot(meta, {}, self.g.table, self.g.types_list, fields=self.g.fields_list)
        with tempfile.TemporaryDirectory() as d:
            path = gobjects.write_objects(snap, d)
            with open(path, 'rb') as f:
                data = f.read()
            self.assertTrue(data.startswith(self.g.header('TestStem', 13).encode('utf-8')))

    def test_cyclic_object_row(self):
        objs = [
            model.ObjectRecord(index=0, address=0x100, flags=0, class_index=-1, outer_index=1, name='X'),
            model.ObjectRecord(index=1, address=0x200, flags=0, class_index=-1, outer_index=0, name='Y'),
        ]
        snap = Snapshot({}, {}, model.ObjectTable(objs), [])
        with tempfile.TemporaryDirectory() as d:
            path = gobjects.write_objects(snap, d)
            with open(path, 'rb') as f:
                data = f.read()
            self.assertIn(b'[00000000] {0x100} <cyclic>\r\n', data)
            self.assertIn(b'[00000001] {0x200} <cyclic>\r\n', data)

    def test_rows(self):
        with tempfile.TemporaryDirectory() as d:
            path = gobjects.write_objects(self.g.snapshot_main, d)
            self.assertEqual(os.path.basename(path), 'GObjects-Dump.txt')
            with open(path, 'rb') as f:
                data = f.read()
            self.assertEqual(data, self.g.dump_text('TestStem', 999, with_properties=False).encode('utf-8'))
            self.assertNotIn(b'\n', data.replace(b'\r\n', b''))  # no bare LF anywhere
            self.assertIn('テスト'.encode('utf-8'), data)
            with open(path, 'rb') as f:
                self.assertFalse(f.read(3) == b'\xef\xbb\xbf')  # no BOM

    def test_props(self):
        with tempfile.TemporaryDirectory() as d:
            path = gobjects.write_objects_with_properties(self.g.snapshot_main, d)
            self.assertEqual(os.path.basename(path), 'GObjects-Dump-WithProperties.txt')
            with open(path, 'rb') as f:
                data = f.read()
            self.assertEqual(data, self.g.dump_text('TestStem', 999, with_properties=True).encode('utf-8'))

    def test_specs(self):
        self.assertEqual(DEFAULT_EXPORTS, ('idmap', 'gobjects', 'gobjects-props'))
        self.assertEqual(set(EXPORT_SPECS), {'gobjects', 'gobjects-props', 'idmap', 'usmap'})
        self.assertEqual(export_path('idmap', self.g.snapshot_main), 'IDAMappings/TestStem.idmap')
        self.assertEqual(export_path('idmap', self.g.snapshot_no_stem), 'IDAMappings/unknown.idmap')
        self.assertEqual(export_path('gobjects', self.g.snapshot_main), 'GObjects-Dump.txt')
        self.assertEqual(export_path('gobjects-props', self.g.snapshot_main), 'GObjects-Dump-WithProperties.txt')
        self.assertEqual(export_path('usmap', self.g.snapshot_main), 'Mappings/TestStem.usmap')
        with self.assertRaises(ValueError):
            export_path('bogus', self.g.snapshot_main)
        with self.assertRaises(TypeError):
            export_path(3, self.g.snapshot_main)
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(ValueError):
                run_export('bogus', self.g.snapshot_main, d)
            with self.assertRaises(TypeError):
                run_export(3, self.g.snapshot_main, d)
            with self.assertRaises(TypeError):
                run_export('gobjects', self.g.snapshot_main, 123)
            # usmap's own writer raises before checking out_dir (S2): run_export must catch this itself.
            with self.assertRaises(TypeError):
                run_export('usmap', self.g.snapshot_main, 123)

    def test_run_export_dispatches(self):
        with tempfile.TemporaryDirectory() as d:
            path = run_export('gobjects', self.g.snapshot_main, d)
            self.assertTrue(os.path.isabs(path))
            self.assertTrue(os.path.isfile(path))


class IdmapGoldenTests(unittest.TestCase):
    def setUp(self):
        self.g = _Golden()

    def test_branches(self):
        with tempfile.TemporaryDirectory() as d:
            path = idmap.write(self.g.snapshot_main, d)
            self.assertEqual(path, os.path.join(os.path.abspath(d), 'IDAMappings', 'TestStem.idmap'))
            with open(path, 'rb') as f:
                data = f.read()
            self.assertEqual(data, self.g.idmap_bytes())

    def test_empty_stem_file_name(self):
        with tempfile.TemporaryDirectory() as d:
            path = idmap.write(self.g.snapshot_no_stem, d)
            self.assertEqual(os.path.basename(path), 'unknown.idmap')

    def test_record_bytes(self):
        with tempfile.TemporaryDirectory() as d:
            path = idmap.write(self.g.snapshot_main, d)
            with open(path, 'rb') as f:
                data = f.read()
            pos = 0
            for rva, name in self.g.idmap:
                nb = name.encode('utf-8')
                rva_read, len_read = struct.unpack_from('<IH', data, pos)
                pos += 6
                self.assertEqual(rva_read, rva)
                self.assertEqual(len_read, len(nb))
                self.assertEqual(data[pos:pos + len_read], nb)
                pos += len_read
            self.assertEqual(pos, len(data))  # no header, no ReadMe.txt, nothing trailing


class UsmapTests(unittest.TestCase):
    def test_not_implemented(self):
        g = _Golden()
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(NotImplementedError) as cm:
                usmap.write(g.snapshot_main, d)
            self.assertEqual(str(cm.exception), 'the usmap writer is not implemented yet')
            self.assertEqual(os.listdir(d), [])


class ParseBackTests(unittest.TestCase):
    def setUp(self):
        self.g = _Golden()

    def test_strict_parsers_accept_ours_plain(self):
        with tempfile.TemporaryDirectory() as d:
            path = gobjects.write_objects(self.g.snapshot_main, d)
            with open(path, 'rb') as f:
                data = f.read()
            parsed = oracle.parse_gobjects_dump(data, with_properties=False)
            self.assertEqual(parsed.line1, 'Object dump by nylib.ue (Dumper-7 format)')
            self.assertEqual(parsed.stem, 'TestStem')
            self.assertEqual(parsed.count, 999)
            self.assertEqual(parsed.rows, self.g.rows)
            self.assertEqual(parsed.props, {})

    def test_strict_parsers_accept_ours_with_properties(self):
        with tempfile.TemporaryDirectory() as d:
            path = gobjects.write_objects_with_properties(self.g.snapshot_main, d)
            with open(path, 'rb') as f:
                data = f.read()
            parsed = oracle.parse_gobjects_dump(data, with_properties=True)
            self.assertEqual(parsed.rows, self.g.rows)
            self.assertEqual(parsed.props, self.g.props_rows)

    def test_strict_parsers_accept_ours_five_line_header(self):
        with tempfile.TemporaryDirectory() as d:
            path = gobjects.write_objects(self.g.snapshot_no_stem, d)
            with open(path, 'rb') as f:
                data = f.read()
            parsed = oracle.parse_gobjects_dump(data, with_properties=False)
            self.assertEqual(parsed.stem, '')
            self.assertEqual(parsed.count, 999)

    def test_strict_parsers_accept_our_idmap(self):
        with tempfile.TemporaryDirectory() as d:
            path = idmap.write(self.g.snapshot_main, d)
            with open(path, 'rb') as f:
                data = f.read()
            parsed = oracle.parse_idmap(data)
            self.assertEqual(parsed, self.g.idmap)


class LoadedSnapshotExportTests(unittest.TestCase):
    """S2/P19: exporters run the same way against a loaded (and a still-.partial) snapshot."""

    def setUp(self):
        self.g = _Golden()

    def _write_folder(self, root) -> str:
        folder = os.path.join(root, 'snap')
        result = write_snapshot(folder, self.g.meta_main, {}, list(self.g.table), self.g.types_list,
                                 self.g.fields_list)
        return result['partial']

    def test_export_over_a_loaded_snapshot(self):
        with tempfile.TemporaryDirectory() as root:
            partial = self._write_folder(root)
            final = partial[:-len('.partial')]
            os.rename(partial, final)
            loaded = Snapshot.load(final)
            try:
                out_dir = os.path.join(root, 'out')
                dump_path = gobjects.write_objects(loaded, out_dir)
                idmap_path = idmap.write(loaded, out_dir)
                with open(dump_path, 'rb') as f:
                    self.assertEqual(f.read(), self.g.dump_text('TestStem', 999, with_properties=False).encode('utf-8'))
                with open(idmap_path, 'rb') as f:
                    self.assertEqual(f.read(), self.g.idmap_bytes())
            finally:
                loaded.close()

    def test_export_over_a_still_partial_snapshot(self):
        with tempfile.TemporaryDirectory() as root:
            partial = self._write_folder(root)  # never renamed: stays '<folder>.partial'
            loaded = Snapshot.load(partial, _partial=True)
            try:
                out_dir = os.path.join(root, 'out')
                dump_path = gobjects.write_objects_with_properties(loaded, out_dir)
                with open(dump_path, 'rb') as f:
                    self.assertEqual(f.read(), self.g.dump_text('TestStem', 999, with_properties=True).encode('utf-8'))
            finally:
                loaded.close()


if __name__ == '__main__':
    unittest.main()
