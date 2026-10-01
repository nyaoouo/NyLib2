import json
import os
import shutil
import tempfile
import tracemalloc
import unittest
import unittest.mock

from nylib.ue import errors, model, snapshot


def _obj(index, address=0x10, flags=0, class_index=-1, outer_index=-1, name='N', vtable_rva=None):
    return model.ObjectRecord(index=index, address=address, flags=flags, class_index=class_index,
                               outer_index=outer_index, name=name, vtable_rva=vtable_rva)


def _write_minimal(folder, objects=(), types=(), fields=()):
    return snapshot.write_snapshot(folder, {}, {}, list(objects), list(types), list(fields))


def _build_world():
    """One package, one class (with a nested function), one struct, one enum, one instance object."""
    objects = [
        _obj(0, address=0x1000, flags=1, name='/Game/Tst'),
        _obj(1, address=0x2000, flags=0x10, outer_index=0, name='MyClass'),
        _obj(2, address=0x3000, outer_index=0, name='MyStruct'),
        _obj(3, address=0x4000, outer_index=0, name='MyEnum'),
        _obj(4, address=0x5000, class_index=1, outer_index=1, name='Instance'),
    ]
    table = model.ObjectTable(objects)
    fn = model.FunctionRecord(path='/Game/Tst.MyClass:Bar', name='Bar', package='/Game/Tst',
                               flags=0, params_size=0, params=[], exec_rva=0x9000)
    cls = model.ClassRecord(path='/Game/Tst.MyClass', name='MyClass', cpp_name='UMyClass', package='/Game/Tst',
                             super=None, size=8, min_alignment=8, properties=[], functions={'Bar': fn})
    prop = model.PropertyRecord(name='Val', offset=0, size=4, array_dim=1, flags=0,
                                 type=model.PropType(prop='IntProperty', kind='IntProperty'))
    struct = model.StructRecord(path='/Game/Tst.MyStruct', name='MyStruct', cpp_name='FMyStruct', package='/Game/Tst',
                                 super=None, size=4, min_alignment=4, properties=[prop])
    enum = model.EnumRecord(path='/Game/Tst.MyEnum', name='MyEnum', cpp_name='EMyEnum', package='/Game/Tst',
                             underlying_size=1, underlying_size_from='reflection', underlying_signed=False,
                             values=[('A', 0), ('B', 1)])
    types_list = [cls, struct, enum]
    fields = [(1, [0x10, 0x20]), (2, [0x30])]
    return table, types_list, fields


class WriteReadTests(unittest.TestCase):
    def test_roundtrip(self):
        table, types_list, fields = _build_world()
        with tempfile.TemporaryDirectory() as d:
            folder = os.path.join(d, 'snap')
            result = snapshot.write_snapshot(folder, {'target': {'stem': 'Stem1'}},
                                              {'schema': {'name': 'x', 'version': '9.9'}, 'x': 1},
                                              list(table), types_list, fields)
            self.assertEqual(result['objects'], len(table))
            self.assertEqual(result['types'], len(types_list))
            self.assertEqual(result['fields'], len(fields))
            partial = result['partial']
            self.assertEqual(sorted(os.listdir(partial)),  # no leftover spool file
                              ['fields.jsonl', 'meta.json', 'objects.jsonl', 'offsets.json',
                               'types.idx.json', 'types.jsonl'])
            os.rename(partial, folder)
            with snapshot.Snapshot.load(folder) as snap:
                self.assertEqual(snap.stem, 'Stem1')
                self.assertEqual(snap.offsets, {'schema': {'name': snapshot.OFFSETS_SCHEMA,
                                                            'version': snapshot.SCHEMA_VERSION}, 'x': 1})
                self.assertEqual(snap.type('/Game/Tst.MyClass'), types_list[0])
                self.assertEqual(snap.type('/Game/Tst.MyStruct'), types_list[1])
                self.assertEqual(snap.type('/Game/Tst.MyEnum'), types_list[2])
                fn = snap.type('/Game/Tst.MyClass:Bar')
                self.assertEqual(fn.path, '/Game/Tst.MyClass:Bar')
                self.assertEqual(fn.name, 'Bar')
                self.assertEqual(fn.package, '/Game/Tst')
                self.assertEqual([t.path for t in snap.types()], sorted(t.path for t in types_list))
                self.assertEqual(snap.type_of_object(1).path, '/Game/Tst.MyClass')
                self.assertIsNone(snap.type_of_object(0))
                self.assertIsNone(snap.type_of_object(4))
                self.assertEqual(snap.field_addresses(1), [0x10, 0x20])
                self.assertEqual(snap.field_addresses(2), [0x30])
                self.assertIsNone(snap.field_addresses(999))

    def test_fields_in_memory_equals_loaded(self):
        table, types_list, fields = _build_world()
        with tempfile.TemporaryDirectory() as d:
            folder = os.path.join(d, 'snap')
            result = snapshot.write_snapshot(folder, {}, {}, list(table), types_list, fields)
            os.rename(result['partial'], folder)
            with snapshot.Snapshot.load(folder) as loaded:
                mem_pairs = snapshot.Snapshot({}, {}, table, types_list, fields=fields)
                mem_dict = snapshot.Snapshot({}, {}, table, types_list, fields=dict(fields))
                for mem in (mem_pairs, mem_dict):
                    for owner in (0, 1, 2, 3, 4, 999):
                        self.assertEqual(mem.field_addresses(owner), loaded.field_addresses(owner))
                    for path in ('/Game/Tst.MyClass', '/Game/Tst.MyStruct', '/Game/Tst.MyEnum',
                                 '/Game/Tst.MyClass:Bar', '/nope'):
                        self.assertEqual(mem.type(path), loaded.type(path))
                    self.assertEqual([t.path for t in mem.types()], [t.path for t in loaded.types()])
                    for idx in range(5):
                        self.assertEqual(mem.type_of_object(idx), loaded.type_of_object(idx))
                got1 = mem_pairs.field_addresses(1)
                got1.append(999)
                self.assertEqual(mem_pairs.field_addresses(1), [0x10, 0x20])  # fresh copy each call
            with self.assertRaises(ValueError):
                snapshot.Snapshot({}, {}, table, types_list, fields=[(1, [1]), (1, [2])])
            with self.assertRaises(ValueError):
                snapshot.Snapshot({}, {}, table, types_list, fields=[(1, [1 << 64])])

    def test_line_bytes_golden(self):
        objects = [
            _obj(0, address=0x1000, flags=0x1, name='日本語'),
            _obj(1, address=0x2000, flags=0x10, class_index=0, outer_index=0, name='Foo', vtable_rva=0x500),
        ]
        struct = model.StructRecord(path='/T/S', name='N\ud800', cpp_name='FS', package='/T', super=None,
                                     size=4, min_alignment=4, properties=[])
        gen = {'tool': 't', 'version': 'v', 'reference': 'r'}
        with tempfile.TemporaryDirectory() as d:
            folder = os.path.join(d, 'snap')
            result = snapshot.write_snapshot(folder, {}, {}, objects, [struct], [(1, [0x10])], generator=gen)
            partial = result['partial']

            expected_objects = (
                '{"schema":{"name":"nylib.ue.objects","version":"1.0"},"columns":'
                '["index","address","flags","class","outer","name"]}\n'
                '[0,"0x1000","0x00000001",-1,-1,"日本語"]\n'
                '[1,"0x2000","0x00000010",0,0,"Foo","0x500"]\n'
            ).encode('utf-8')
            expected_fields = (
                '{"schema":{"name":"nylib.ue.fields","version":"1.0"}}\n'
                '[1,["0x10"]]\n'
            ).encode('utf-8')
            expected_offsets = '{"schema":{"name":"nylib.ue.offsets","version":"1.0"}}\n'.encode('utf-8')
            expected_meta = (
                '{"schema":{"name":"nylib.ue.snapshot","version":"1.0"},'
                '"generator":{"tool":"t","version":"v","reference":"r"}}\n'
            ).encode('utf-8')
            # the lone surrogate in the type's own name is escaped (uppercase hex) the same way
            # objects.jsonl names are; ensure_ascii=False keeps everything else raw UTF-8.
            type_line = (
                '{"kind":"struct","path":"/T/S","name":"N\\uD800","cpp_name":"FS","package":"/T",'
                '"super":null,"size":"0x4","min_alignment":4,"properties":[]}'
            ).encode('utf-8')
            expected_types = type_line + b'\n'
            expected_idx = ('{"/T/S":[0,' + str(len(type_line)) + ']}\n').encode('utf-8')

            for name, expected in (
                ('objects.jsonl', expected_objects), ('fields.jsonl', expected_fields),
                ('offsets.json', expected_offsets), ('types.idx.json', expected_idx),
                ('types.jsonl', expected_types), ('meta.json', expected_meta),
            ):
                with open(os.path.join(partial, name), 'rb') as f:
                    data = f.read()
                self.assertEqual(data, expected, name)
                self.assertNotIn(b'\r', data, name)
                self.assertTrue(data.endswith(b'\n'), name)

    def test_idx_bytes(self):
        struct = model.StructRecord(path='/A/テスト.構造体', name='構造体', cpp_name='FKouzoutai', package='/A',
                                     super=None, size=4, min_alignment=4, properties=[])
        enum = model.EnumRecord(path='/B/\U0001F600Emoji', name='\U0001F600Emoji', cpp_name='EEmoji', package='/B',
                                 underlying_size=1, underlying_size_from='reflection', underlying_signed=False,
                                 values=[('X', 0)])
        types_list = [struct, enum]
        with tempfile.TemporaryDirectory() as d:
            partials = []
            for i in range(2):
                folder = os.path.join(d, f'snap{i}')
                result = snapshot.write_snapshot(folder, {}, {}, [], types_list, [])
                partials.append(result['partial'])

            with open(os.path.join(partials[0], 'types.idx.json'), 'r', encoding='utf-8') as f:
                idx = json.loads(f.read())
            self.assertEqual(list(idx), ['/A/テスト.構造体', '/B/\U0001F600Emoji'])

            with open(os.path.join(partials[0], 'types.jsonl'), 'rb') as f:
                jsonl_bytes = f.read()

            offset = 0
            for rec in types_list:
                entry_offset, entry_length = idx[rec.path]
                self.assertEqual(entry_offset, offset)
                line = jsonl_bytes[entry_offset:entry_offset + entry_length]
                self.assertNotIn(b'\n', line)
                self.assertEqual(jsonl_bytes[entry_offset + entry_length:entry_offset + entry_length + 1], b'\n')
                self.assertEqual(json.loads(line.decode('utf-8')), rec.to_json())
                offset = entry_offset + entry_length + 1

            with open(os.path.join(partials[1], 'types.jsonl'), 'rb') as f:
                self.assertEqual(f.read(), jsonl_bytes)
            with open(os.path.join(partials[1], 'types.idx.json'), 'rb') as f:
                idx_bytes_1 = f.read()
            with open(os.path.join(partials[0], 'types.idx.json'), 'rb') as f:
                idx_bytes_0 = f.read()
            self.assertEqual(idx_bytes_0, idx_bytes_1)

    def test_surrogate(self):
        name = 'Na\ud83dme'
        with tempfile.TemporaryDirectory() as d:
            folder = os.path.join(d, 'snap')
            result = snapshot.write_snapshot(folder, {}, {}, [_obj(0, name=name)], [], [])
            partial = result['partial']
            with open(os.path.join(partial, 'objects.jsonl'), 'rb') as f:
                data = f.read()
            self.assertIn(b'\\uD83D', data)
            text = data.decode('utf-8')  # must not raise: the file stays valid UTF-8
            self.assertNotIn('\r', text)
            os.rename(partial, folder)
            with snapshot.Snapshot.load(folder) as snap:
                self.assertEqual(snap.objects[0].name, name)

    def test_order_and_ranges(self):
        with tempfile.TemporaryDirectory() as d:
            for i, objs in enumerate(([_obj(0), _obj(0)], [_obj(1), _obj(0)], [_obj(-1)])):
                with self.assertRaises(ValueError, msg=objs):
                    _write_minimal(os.path.join(d, f'v{i}'), objects=objs)

            with self.assertRaises(TypeError):
                _write_minimal(os.path.join(d, 't0'), objects=['not-a-record'])
            with self.assertRaisesRegex(TypeError, 'address'):
                bad = model.ObjectRecord(index=0, address='nope', flags=0, class_index=-1, outer_index=-1, name='N')
                _write_minimal(os.path.join(d, 't1'), objects=[bad])
            with self.assertRaises(ValueError):
                _write_minimal(os.path.join(d, 'r0'), objects=[_obj(0, address=-1)])
            with self.assertRaises(ValueError):
                _write_minimal(os.path.join(d, 'r1'), objects=[_obj(0, address=1 << 64)])

            for i, fields in enumerate(([(0, []), (0, [])], [(1, []), (0, [])], [(-1, [])])):
                with self.assertRaises(ValueError, msg=fields):
                    _write_minimal(os.path.join(d, f'f{i}'), fields=fields)
            with self.assertRaises(TypeError):
                _write_minimal(os.path.join(d, 'fp'), fields=[(0,)])
            with self.assertRaises(TypeError):
                _write_minimal(os.path.join(d, 'fp2'), fields=[123])
            with self.assertRaises(TypeError):
                _write_minimal(os.path.join(d, 'fa'), fields=[(0, ['nope'])])
            with self.assertRaises(ValueError):
                _write_minimal(os.path.join(d, 'far'), fields=[(0, [1 << 64])])

            # a loader fed a hand-edited file with the same defects raises SnapshotError, not ValueError
            result = _write_minimal(os.path.join(d, 'src'), objects=[_obj(0)])
            partial = result['partial']
            objects_path = os.path.join(partial, 'objects.jsonl')
            with open(objects_path, 'rb') as f:
                header = f.readline()
            with open(objects_path, 'wb') as f:
                f.write(header)
                f.write(b'[0,"0x10","0x00000000",-1,-1,"N"]\n')
                f.write(b'[0,"0x10","0x00000000",-1,-1,"N"]\n')  # duplicate index
            folder = os.path.join(d, 'src_final')
            os.rename(partial, folder)
            with self.assertRaises(snapshot.SnapshotError):
                snapshot.Snapshot.load(folder)

    def test_dup_path(self):
        a = model.StructRecord(path='/A/X', name='X', cpp_name='FX', package='/A', super=None,
                                size=4, min_alignment=4, properties=[])
        b = model.EnumRecord(path='/A/X', name='X2', cpp_name='EX', package='/A', underlying_size=1,
                              underlying_size_from='reflection', underlying_signed=False, values=[('A', 0)])
        with tempfile.TemporaryDirectory() as d:
            folder = os.path.join(d, 'snap')
            with self.assertRaises(ValueError):
                _write_minimal(folder, types=[a, b])
            self.assertFalse(os.path.isfile(folder + '.partial' + os.sep + 'meta.json'))

    def test_dup_path_surrogate_pair_collides_with_astral(self):
        # A lone-surrogate pair and its combined astral code point serialise to the same JSON
        # text, so the writer must treat them as the same path, not two distinct ones.
        surrogate_pair_path = '/A/' + chr(0xd83d) + chr(0xde00)  # NOT the same Python str as below
        astral_path = '/A/\U0001F600'
        self.assertNotEqual(surrogate_pair_path, astral_path)  # sanity: genuinely different str objects
        a = model.StructRecord(path=surrogate_pair_path, name='a', cpp_name='FA', package='/A', super=None,
                                size=4, min_alignment=4, properties=[])
        b = model.StructRecord(path=astral_path, name='b', cpp_name='FB', package='/A', super=None,
                                size=4, min_alignment=4, properties=[])
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(ValueError):
                _write_minimal(os.path.join(d, 'snap'), types=[a, b])

    def test_type_to_json_raises_leaves_no_meta(self):
        class Bad:
            path = '/A/Bad'

            def to_json(self):
                raise RuntimeError('boom')

        with tempfile.TemporaryDirectory() as d:
            folder = os.path.join(d, 'snap')
            with self.assertRaisesRegex(RuntimeError, 'boom'):
                _write_minimal(folder, types=[Bad()])
            self.assertFalse(os.path.isfile(folder + '.partial' + os.sep + 'meta.json'))

    def test_stale_meta_removed(self):
        with tempfile.TemporaryDirectory() as d:
            folder = os.path.join(d, 'snap')
            r1 = _write_minimal(folder, objects=[_obj(0)])
            partial = r1['partial']
            self.assertTrue(os.path.isfile(os.path.join(partial, 'meta.json')))
            with self.assertRaises(TypeError):
                _write_minimal(folder, objects=[_obj(0), 'not-a-record'])
            self.assertFalse(os.path.isfile(os.path.join(partial, 'meta.json')))
            with self.assertRaises(snapshot.SnapshotError):
                snapshot.Snapshot.load(partial, _partial=True)

    def test_partial(self):
        with tempfile.TemporaryDirectory() as d:
            folder = os.path.join(d, 'snap')
            result = _write_minimal(folder, objects=[_obj(0)])
            partial = result['partial']
            self.assertEqual(partial, os.path.abspath(folder) + '.partial')

            with self.assertRaises(snapshot.SnapshotError):
                snapshot.Snapshot.load(folder)
            with self.assertRaises(snapshot.SnapshotError):
                snapshot.Snapshot.load(partial)
            with snapshot.Snapshot.load(partial, _partial=True):
                pass
            with self.assertRaises(snapshot.SnapshotError):
                snapshot.Snapshot.load(partial + os.sep)

            upper = partial[:-len('.partial')] + '.PARTIAL'
            os.rename(partial, upper)
            with self.assertRaises(snapshot.SnapshotError):
                snapshot.Snapshot.load(upper)
            with snapshot.Snapshot.load(upper, _partial=True):
                pass
            os.rename(upper, folder)
            with snapshot.Snapshot.load(folder):
                pass

            with self.assertRaises(ValueError):
                snapshot.write_snapshot(folder + '.partial', {}, {}, [], [], [])

    def test_partial_trailing_dot_and_space(self):
        # Windows silently drops trailing dots/spaces from a directory name, so the writer and
        # loader must still recognise these as naming the same `.partial` folder.
        with tempfile.TemporaryDirectory() as d:
            folder = os.path.join(d, 'snap')
            result = _write_minimal(folder, objects=[_obj(0)])
            partial = result['partial']
            for suffix in ('.', ' ', '. ', os.sep + '.'):
                with self.assertRaises(snapshot.SnapshotError, msg=suffix):
                    snapshot.Snapshot.load(partial + suffix)

            with self.assertRaises(ValueError):
                snapshot.write_snapshot(folder + '.PARTIAL', {}, {}, [], [], [])
            with self.assertRaises(ValueError):
                snapshot.write_snapshot(folder + '.partial' + os.sep, {}, {}, [], [], [])

    def test_writer_empty_folder(self):
        with self.assertRaises(ValueError):
            snapshot.write_snapshot('', {}, {}, [], [], [])

    def test_writer_offsets_generator_typecheck(self):
        with tempfile.TemporaryDirectory() as d:
            folder = os.path.join(d, 'snap')
            with self.assertRaises(TypeError):
                snapshot.write_snapshot(folder, {}, 'not-a-dict', [], [], [])
            with self.assertRaises(TypeError):
                snapshot.write_snapshot(folder, {}, {}, [], [], [], generator='not-a-dict')

    def test_type_element_path_typecheck(self):
        class BadPath:
            path = 123

            def to_json(self):
                return {}

        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(TypeError):
                _write_minimal(os.path.join(d, 'snap'), types=[BadPath()])

    def test_empty_address_list_accepted(self):
        with tempfile.TemporaryDirectory() as d:
            folder = os.path.join(d, 'snap')
            result = _write_minimal(folder, objects=[_obj(0)], fields=[(0, [])])
            os.rename(result['partial'], folder)
            with snapshot.Snapshot.load(folder) as snap:
                self.assertEqual(snap.field_addresses(0), [])

    def test_bool_class_index_roundtrip(self):
        # bool is an int subtype (F1): a caller passing True/False for an int-typed column must
        # still round-trip as a plain JSON integer, not `true`/`false`.
        with tempfile.TemporaryDirectory() as d:
            folder = os.path.join(d, 'snap')
            result = _write_minimal(folder, objects=[_obj(0, class_index=True, outer_index=False)])
            partial = result['partial']
            with open(os.path.join(partial, 'objects.jsonl'), 'rb') as f:
                data = f.read()
            self.assertNotIn(b'true', data)
            self.assertNotIn(b'false', data)
            os.rename(partial, folder)
            with snapshot.Snapshot.load(folder) as snap:
                rec = snap.objects[0]
                self.assertEqual(rec.class_index, 1)
                self.assertEqual(rec.outer_index, 0)

    def test_control_char_name_roundtrip(self):
        # U+0085 (NEL) and U+2028 (LINE SEPARATOR) are line boundaries for str.splitlines() but
        # not for the JSONL grammar (split('\n') only); a name holding them must still round-trip.
        name = 'a' + chr(0x85) + 'b' + chr(0x2028) + 'c'
        with tempfile.TemporaryDirectory() as d:
            folder = os.path.join(d, 'snap')
            result = _write_minimal(folder, objects=[_obj(0, name=name)])
            os.rename(result['partial'], folder)
            with snapshot.Snapshot.load(folder) as snap:
                self.assertEqual(snap.objects[0].name, name)

    def test_meta_overwrite(self):
        with tempfile.TemporaryDirectory() as d:
            folder = os.path.join(d, 'snap')
            caller_meta = {'schema': {'name': 'x', 'version': '9.9'}, 'note': 'hi'}
            original = dict(caller_meta)
            result = snapshot.write_snapshot(folder, caller_meta, {}, [], [], [],
                                              generator={'tool': 'nylib.ue', 'version': 'test', 'reference': 'x'})
            self.assertEqual(caller_meta, original)
            os.rename(result['partial'], folder)
            with snapshot.Snapshot.load(folder) as snap:
                self.assertEqual(snap.meta['schema'], {'name': snapshot.SCHEMA_NAME, 'version': snapshot.SCHEMA_VERSION})
                self.assertEqual(snap.meta['generator'], {'tool': 'nylib.ue', 'version': 'test', 'reference': 'x'})
                self.assertEqual(snap.meta['note'], 'hi')

        with tempfile.TemporaryDirectory() as d:
            folder = os.path.join(d, 'snap')
            with self.assertRaises(ValueError):
                snapshot.write_snapshot(folder, {'bad': float('nan')}, {}, [], [], [])
            self.assertFalse(os.path.exists(folder + '.partial'))

        with tempfile.TemporaryDirectory() as d:
            folder = os.path.join(d, 'snap3')
            with self.assertRaises(ValueError):
                snapshot.write_snapshot(folder, {'bad': {1, 2, 3}}, {}, [], [], [])
            self.assertFalse(os.path.exists(folder + '.partial'))

    def test_caller_meta_generator_key_ignored_when_generator_none(self):
        # A `generator` key embedded in the caller's own `meta` must not leak through when the
        # `generator=` argument is left at its default: GENERATOR_DEFAULT always wins then.
        with tempfile.TemporaryDirectory() as d:
            folder = os.path.join(d, 'snap')
            caller_meta = {'generator': {'tool': 'evil', 'version': 'x', 'reference': 'y'}}
            result = snapshot.write_snapshot(folder, caller_meta, {}, [], [], [])
            os.rename(result['partial'], folder)
            with snapshot.Snapshot.load(folder) as snap:
                self.assertEqual(snap.meta['generator'], snapshot.GENERATOR_DEFAULT)


class TypeTests(unittest.TestCase):
    def test_exact_before_split(self):
        fn_top = model.FunctionRecord(path='/A/Foo:Bar', name='Bar', package='/A', flags=0, params_size=111,
                                       params=[], exec_rva=None)
        nested_bar = model.FunctionRecord(path='/A/Foo:Bar', name='Bar', package='/A', flags=0, params_size=222,
                                           params=[], exec_rva=None)
        cls = model.ClassRecord(path='/A/Foo', name='Foo', cpp_name='UFoo', package='/A', super=None, size=8,
                                 min_alignment=8, properties=[], functions={'Bar': nested_bar})
        struct = model.StructRecord(path='/A/NotAClass', name='NotAClass', cpp_name='FNotAClass', package='/A',
                                     super=None, size=4, min_alignment=4, properties=[])
        table = model.ObjectTable([])
        snap = snapshot.Snapshot({}, {}, table, [fn_top, cls, struct])
        self.assertIs(snap.type('/A/Foo:Bar'), fn_top)
        self.assertIsNone(snap.type('/A/Foo:missing'))
        self.assertIsNone(snap.type('/A/NotAClass:x'))
        self.assertIsNone(snap.type('/A/Missing:x'))
        with self.assertRaises(TypeError):
            snap.type(123)

    def test_rpartition_on_multiple_colons(self):
        # Each ':' is tried from the left: '/A/Foo' is no class, so the split falls through to '/A/Foo:Bar'.
        fn = model.FunctionRecord(path='/A/Foo:Bar:Baz', name='Baz', package='/A', flags=0, params_size=0,
                                   params=[], exec_rva=None)
        cls = model.ClassRecord(path='/A/Foo:Bar', name='Bar', cpp_name='UBar', package='/A', super=None, size=8,
                                 min_alignment=8, properties=[], functions={'Baz': fn})
        table = model.ObjectTable([])
        snap = snapshot.Snapshot({}, {}, table, [cls])
        self.assertIs(snap.type('/A/Foo:Bar:Baz'), fn)

    def test_colon_in_function_name(self):
        names = ('Task: Update All Attribute', 'CSW::SetBrushAtKeyFrame')
        fns = {n: model.FunctionRecord(path=f'/G/BP.BP_C:{n}', name=n, package='/G/BP', flags=0, params_size=0,
                                       params=[], exec_rva=None) for n in names}
        cls = model.ClassRecord(path='/G/BP.BP_C', name='BP_C', cpp_name='UBP_C', package='/G/BP', super=None, size=8,
                                 min_alignment=8, properties=[], functions=fns)
        mem = snapshot.Snapshot({}, {}, model.ObjectTable([]), [cls])
        with tempfile.TemporaryDirectory() as d:
            folder = os.path.join(d, 'snap')
            os.rename(_write_minimal(folder, types=[cls])['partial'], folder)
            with snapshot.Snapshot.load(folder) as loaded:
                for snap in (mem, loaded):
                    for n in names:
                        self.assertEqual(snap.type(f'/G/BP.BP_C:{n}'), fns[n])
                    self.assertIsNone(snap.type('/G/BP.BP_C:Task: missing'))

    def test_cache_bounded(self):
        n_fn = 300
        functions = {f'Fn{i}': model.FunctionRecord(path=f'/A/Cls:Fn{i}', name=f'Fn{i}', package='/A', flags=0,
                                                     params_size=0, params=[], exec_rva=None) for i in range(n_fn)}
        cls = model.ClassRecord(path='/A/Cls', name='Cls', cpp_name='UCls', package='/A', super=None, size=8,
                                 min_alignment=8, properties=[], functions=functions)
        extra = [model.StructRecord(path=f'/B/S{i:04d}', name=f'S{i}', cpp_name=f'FS{i}', package='/B', super=None,
                                     size=4, min_alignment=4, properties=[]) for i in range(snapshot.TYPE_CACHE_SIZE)]
        with tempfile.TemporaryDirectory() as d:
            folder = os.path.join(d, 'snap')
            result = _write_minimal(folder, types=[cls, *extra])
            os.rename(result['partial'], folder)
            with snapshot.Snapshot.load(folder) as snap:
                calls = []
                orig = snapshot.type_from_json

                def spy(data):
                    calls.append(data)
                    return orig(data)

                with unittest.mock.patch('nylib.ue.snapshot.type_from_json', side_effect=spy):
                    for i in range(n_fn):
                        snap.type(f'/A/Cls:Fn{i}')
                    self.assertEqual(len(calls), 1)  # the class line is parsed once for 300 functions

                    for t in extra:
                        snap.type(t.path)
                    self.assertEqual(len(calls), 1 + len(extra))  # touched CACHE_SIZE + 1 distinct types

                    snap.type(extra[0].path)  # only Cls (the true LRU victim) should have been evicted
                    self.assertEqual(len(calls), 1 + len(extra))

                    snap.type('/A/Cls:Fn0')  # evicted -> reparsed
                    self.assertEqual(len(calls), 1 + len(extra) + 1)

                    snap.type(extra[-1].path)  # most recently used -> no reparse
                    self.assertEqual(len(calls), 1 + len(extra) + 1)

    def test_cache_lru_order(self):
        types_list = [model.StructRecord(path=f'/C/{i:03d}', name=f'C{i}', cpp_name=f'FC{i}', package='/C',
                                          super=None, size=4, min_alignment=4, properties=[])
                      for i in range(snapshot.TYPE_CACHE_SIZE + 1)]
        with tempfile.TemporaryDirectory() as d:
            folder = os.path.join(d, 'snap')
            result = _write_minimal(folder, types=types_list)
            os.rename(result['partial'], folder)
            with snapshot.Snapshot.load(folder) as snap:
                calls = []
                orig = snapshot.type_from_json

                def spy(data):
                    calls.append(data)
                    return orig(data)

                with unittest.mock.patch('nylib.ue.snapshot.type_from_json', side_effect=spy):
                    for t in types_list[:-1]:  # fill the cache to exactly TYPE_CACHE_SIZE entries
                        snap.type(t.path)
                    self.assertEqual(len(calls), snapshot.TYPE_CACHE_SIZE)

                    snap.type(types_list[0].path)  # touch the oldest entry again -> promotes it to MRU
                    self.assertEqual(len(calls), snapshot.TYPE_CACHE_SIZE)

                    snap.type(types_list[-1].path)  # one more distinct type -> exactly one eviction
                    self.assertEqual(len(calls), snapshot.TYPE_CACHE_SIZE + 1)

                    snap.type(types_list[0].path)  # was promoted -> must still be cached
                    self.assertEqual(len(calls), snapshot.TYPE_CACHE_SIZE + 1)

                    snap.type(types_list[1].path)  # the actual LRU victim -> must have been evicted
                    self.assertEqual(len(calls), snapshot.TYPE_CACHE_SIZE + 2)

    def test_closed(self):
        struct = model.StructRecord(path='/A/S', name='S', cpp_name='FS', package='/A', super=None,
                                     size=4, min_alignment=4, properties=[])
        with tempfile.TemporaryDirectory() as d:
            folder = os.path.join(d, 'snap')
            result = _write_minimal(folder, objects=[_obj(0)], types=[struct])
            os.rename(result['partial'], folder)
            snap = snapshot.Snapshot.load(folder)
            snap.close()
            with self.assertRaises(ValueError):
                snap.type('/A/S')
            with self.assertRaises(ValueError):
                snap.types()  # checked at call time, before the generator is even consumed
            with self.assertRaises(ValueError):
                list(snap.types())
            with self.assertRaises(ValueError):
                snap.type_of_object(0)
            self.assertIsNone(snap.field_addresses(0))
            self.assertIsInstance(snap.objects, model.ObjectTable)
            self.assertEqual(snap.meta['schema']['name'], snapshot.SCHEMA_NAME)
            self.assertEqual(snap.stem, '')
            self.assertEqual(snap.path, folder)
            snap.close()  # idempotent

    def test_line_errors(self):
        struct = model.StructRecord(path='/A/S', name='S', cpp_name='FS', package='/A', super=None,
                                     size=4, min_alignment=4, properties=[])
        with tempfile.TemporaryDirectory() as d:
            folder = os.path.join(d, 'snap')
            result = _write_minimal(folder, types=[struct])
            os.rename(result['partial'], folder)

            jsonl_path = os.path.join(folder, 'types.jsonl')
            idx_path = os.path.join(folder, 'types.idx.json')
            with open(jsonl_path, 'rb') as f:
                appended = f.read()
            with open(idx_path, 'r', encoding='utf-8') as f:
                new_idx = json.loads(f.read())

            def append(key, payload: bytes):
                nonlocal appended
                offset = len(appended)
                appended += payload + b'\n'
                new_idx[key] = [offset, len(payload)]

            append('/X/BadUtf8', b'\xff\xfe\xfd')
            append('/X/BadJson', b'not json at all')
            append('/X/PathMismatch', b'{"path":"/X/Other"}')
            append('/X/BadKind', b'{"path":"/X/BadKind","kind":"nonsense"}')
            append('/X/NotObject', b'[1,2,3]')

            with open(jsonl_path, 'wb') as f:
                f.write(appended)
            with open(idx_path, 'w', encoding='utf-8', newline='\n') as f:
                f.write(json.dumps(new_idx))
                f.write('\n')

            with snapshot.Snapshot.load(folder) as snap:
                for path in ('/X/BadUtf8', '/X/BadJson', '/X/PathMismatch', '/X/BadKind', '/X/NotObject'):
                    with self.assertRaises(snapshot.SnapshotError, msg=path):
                        snap.type(path)

    def test_deep_nesting_type_line(self):
        with tempfile.TemporaryDirectory() as d:
            folder = os.path.join(d, 'snap')
            struct = model.StructRecord(path='/A/S', name='S', cpp_name='FS', package='/A', super=None,
                                         size=4, min_alignment=4, properties=[])
            result = _write_minimal(folder, types=[struct])
            partial = result['partial']
            depth = 3000
            inner = '{"prop":"ArrayProperty","inner":' * depth + '{"prop":"IntProperty"}' + '}' * depth
            line = ('{"kind":"struct","path":"/A/S","name":"S","cpp_name":"FS","package":"/A","super":null,'
                    '"size":"0x4","min_alignment":4,"properties":[{"name":"p","offset":"0x0","size":"0x4",'
                    '"array_dim":1,"flags":"0x0","type":' + inner + '}]}').encode()
            with open(os.path.join(partial, 'types.jsonl'), 'wb') as f:
                f.write(line + b'\n')
            with open(os.path.join(partial, 'types.idx.json'), 'wb') as f:
                f.write(json.dumps({'/A/S': [0, len(line)]}).encode() + b'\n')
            os.rename(partial, folder)
            with snapshot.Snapshot.load(folder) as snap:
                with self.assertRaises(snapshot.SnapshotError):
                    snap.type('/A/S')

    def test_type_of_object_missing_index_raises_keyerror(self):
        table = model.ObjectTable([])
        snap = snapshot.Snapshot({}, {}, table, [])
        with self.assertRaises(KeyError):
            snap.type_of_object(999)

    def test_type_of_object_cyclic_outer_returns_none(self):
        objects = [
            model.ObjectRecord(index=0, address=0x10, flags=0, class_index=-1, outer_index=1, name='A'),
            model.ObjectRecord(index=1, address=0x20, flags=0, class_index=-1, outer_index=0, name='B'),
        ]
        table = model.ObjectTable(objects)
        snap = snapshot.Snapshot({}, {}, table, [])
        self.assertIsNone(snap.type_of_object(0))

    def test_field_addresses_typecheck(self):
        table = model.ObjectTable([])
        snap = snapshot.Snapshot({}, {}, table, [])
        with self.assertRaises(TypeError):
            snap.field_addresses('nope')

    def test_inmemory_duplicate_path_keeps_first(self):
        a = model.StructRecord(path='/A/X', name='first', cpp_name='FX', package='/A', super=None,
                                size=4, min_alignment=4, properties=[])
        b = model.StructRecord(path='/A/X', name='second', cpp_name='FX2', package='/A', super=None,
                                size=4, min_alignment=4, properties=[])
        table = model.ObjectTable([])
        snap = snapshot.Snapshot({}, {}, table, [a, b])
        self.assertIs(snap.type('/A/X'), a)

    def test_inmemory_objects_typecheck(self):
        with self.assertRaises(TypeError):
            snapshot.Snapshot({}, {}, [], [])

    def test_inmemory_type_element_typecheck(self):
        table = model.ObjectTable([])
        with self.assertRaises(TypeError):
            snapshot.Snapshot({}, {}, table, ['not-a-type-record'])

    def test_inmemory_fields_stores_copy_not_alias(self):
        table = model.ObjectTable([])
        addrs = [0x10, 0x20]
        snap = snapshot.Snapshot({}, {}, table, [], fields=[(0, addrs)])
        addrs.append(0x99)
        self.assertEqual(snap.field_addresses(0), [0x10, 0x20])


class SchemaTests(unittest.TestCase):
    def test_major(self):
        with tempfile.TemporaryDirectory() as d:
            folder = os.path.join(d, 'snap')
            result = snapshot.write_snapshot(folder, {}, {}, [], [], [],
                                              generator={'tool': 'nylib.ue', 'version': 'writer-1.2.3', 'reference': 'x'})
            partial = result['partial']
            meta_path = os.path.join(partial, 'meta.json')
            with open(meta_path, 'r', encoding='utf-8') as f:
                meta = json.loads(f.read())
            meta['schema']['version'] = '2.0'
            with open(meta_path, 'w', encoding='utf-8', newline='\n') as f:
                f.write(json.dumps(meta))
                f.write('\n')
            os.rename(partial, folder)
            meta_path_final = os.path.join(folder, 'meta.json')
            expected = (f'{meta_path_final} has schema 2.0; this reader understands 1.x. Update nylib, '
                        f'or read it with the nylib.ue version that wrote it (writer-1.2.3).')
            with self.assertRaises(snapshot.SchemaError) as cm:
                snapshot.Snapshot.load(folder)
            self.assertIsInstance(cm.exception, snapshot.SnapshotError)
            self.assertEqual(str(cm.exception), expected)

    def test_minor_tolerated(self):
        with tempfile.TemporaryDirectory() as d:
            folder = os.path.join(d, 'snap')
            result = snapshot.write_snapshot(folder, {}, {}, [], [], [])
            partial = result['partial']
            meta_path = os.path.join(partial, 'meta.json')
            with open(meta_path, 'r', encoding='utf-8') as f:
                meta = json.loads(f.read())
            meta['schema']['version'] = '1.5'
            with open(meta_path, 'w', encoding='utf-8', newline='\n') as f:
                f.write(json.dumps(meta))
                f.write('\n')
            os.rename(partial, folder)
            with snapshot.Snapshot.load(folder):
                pass

    def test_version_malformed(self):
        for bad_version in ('1', 2):
            with tempfile.TemporaryDirectory() as d:
                folder = os.path.join(d, 'snap')
                result = snapshot.write_snapshot(folder, {}, {}, [], [], [])
                partial = result['partial']
                meta_path = os.path.join(partial, 'meta.json')
                with open(meta_path, 'r', encoding='utf-8') as f:
                    meta = json.loads(f.read())
                meta['schema']['version'] = bad_version
                with open(meta_path, 'w', encoding='utf-8', newline='\n') as f:
                    f.write(json.dumps(meta))
                    f.write('\n')
                os.rename(partial, folder)
                with self.assertRaises(snapshot.SnapshotError) as cm:
                    snapshot.Snapshot.load(folder)
                self.assertIs(type(cm.exception), snapshot.SnapshotError)

    def test_reexport(self):
        self.assertIs(snapshot.SchemaError, errors.SchemaError)
        self.assertIs(snapshot.SnapshotError, errors.SnapshotError)

    def test_writer_version_fallback_to_unknown(self):
        for bad_generator in (None, 'not-a-dict', {'reference': 'x'}, {'version': 123}):
            with tempfile.TemporaryDirectory() as d:
                folder = os.path.join(d, 'snap')
                result = snapshot.write_snapshot(folder, {}, {}, [], [], [])
                partial = result['partial']
                meta_path = os.path.join(partial, 'meta.json')
                with open(meta_path, 'r', encoding='utf-8') as f:
                    meta = json.loads(f.read())
                meta['schema']['version'] = '2.0'
                meta['generator'] = bad_generator
                with open(meta_path, 'w', encoding='utf-8', newline='\n') as f:
                    f.write(json.dumps(meta))
                    f.write('\n')
                os.rename(partial, folder)
                with self.assertRaises(snapshot.SchemaError, msg=bad_generator) as cm:
                    snapshot.Snapshot.load(folder)
                self.assertIn('wrote it (unknown)', str(cm.exception))

    def test_constants_pinned(self):
        self.assertEqual(snapshot.SCHEMA_NAME, 'nylib.ue.snapshot')
        self.assertEqual(snapshot.SCHEMA_VERSION, '1.0')
        self.assertEqual(snapshot.OFFSETS_SCHEMA, 'nylib.ue.offsets')
        self.assertEqual(snapshot.OBJECTS_SCHEMA, 'nylib.ue.objects')
        self.assertEqual(snapshot.FIELDS_SCHEMA, 'nylib.ue.fields')
        self.assertEqual(snapshot.OBJECT_COLUMNS, ['index', 'address', 'flags', 'class', 'outer', 'name'])
        self.assertEqual(snapshot.TYPE_CACHE_SIZE, 256)
        self.assertEqual(snapshot.GENERATOR_DEFAULT['reference'], 'Dumper-7@ea0dab3')
        self.assertEqual(snapshot.GENERATOR_DEFAULT['tool'], 'nylib.ue')


class SchemaMalformedTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.base = os.path.join(self._tmp.name, 'base')
        result = _write_minimal(self.base, objects=[_obj(0)],
                                 types=[model.StructRecord(path='/A/S', name='S', cpp_name='FS', package='/A',
                                                            super=None, size=4, min_alignment=4, properties=[])])
        os.rename(result['partial'], self.base)

    def tearDown(self):
        self._tmp.cleanup()

    def _copy(self, name):
        dest = os.path.join(self._tmp.name, name)
        shutil.copytree(self.base, dest)
        return dest

    def _assert_malformed(self, folder, *, allow_subclass=False):
        with self.assertRaises(snapshot.SnapshotError) as cm:
            snapshot.Snapshot.load(folder)
        if not allow_subclass:
            self.assertIs(type(cm.exception), snapshot.SnapshotError)

    def test_no_meta(self):
        folder = self._copy('no_meta')
        os.remove(os.path.join(folder, 'meta.json'))
        self._assert_malformed(folder)

    def test_meta_not_object(self):
        folder = self._copy('meta_not_obj')
        with open(os.path.join(folder, 'meta.json'), 'w', encoding='utf-8', newline='\n') as f:
            f.write('[1,2,3]\n')
        self._assert_malformed(folder)

    def test_wrong_schema_name(self):
        cases = {
            'offsets.json': '{"schema":{"name":"bogus","version":"1.0"}}\n',
            'meta.json': '{"schema":{"name":"bogus","version":"1.0"}}\n',
            'objects.jsonl': ('{"schema":{"name":"bogus","version":"1.0"},"columns":'
                               '["index","address","flags","class","outer","name"]}\n'
                               '[0,"0x10","0x00000000",-1,-1,"N"]\n'),
            'fields.jsonl': '{"schema":{"name":"bogus","version":"1.0"}}\n',
        }
        for fname, content in cases.items():
            with self.subTest(fname=fname):
                folder = self._copy('wrong_schema_' + fname.replace('.', '_'))
                with open(os.path.join(folder, fname), 'w', encoding='utf-8', newline='\n') as f:
                    f.write(content)
                self._assert_malformed(folder)

    def test_missing_idx(self):
        folder = self._copy('missing_idx')
        os.remove(os.path.join(folder, 'types.idx.json'))
        self._assert_malformed(folder)

    def test_missing_required_files(self):
        for fname in ('types.jsonl', 'offsets.json', 'objects.jsonl'):
            with self.subTest(fname=fname):
                folder = self._copy('missing_' + fname.replace('.', '_'))
                os.remove(os.path.join(folder, fname))
                self._assert_malformed(folder)

    def test_bad_object_row(self):
        folder = self._copy('bad_row')
        p = os.path.join(folder, 'objects.jsonl')
        with open(p, 'r', encoding='utf-8') as f:
            lines = f.read().splitlines()
        lines[1] = '[0,"nothex","0x0",-1,-1,"A"]'
        with open(p, 'w', encoding='utf-8', newline='\n') as f:
            f.write('\n'.join(lines) + '\n')
        self._assert_malformed(folder)

    def test_object_address_out_of_range(self):
        for bad_addr in ('-0x1', '0x10000000000000000'):
            with self.subTest(bad_addr=bad_addr):
                folder = self._copy('addr_' + bad_addr.replace('-', 'neg').replace('0x', ''))
                p = os.path.join(folder, 'objects.jsonl')
                with open(p, 'rb') as f:
                    data = f.read()
                data = data.replace(b'"0x10"', ('"%s"' % bad_addr).encode(), 1)
                with open(p, 'wb') as f:
                    f.write(data)
                self._assert_malformed(folder)

    def test_missing_final_newline(self):
        folder = self._copy('no_final_nl')
        p = os.path.join(folder, 'objects.jsonl')
        with open(p, 'rb') as f:
            data = f.read()
        with open(p, 'wb') as f:
            f.write(data[:-1])
        self._assert_malformed(folder)

    def test_empty_line(self):
        folder = self._copy('empty_line')
        p = os.path.join(folder, 'objects.jsonl')
        with open(p, 'rb') as f:
            data = f.read()
        with open(p, 'wb') as f:
            f.write(data + b'\n')
        self._assert_malformed(folder)

    def test_idx_offset_past_eof(self):
        folder = self._copy('idx_eof')
        p = os.path.join(folder, 'types.idx.json')
        with open(p, 'r', encoding='utf-8') as f:
            idx = json.loads(f.read())
        for k in idx:
            idx[k] = [10 ** 9, 10]
        with open(p, 'w', encoding='utf-8', newline='\n') as f:
            f.write(json.dumps(idx))
            f.write('\n')
        self._assert_malformed(folder)

    def test_missing_fields_ok(self):
        folder = self._copy('no_fields')
        os.remove(os.path.join(folder, 'fields.jsonl'))
        with snapshot.Snapshot.load(folder) as snap:
            self.assertIsNone(snap.field_addresses(0))

    def test_idx_entry_leaves_no_room_for_newline(self):
        # Shrinking types.jsonl to exactly offset+length bytes drops the line's trailing '\n';
        # the bound check must still reject it (offset + length + 1 <= size).
        folder = self._copy('idx_no_room')
        jsonl_path = os.path.join(folder, 'types.jsonl')
        idx_path = os.path.join(folder, 'types.idx.json')
        with open(jsonl_path, 'rb') as f:
            data = f.read()
        with open(idx_path, 'r', encoding='utf-8') as f:
            idx = json.loads(f.read())
        (offset, length), = idx.values()
        with open(jsonl_path, 'wb') as f:
            f.write(data[:offset + length])
        self._assert_malformed(folder)

    def test_fields_duplicate_owner(self):
        with tempfile.TemporaryDirectory() as d:
            folder = os.path.join(d, 'snap')
            result = _write_minimal(folder, objects=[_obj(0), _obj(1)], fields=[(0, [0x10]), (1, [0x20])])
            partial = result['partial']
            fields_path = os.path.join(partial, 'fields.jsonl')
            with open(fields_path, 'rb') as f:
                header = f.readline()
            with open(fields_path, 'wb') as f:
                f.write(header)
                f.write(b'[0,["0x10"]]\n')
                f.write(b'[0,["0x20"]]\n')  # hand-edited: duplicate owner
            os.rename(partial, folder)
            with self.assertRaises(snapshot.SnapshotError):
                snapshot.Snapshot.load(folder)

    def test_fields_address_out_of_range(self):
        with tempfile.TemporaryDirectory() as d:
            folder = os.path.join(d, 'snap')
            result = _write_minimal(folder, objects=[_obj(0)], fields=[(0, [0x10])])
            partial = result['partial']
            p = os.path.join(partial, 'fields.jsonl')
            with open(p, 'rb') as f:
                data = f.read()
            data = data.replace(b'"0x10"', b'"0x10000000000000000"', 1)
            with open(p, 'wb') as f:
                f.write(data)
            os.rename(partial, folder)
            with self.assertRaises(snapshot.SnapshotError):
                snapshot.Snapshot.load(folder)

    def test_huge_int_objects_row(self):
        folder = self._copy('huge_obj')
        p = os.path.join(folder, 'objects.jsonl')
        with open(p, 'rb') as f:
            data = f.read()
        data = data.replace(b'[0,"0x10"', b'[' + b'9' * 5000 + b',"0x10"', 1)
        with open(p, 'wb') as f:
            f.write(data)
        self._assert_malformed(folder)

    def test_huge_int_idx_offset(self):
        folder = self._copy('huge_idx')
        p = os.path.join(folder, 'types.idx.json')
        with open(p, 'w', encoding='utf-8', newline='\n') as f:
            f.write('{"/A/S":[' + '1' * 5000 + ',5]}\n')
        self._assert_malformed(folder)

    def test_huge_int_schema_major(self):
        folder = self._copy('huge_major')
        p = os.path.join(folder, 'meta.json')
        with open(p, 'rb') as f:
            data = f.read()
        data = data.replace(b'"version":"1.0"', b'"version":"' + b'9' * 5000 + b'.0"', 1)
        with open(p, 'wb') as f:
            f.write(data)
        self._assert_malformed(folder)

    def test_huge_int_fields_owner(self):
        with tempfile.TemporaryDirectory() as d:
            folder = os.path.join(d, 'snap')
            result = _write_minimal(folder, objects=[_obj(0)], fields=[(0, [0x10])])
            partial = result['partial']
            p = os.path.join(partial, 'fields.jsonl')
            with open(p, 'rb') as f:
                data = f.read()
            data = data.replace(b'[0,', b'[' + b'9' * 5000 + b',', 1)
            with open(p, 'wb') as f:
                f.write(data)
            os.rename(partial, folder)
            with self.assertRaises(snapshot.SnapshotError):
                snapshot.Snapshot.load(folder)

    def test_deep_nesting_offsets(self):
        folder = self._copy('deep_offsets')
        p = os.path.join(folder, 'offsets.json')
        with open(p, 'wb') as f:
            f.write(b'{"schema":{"name":"nylib.ue.offsets","version":"1.0"},"x":'
                     + b'[' * 100000 + b']' * 100000 + b'}\n')
        self._assert_malformed(folder)


class LaunchIndependenceTests(unittest.TestCase):
    def test_shifted(self):
        objects_a = [_obj(0, address=0x1000, name='A'), _obj(1, address=0x2000, class_index=0, outer_index=0, name='B')]
        fields_a = [(1, [0x10, 0x20])]
        types_list = [model.StructRecord(path='/A/S', name='S', cpp_name='FS', package='/A', super=None,
                                          size=4, min_alignment=4, properties=[])]
        shift = 0x100000
        objects_b = [_obj(r.index, address=r.address + shift, flags=r.flags, class_index=r.class_index,
                           outer_index=r.outer_index, name=r.name,
                           vtable_rva=(r.vtable_rva + shift if r.vtable_rva is not None else None))
                     for r in objects_a]
        fields_b = [(owner, [a + shift for a in addrs]) for owner, addrs in fields_a]
        with tempfile.TemporaryDirectory() as d:
            ra = snapshot.write_snapshot(os.path.join(d, 'a'), {}, {}, objects_a, types_list, fields_a)
            rb = snapshot.write_snapshot(os.path.join(d, 'b'), {}, {}, objects_b, types_list, fields_b)
            for name in ('types.jsonl', 'types.idx.json'):
                with open(os.path.join(ra['partial'], name), 'rb') as f1, open(os.path.join(rb['partial'], name), 'rb') as f2:
                    self.assertEqual(f1.read(), f2.read(), name)
            for name in ('objects.jsonl', 'fields.jsonl'):
                with open(os.path.join(ra['partial'], name), 'rb') as f1, open(os.path.join(rb['partial'], name), 'rb') as f2:
                    self.assertNotEqual(f1.read(), f2.read(), name)


def _gen_objects(n):
    for i in range(n):
        yield _obj(i, address=0x1000 + i, name=f'Obj{i}')


def _gen_fields(n):
    for i in range(n):
        base = i * 64
        yield (i, [0x10 + base + j for j in range(64)])


def _gen_types(n):
    for i in range(n):
        long_name = f'{i:07d}' + 'X' * 4093
        prop = model.PropertyRecord(name=long_name, offset=0, size=4, array_dim=1, flags=0,
                                     type=model.PropType(prop='IntProperty', kind='IntProperty'))
        yield model.StructRecord(path=f'/T/{i:06d}', name=f'S{i}', cpp_name=f'FS{i}', package='/T',
                                  super=None, size=4, min_alignment=4, properties=[prop])


class MemoryTests(unittest.TestCase):
    def test_streaming(self):
        def run(n_types, n_objects, n_fields):
            with tempfile.TemporaryDirectory() as d:
                folder = os.path.join(d, 'snap')
                tracemalloc.reset_peak()
                snapshot.write_snapshot(folder, {}, {}, _gen_objects(n_objects), _gen_types(n_types),
                                         _gen_fields(n_fields))
                peak = tracemalloc.get_traced_memory()[1]
                partial = folder + '.partial'
                total_bytes = sum(
                    os.path.getsize(os.path.join(partial, name))
                    for name in ('objects.jsonl', 'fields.jsonl', 'types.jsonl', 'types.idx.json',
                                 'offsets.json', 'meta.json')
                )
            return peak, total_bytes

        tracemalloc.start()
        try:
            peak_a, bytes_a = run(4000, 50000, 20000)
            peak_b, bytes_b = run(8000, 100000, 40000)
        finally:
            tracemalloc.stop()
        self.assertGreater(bytes_b, bytes_a)
        self.assertLess(peak_b - peak_a, (bytes_b - bytes_a) / 4)


if __name__ == '__main__':
    unittest.main()
