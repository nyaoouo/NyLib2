"""Port gate 6-G: stages 4-6 on every captured session, compared with that session's Dumper-7 oracle.

Env-gated: skipped when NYLIB_UE_CAPTURES is unset; see port.py for the run and the comparisons.
"""
import os
import sys
import tempfile
import unittest

from . import real


class PortGateTests(unittest.TestCase):
    sessions: list = []
    runs: list = []

    @classmethod
    def setUpClass(cls):
        if real.captures_root() is None:
            raise unittest.SkipTest('NYLIB_UE_CAPTURES not set')
        cls.sessions = real.iter_sessions()
        cls.runs = []
        if not cls.sessions:
            return
        from . import port  # only with a session: imports the port (stages 4-6)
        for session in cls.sessions:
            with tempfile.TemporaryDirectory(prefix='nylib-ue-port-', ignore_cleanup_errors=True) as tmp:
                run = port.run_port(session, tmp, extra=True)  # 6-G.4 (review M10): extras run in the committed gate
            print(run.report(), file=sys.stderr)
            cls.runs.append(run)

    def _check(self, name: str, *, bootstrap: bool = False):
        for run in self.runs:
            with self.subTest(session=f'{run.target}/{os.path.basename(run.dir)}'):
                for s in run.steps if bootstrap else ():
                    if s.name == 'walk':
                        break
                    if s.status != 'ok':
                        self.fail(f'step {s.name} {s.status}: {s.detail or run.error}')
                if name in run.skipped:
                    self.skipTest(run.skipped[name])
                if (dr := run.checks.get(name)) is None:
                    self.fail(f'{name} not run: the run stopped at {run.error}')
                lines = '\n'.join(dr.samples)
                self.assertTrue(dr.ok, f'{name}: {dr.reason} (matched={dr.matched} changed={dr.changed} drift={dr.drift:.4f})\n{lines}')

    def test_sessions_present(self):
        if not self.sessions:
            self.fail('no complete capture session')
        for t in real.required_targets():
            if not any(s.target == t for s in self.sessions):
                self.fail(f'required target {t} has no complete session')

    def test_bootstrap_and_offsets(self):
        self._check('offsets', bootstrap=True)

    def test_gobjects(self):
        self._check('gobjects')

    def test_gobjects_with_properties(self):
        self._check('gobjects-props')

    def test_idmap(self):
        self._check('idmap')

    def test_stem(self):
        self._check('stem')

    def test_names(self):
        self._check('names')

    def test_counts(self):
        self._check('counts')

    def test_enums(self):
        self._check('enums')

    def test_props_exact(self):
        self._check('props-exact')

    def test_cdo_types(self):
        self._check('cdo-types')

    def test_dumpspace(self):
        self._check('dumpspace')

    def test_extra_from_snapshot(self):
        self._check('extra:from_snapshot')

    def test_extra_live_resolver(self):
        self._check('extra:live_resolver')


class PortRegressionTests(unittest.TestCase):
    """Regressions found by 6-G that need no capture; never skipped."""

    def _run_joined(self, fn):
        """Runs fn in a daemon thread joined for 10 s; returns its exception, or None."""
        import threading
        outcome = []

        def target():
            try:
                fn()
                outcome.append(None)
            except BaseException as ex:
                outcome.append(ex)
        thread = threading.Thread(target=target, daemon=True)
        thread.start()
        thread.join(10)
        self.assertFalse(thread.is_alive(), 'still running after 10 s')
        return outcome[0]

    @staticmethod
    def _engine_with_segment(base: int, data: bytes):
        """An Engine over the mapped sys._base_executable plus one segment at base."""
        from ..capture import ImageSource
        from ..engine.core import Engine
        from .pe_file import map_pe_file
        exe = map_pe_file(sys._base_executable)
        try:
            segments = [(r.base, exe.read(r.base, r.end - r.base)) for r in exe.regions()]
            modules = [exe.main_module]
        finally:
            exe.close()
        return Engine(ImageSource(segments + [(base, data)], modules))

    def test_cyclic_field_chain_raises(self):
        import struct
        from ..engine.unreal import UEStruct
        from ..errors import MemoryReadError
        from ..flags import EClassCastFlags
        base = 0x100000
        data = bytearray(0x400)
        struct.pack_into('<Q', data, 0x08, base + 0x100)                # UStruct::ChildProperties -> field A
        for field, next_field in ((0x100, 0x200), (0x200, 0x100)):      # A -> B -> A
            struct.pack_into('<Q', data, field + 0x08, base + 0x300)    # FField::Class
            struct.pack_into('<Q', data, field + 0x20, base + next_field)  # FField::Next
        struct.pack_into('<Q', data, 0x300 + 0x10, EClassCastFlags.Property)  # FFieldClass::CastFlags
        e = self._engine_with_segment(base, bytes(data))
        try:
            e.settings.Internal.bUseFProperty = True
            e.off.UStruct.ChildProperties = 0x08
            e.off.FField.Class, e.off.FField.Next = 0x08, 0x20
            e.off.FFieldClass.CastFlags = 0x10
            err = self._run_joined(UEStruct(e, base).get_properties)
            self.assertIsInstance(err, MemoryReadError)
            self.assertIn('exceeds 65536 links', err.reason)
        finally:
            e.mem.close()

    def test_cyclic_outer_chain_raises(self):
        import struct
        from unittest import mock
        from ..engine.unreal import UEObject
        from ..errors import MemoryReadError
        base = 0x100000
        data = bytearray(0x100)
        struct.pack_into('<Q', data, 0x20, base)  # UObject::Outer -> itself
        e = self._engine_with_segment(base, bytes(data))
        try:
            e.off.UObject.Class, e.off.UObject.Outer = 0x10, 0x20
            with mock.patch.object(UEObject, 'get_name', lambda self: 'Obj'):
                err = self._run_joined(UEObject(e, base).get_full_name)
            self.assertIsInstance(err, MemoryReadError)
            self.assertIn('exceeds 256 links', err.reason)
        finally:
            e.mem.close()

    @staticmethod
    def _outer_chain(base: int, count: int) -> bytes:
        """`count` outer hops from `base` (self); each node's Outer field holds the next node's address, the last holds 0."""
        import struct
        data = bytearray(0x20 * (count + 2))
        for j in range(1, count + 1):
            struct.pack_into('<Q', data, 0x20 * j, base + 0x20 * j)  # node (j-1)'s Outer == node j's address
        struct.pack_into('<Q', data, 0x20 * (count + 1), 0)  # node count's Outer: terminate
        return bytes(data)

    def test_outer_chain_bound(self):
        from ..engine.unreal import UEObject
        from ..errors import MemoryReadError
        base = 0x100000
        for count, raises in ((256, False), (257, True)):
            with self.subTest(count=count):
                e = self._engine_with_segment(base, self._outer_chain(base, count))
                try:
                    e.off.UObject.Class, e.off.UObject.Outer = 0x10, 0x20
                    if raises:
                        with self.assertRaises(MemoryReadError) as cm:
                            UEObject(e, base).get_outermost()
                        self.assertIn('exceeds 256 links', cm.exception.reason)
                    else:
                        outermost = UEObject(e, base).get_outermost()
                        self.assertEqual(outermost.address, base + 0x20 * count)
                finally:
                    e.mem.close()

    def test_a6_skips_unreadable_object(self):
        from unittest import mock
        from ..engine.core import Engine
        from ..engine.objects import ObjectArray
        from ..engine.unreal import UEObject
        from ..errors import MemoryReadError
        from .pe_file import map_pe_file
        image = map_pe_file(sys._base_executable)
        try:
            e = Engine(image)
            bad, actor = UEObject(e, 0x1000), UEObject(e, 0x2000)

            def name_of(full: bool):
                def get(obj):
                    if obj.address == bad.address:
                        raise MemoryReadError(obj.address, 8, 'unreadable object')
                    return 'Class /Script/Engine.Actor' if full else 'Actor'
                return get
            with mock.patch.object(ObjectArray, '__iter__', lambda self: iter([bad, actor])), \
                    mock.patch.object(UEObject, 'get_name', name_of(False)), \
                    mock.patch.object(UEObject, 'get_full_name', name_of(True)):
                self.assertEqual(e.objects.find_object_fast('Actor'), actor)
                self.assertEqual(e.objects.find_object('Class /Script/Engine.Actor'), actor)
            self.assertIn('A6: 1 unreadable objects left out of the name index\n', e.messages)
            self.assertIn('A6: 1 unreadable objects left out of the full index\n', e.messages)
        finally:
            image.close()

    def test_gnames_override_rejected(self):
        from ..engine.core import Engine
        from ..errors import DetectionError
        from .pe_file import map_pe_file
        image = map_pe_file(sys._base_executable)
        try:
            base = image.main_module.base
            rva = next(a - base for r in image.regions()[1:] for a in range(r.end - 0x20, r.base - 1, -0x20)
                       if image.read(a, 0x20) == bytes(0x20))
            e = Engine(image)
            with self.assertRaises(DetectionError) as cm:
                e.fname.init_override(rva, 'GNames', True)
            self.assertEqual(cm.exception.step, 'FName::Init')
            self.assertEqual(e.names.GNames, 0)
        finally:
            image.close()

    def test_deep_property_nesting_is_unreadable(self):
        from unittest import mock
        from ..engine.core import Engine
        from ..engine.unreal import UEArrayProperty, UEProperty
        from ..errors import MemoryReadError
        from ..flags import EClassCastFlags
        from ..reflect import Reflection
        from .pe_file import map_pe_file
        image = map_pe_file(sys._base_executable)
        try:
            e = Engine(image)
            prop = UEProperty(e, 0x1000)
            with mock.patch.object(UEProperty, 'get_cast_flags', lambda self: EClassCastFlags.ArrayProperty), \
                    mock.patch.object(UEProperty, 'get_prop_class_name', lambda self: 'ArrayProperty'), \
                    mock.patch.object(UEArrayProperty, 'get_inner_property', lambda self: UEProperty(self.e, self.address)):
                with self.assertRaises(MemoryReadError) as cm:
                    Reflection(e, None).prop_type(prop)
            self.assertEqual(cm.exception.address, prop.address)
            self.assertIn('exceeds 8 levels', cm.exception.reason)
        finally:
            image.close()

    def test_invalid_ansi_name_bytes_are_unreadable(self):
        import struct
        from ..engine.gnames import FNameEntry
        from ..errors import MemoryReadError
        base = 0x100000
        data = bytearray(0x10)
        struct.pack_into('<H', data, 0x0, 1 << 6)  # header: ANSI, length 1 at shift 6
        data[0x2] = 0xA9
        e = self._engine_with_segment(base, bytes(data))
        try:
            e.settings.Internal.bUseNamePool = True
            e.off.FNameEntry.NamePool.HeaderOffset, e.off.FNameEntry.NamePool.StringOffset = 0x0, 0x2
            e.names.FNameEntryLengthShiftCount = 6
            e.names._GetStr = e.names._get_str_name_pool
            with self.assertRaises(MemoryReadError) as cm:
                FNameEntry(e, base).get_wstring()
            self.assertEqual(cm.exception.address, base)
            self.assertIn('not valid UTF-8', cm.exception.reason)
        finally:
            e.mem.close()

    def test_invalid_ansi_name_array_bytes_are_unreadable(self):
        import struct
        from ..engine.gnames import FNameEntry
        from ..errors import MemoryReadError
        base = 0x100000
        data = bytearray(0x1000)  # _read_until_nul reads up to the page end
        struct.pack_into('<i', data, 0x0, 3 << 1)  # index 3, narrow
        data[0x4] = 0xA9
        e = self._engine_with_segment(base, bytes(data))
        try:
            e.settings.Internal.bUseNamePool = False
            e.off.FNameEntry.NameArray.IndexOffset, e.off.FNameEntry.NameArray.StringOffset = 0x0, 0x4
            e.names._GetStr = e.names._get_str_name_array
            with self.assertRaises(MemoryReadError) as cm:
                FNameEntry(e, base).get_wstring()
            self.assertEqual(cm.exception.address, base)
            self.assertIn('not valid UTF-8', cm.exception.reason)
        finally:
            e.mem.close()

    def test_stem_skips_bad_candidate(self):
        import struct
        from ..capture import ImageSource
        from ..engine.core import Engine
        from ..engine.stem import detect_stem
        from .pe_file import map_pe_file

        def candidate(x, y, patch, changelist, data_ptr, num_elements, max_elements):
            buf = bytearray(0x20)
            struct.pack_into('<HH', buf, 0x0, x, y)
            struct.pack_into('<H', buf, 0x4, patch)
            struct.pack_into('<I', buf, 0x8, changelist)
            struct.pack_into('<Q', buf, 0x10, data_ptr)
            struct.pack_into('<i', buf, 0x18, num_elements)
            struct.pack_into('<i', buf, 0x1C, max_elements)
            return bytes(buf)

        src = map_pe_file(sys._base_executable)
        try:
            image = ImageSource([(r.base, src.read(r.base, r.size)) for r in src.regions()], list(src.modules()), writable=True)
        finally:
            src.close()
        try:
            e = Engine(image)
            section = max((s for s in e.platform.image.sections if s.writable and s.characteristics & 0x40000000), key=lambda s: s.size)
            branch = '++UE5+Release-5.4'
            branch_addr = section.address + 0x100
            image.write(branch_addr, branch.encode('utf-16-le') + b'\x00\x00')
            bad_addr, good_addr = section.address + 0x40, section.address + 0x80
            image.write(bad_addr, candidate(5, 4, 4, 35576357, image.main_module.base + 0x7FFF0000, 1, 1))  # Data unmapped
            image.write(good_addr, candidate(5, 4, 4, 35576357, branch_addr, len(branch) + 1, len(branch) + 1))

            stem = detect_stem(e)
            self.assertEqual(stem.engine_version, '5.4.4-35576357+++UE5+Release-5.4')
            self.assertEqual(e.provenance['Settings.Generator.GameVersion'], 'auto: FEngineVersion::Current (memory)')
        finally:
            image.close()

    def test_stem_skips_bad_candidate_only(self):
        import struct
        from ..capture import ImageSource
        from ..engine.core import Engine
        from ..engine.stem import detect_stem
        from .pe_file import map_pe_file

        def candidate(x, y, patch, changelist, data_ptr, num_elements, max_elements):
            buf = bytearray(0x20)
            struct.pack_into('<HH', buf, 0x0, x, y)
            struct.pack_into('<H', buf, 0x4, patch)
            struct.pack_into('<I', buf, 0x8, changelist)
            struct.pack_into('<Q', buf, 0x10, data_ptr)
            struct.pack_into('<i', buf, 0x18, num_elements)
            struct.pack_into('<i', buf, 0x1C, max_elements)
            return bytes(buf)

        src = map_pe_file(sys._base_executable)
        try:
            image = ImageSource([(r.base, src.read(r.base, r.size)) for r in src.regions()], list(src.modules()), writable=True)
        finally:
            src.close()
        try:
            e = Engine(image)
            section = max((s for s in e.platform.image.sections if s.writable and s.characteristics & 0x40000000), key=lambda s: s.size)
            branch = '++UE5+Release-5.4'
            branch_addr = section.address + 0x100
            image.write(branch_addr, branch.encode('utf-16-le') + b'\x00\x00')
            bad_addr = section.address + 0x40
            image.write(bad_addr, candidate(5, 4, 4, 35576357, image.main_module.base + 0x7FFF0000, 1, 1))  # Data unmapped

            detect_stem(e)
            stem_messages = [m for m in e.messages if 'FEngineVersion::Current (memory)' in m]
            self.assertEqual(len(stem_messages), 1, stem_messages)
            self.assertIn('0 candidates', stem_messages[0])
            self.assertIn('1 skipped', stem_messages[0])
        finally:
            image.close()

    def test_from_snapshot_rejects_decrypted(self):
        import copy
        from ..engine.context import EngineContext
        from ..engine.core import Engine
        from ..engine.stem import Stem
        from ..errors import DetectionError
        from .pe_file import map_pe_file
        image = map_pe_file(sys._base_executable)
        try:
            e = Engine(image)
            e.objects.GObjects = image.main_module.base + 0x2000
            ctx = EngineContext(e, Stem(engine_version='5.4.4-0+branch', game_name='Test'))

            meta = ctx.to_meta()
            self.assertFalse(meta['globals']['GObjects']['decrypted'])
            e.objects.init_decryption(lambda p: p, 'test')
            meta = ctx.to_meta()
            self.assertTrue(meta['globals']['GObjects']['decrypted'])

            offsets = ctx.to_offsets()
            meta['target']['engine_version_from'] = 'test'
            meta['target']['game_name_from'] = 'test'
            with self.assertRaises(DetectionError) as cm:
                EngineContext.from_snapshot(meta, offsets, image)
            self.assertEqual(cm.exception.step, 'EngineContext.from_snapshot')
            self.assertIn('decrypt', cm.exception.detail)

            for mutate in (
                lambda m: m.__setitem__('globals', None),
                lambda m: m['globals'].__setitem__('GObjects', None),
                lambda m: m['globals']['GObjects'].__setitem__('decrypted', None),
            ):
                with self.subTest(mutate=mutate):
                    bad_meta = copy.deepcopy(meta)
                    mutate(bad_meta)
                    with self.assertRaises(ValueError) as cm:
                        EngineContext.from_snapshot(bad_meta, offsets, image)
                    self.assertIn('globals.GObjects.decrypted', str(cm.exception))
        finally:
            image.close()

    def test_gobjects_changed_row_fails(self):
        from . import port
        from .oracle import GObjectsDump
        rows = [(i, 0x1000 + i, f'Class /Script/Engine.Obj{i}') for i in range(10001)]
        oracle = GObjectsDump(line1='x', stem='', count=len(rows), rows=rows, props={})
        ours_rows = list(rows)
        ours_rows[-1] = (ours_rows[-1][0], ours_rows[-1][1], 'Class /Script/Engine.Changed')
        ours = GObjectsDump(line1='x', stem='', count=len(ours_rows), rows=ours_rows, props={})
        dr = port.compare_gobjects_capture(ours, oracle, target='pal', check='gobjects')
        self.assertFalse(dr.ok)
        self.assertEqual(dr.changed, 1)

    def test_dumpspace_detects_differences(self):
        from . import port
        from ..flags import EFunctionFlags, EPropertyFlags
        from ..model import ClassRecord, PropertyRecord, PropType

        def make():
            prop_score = PropertyRecord(name='Score', offset=0, size=4, array_dim=1, flags=0,
                                        type=PropType(prop='IntProperty', kind='IntProperty'), address=None)
            prop_flag = PropertyRecord(name='bFlag', offset=4, size=1, array_dim=1, flags=0,
                                       type=PropType(prop='BoolProperty', kind='BoolProperty', field_size=1, byte_offset=0,
                                                     byte_mask=1, field_mask=0x02), address=None)
            rec_base = ClassRecord(path='/Script/Test.Base', name='Base', cpp_name='UBase', package='/Script/Test',
                                   super=None, size=8, min_alignment=8, properties=[], address=None)
            rec_child = ClassRecord(path='/Script/Test.Child', name='Child', cpp_name='UChild', package='/Script/Test',
                                    super='/Script/Test.Base', size=16, min_alignment=8,
                                    properties=[prop_score, prop_flag], address=None)
            param_in = PropertyRecord(name='InVal', offset=0, size=4, array_dim=1, flags=int(EPropertyFlags.Parm),
                                      type=PropType(prop='IntProperty', kind='IntProperty'), address=None)
            param_out = PropertyRecord(name='OutVal', offset=4, size=4, array_dim=1, flags=int(EPropertyFlags.Parm),
                                       type=PropType(prop='IntProperty', kind='IntProperty'), address=None)
            fn = port.FunctionRecord(path='/Script/Test.Child:DoThing', name='DoThing', package='/Script/Test',
                                     flags=int(EFunctionFlags.Native | EFunctionFlags.BlueprintCallable), params_size=8,
                                     params=[param_in, param_out], exec_rva=0x1234, address=None)
            rec_child.functions = {'DoThing': fn}
            flags_str = port._stringify_function_flags(fn.flags)
            oracle = port.DumpspaceTypes(
                types={
                    'UBase': [[{'__InheritInfo': []}, {'__MDKClassSize': 8}]],
                    'UChild': [[{'__InheritInfo': ['UBase']}, {'__MDKClassSize': 16},
                                {'Score': [['int32', 'D', '', []], 0, 4, 1]},
                                {'bFlag': [['uint8', 'D', '', []], 4, 1, 1, 1]}]],
                },
                functions={'UChild': [[{'DoThing': [['void', 'D', '', []],
                                                     [[['int32', 'D', '', []], '', 'InVal'],
                                                      [['int32', 'D', '', []], '', 'OutVal']], 0x1234, flags_str]}]]},
            )
            return rec_base, rec_child, oracle

        rec_base, rec_child, oracle = make()
        dr = port.compare_dumpspace([rec_base, rec_child], oracle, target='pal', min_types=0, min_members=0)
        self.assertEqual(dr.changed, 0, dr.samples)

        def mutated(mutate):
            rec_base, rec_child, oracle = make()
            mutate(rec_base, rec_child, oracle)
            return port.compare_dumpspace([rec_base, rec_child], oracle, target='pal', min_types=0, min_members=0)

        mutations = {
            'member offset': lambda b, c, o: setattr(c.properties[0], 'offset', 99),
            'member size': lambda b, c, o: setattr(c.properties[0], 'size', 99),
            'array_dim': lambda b, c, o: setattr(c.properties[0], 'array_dim', 2),
            'bit index': lambda b, c, o: o.types['UChild'][0].__setitem__(
                3, {'bFlag': [['uint8', 'D', '', []], 4, 1, 1, 7]}),
            'member type name': lambda b, c, o: (setattr(c.properties[0].type, 'kind', 'FloatProperty'),
                                                 setattr(c.properties[0].type, 'prop', 'FloatProperty')),
            'function flag': lambda b, c, o: setattr(next(iter(c.functions.values())), 'flags', int(EFunctionFlags.Native)),
            'exec offset': lambda b, c, o: setattr(next(iter(c.functions.values())), 'exec_rva', 0x9999),
            'parameter order': lambda b, c, o: o.functions['UChild'][0].__setitem__(
                0, {'DoThing': [['void', 'D', '', []],
                                [[['int32', 'D', '', []], '', 'OutVal'], [['int32', 'D', '', []], '', 'InVal']],
                                0x1234, port._stringify_function_flags(int(EFunctionFlags.Native | EFunctionFlags.BlueprintCallable))]}),
            'super-chain entry': lambda b, c, o: o.types['UChild'].__setitem__(
                0, [{'__InheritInfo': ['UOther']}] + o.types['UChild'][0][1:]),
            '__MDKClassSize': lambda b, c, o: o.types['UChild'][0].__setitem__(1, {'__MDKClassSize': 999}),
        }
        for label, mutate in mutations.items():
            with self.subTest(mutation=label):
                dr = mutated(mutate)
                self.assertEqual(dr.changed, 1, f'{label}: {dr.samples}')


if __name__ == '__main__':
    unittest.main()
