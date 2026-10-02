"""Capture-free guards for nylib.ue.runtime (## Guards, G9.1-G9.8): never skip. Most build a fake
RuntimeContext (RT0's duck-typed members) over a writable in-memory ImageSource, as the frozen node
describes; G9.3's second case and G9.8 use a real child process and a real on-disk snapshot.
See test_runtime_captures.py for the capture-backed checks (G9.9, G9.10, ## Verification)."""
import datetime
import subprocess
import sys
import tempfile
import threading
import time
import types
import unittest
from unittest import mock

from ... import ctype
from .. import errors, memory, pipeline, runtime, snapshot, store
from ..capture import ImageSource
from ..engine.accessor import SourceAccessor, view as accessor_view
from ..engine.state import Off, PropertySizes, Settings
from ..model import ClassRecord, EnumRecord, ObjectRecord, ObjectTable, PropType, PropertyRecord, StructRecord
from ..runtime import accessor as rt_accessor
from ..runtime import codecs as rt_codecs
from ..runtime import containers as rt_containers
from ..runtime import index as rt_index
from ..runtime import names as rt_names
from ..runtime import session
from ..runtime import types as rt_types

_IMAGE_BASE = 0x10000
_IMAGE_SIZE = 0x200000


def _make_image() -> ImageSource:
    return ImageSource([(_IMAGE_BASE, bytearray(_IMAGE_SIZE))], writable=True)


def _fake_target_info(*, exe='Game-Win64-Shipping.exe', pe_timestamp=0xAAAAAAAA, size_of_image=0x3000,
                      module_base=0x140000000) -> pipeline.TargetInfo:
    return pipeline.TargetInfo(mode='external', pid=4242, exe=exe, exe_path='', exe_sha256=None,
                               module_base=module_base, size_of_image=size_of_image, pe_timestamp=pe_timestamp,
                               file_version=None, version_info=None)


class _FakeTypeSource:
    """RT3 duck type: `records` is filled by the test directly (path -> TypeRecord)."""

    def __init__(self):
        self.records = {}

    def type(self, path, address=None):
        return self.records.get(path)

    def path_of(self, address):
        return None

    def note(self, path, address):
        pass

    def refresh(self):
        self.records.clear()


class _FakeIndex:
    """RT2 duck type: enough for ClassFactory's super-chain fallback, never exercised by these guards."""

    def super_chain(self, address):
        return ()


class _FakeNames:
    """RT1 duck type over a small (comparison_index, number) -> text table, read through `acc`."""

    def __init__(self, acc: SourceAccessor):
        self.acc = acc
        self.table = {}

    def add(self, comparison_index: int, number: int, text: str) -> None:
        self.table[(comparison_index, number)] = text

    def decode(self, comparison_index: int, number: int) -> str:
        try:
            return self.table[(comparison_index, number)]
        except KeyError:
            raise ValueError(f'FName comparison index {comparison_index:#x} is outside the name pool')

    def read(self, address: int):
        from ..runtime.names import FNameValue
        raw = self.acc.read(address, 8)
        c = int.from_bytes(raw[0:4], 'little', signed=True)
        n = int.from_bytes(raw[4:8], 'little', signed=False)
        return FNameValue(self.decode(c, n), c, n, raw)

    def lookup(self, text: str):
        from ..runtime.names import FNameValue
        for (c, n), t in self.table.items():
            if t == text:
                raw = c.to_bytes(4, 'little', signed=True) + n.to_bytes(4, 'little', signed=False)
                return FNameValue(text, c, n, raw)
        return None


class _FakeContext:
    """RT0 duck type over a writable in-memory ImageSource, for the codec/container/type guards."""

    def __init__(self, image: ImageSource, *, write: bool = True):
        self.image = image
        self.acc = SourceAccessor(image)
        e = types.SimpleNamespace()
        e.off = Off()
        e.off.InSDK.Name.FNameSize = 8
        e.settings = Settings()
        e.property_sizes = PropertySizes()
        e.acc = self.acc
        e.mem = image
        self.e = e
        self.write = write
        self.calls = None
        self.mode = 'capture'
        self.closed = False
        self.lock = threading.RLock()
        self.names = _FakeNames(self.acc)
        self.types = _FakeTypeSource()
        self.index = _FakeIndex()
        self.factory = None

    def proxy(self, address):
        if not isinstance(address, int):
            raise TypeError(f'address must be int, got {type(address).__name__}')
        if address == 0:
            return None
        raise NotImplementedError('_FakeContext.proxy: not exercised by these guards')

    def struct_view(self, path, address):
        raise NotImplementedError('_FakeContext.struct_view: not exercised by these guards')

    def raw_view(self, address):
        raise NotImplementedError('_FakeContext.raw_view: not exercised by these guards')

    def enum_class(self, path):
        return None

    def is_subclass(self, path, base):
        return path == base

    def weak_get(self, index, serial):
        return None

    def weak_ref(self, obj):
        return (0, 0)

    def text_layout(self):
        raise NotImplementedError('_FakeContext.text_layout: not exercised by these guards')

    def check_write(self, label: str) -> None:
        if self.closed:
            raise errors.SessionError('the session is closed')
        if not self.write:
            raise errors.ReadOnlySessionError(
                f'cannot write {label}: the session is read-only. Attach with write=True '
                f'(opens the target with VM_WRITE | VM_OPERATION).', member=label)

    def invoke(self, obj, fn, args, kwargs):
        raise NotImplementedError('_FakeContext.invoke: not exercised by these guards')


_CHILD_SRC = (
    "import ctypes, os, sys\n"
    "buf = ctypes.create_string_buffer(64)\n"
    "print(f'{os.getpid()} {ctypes.addressof(buf)}', flush=True)\n"
    "sys.stdin.read()\n"
)


class _Child:
    """A spawned python holding one writable heap buffer at .addr (G9.3's handle-rights check)."""

    def __enter__(self):
        self.popen = subprocess.Popen([getattr(sys, '_base_executable', sys.executable), '-c', _CHILD_SRC],
                                      stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        try:
            pid, addr = self.popen.stdout.readline().split()
        except BaseException:
            self._kill()
            raise
        self.pid, self.addr = int(pid), int(addr)
        return self

    def _kill(self):
        if self.popen.poll() is None:
            self.popen.kill()
        self.popen.wait()
        self.popen.stdin.close()
        self.popen.stdout.close()

    def __exit__(self, *exc):
        self._kill()


class UnverifiedGateTests(unittest.TestCase):
    """G9.1: D13 is literal (root Q33 = B, amended) -- no probed offset is exempt from the write gate."""

    def test_direct_raises_for_any_key(self):
        for key in ('Off.UStruct.MinAlignment', 'Off.InSDK.Text.TextDatOffset'):
            with self.subTest(key=key):
                with self.assertRaises(errors.UnverifiedOffsetsError) as cm:
                    session.unverified_gate([key], write=True, allow_unverified=False)
                self.assertEqual(cm.exception.keys, (key,))

    def test_direct_returns_without_raising_when_not_writing(self):
        gating = session.unverified_gate(['Off.UStruct.MinAlignment'], write=False, allow_unverified=False)
        self.assertEqual(gating, ('Off.UStruct.MinAlignment',))

    def test_direct_returns_without_raising_when_allowed(self):
        gating = session.unverified_gate(['Off.UStruct.MinAlignment'], write=True, allow_unverified=True)
        self.assertEqual(gating, ('Off.UStruct.MinAlignment',))

    def test_live_attach_gates_before_from_snapshot(self):
        key = 'Off.InSDK.Text.TextDatOffset'
        info = _fake_target_info()

        def open_target(target, *, write, remote_calls, cache_bytes):
            return pipeline.OpenedTarget(source=_make_image(), info=info, process=None,
                                         check_alive=lambda: True, closer=lambda: None)

        report = pipeline.ProbeReport(
            ok=True, target=info, profile=None, profile_note='none', values=(), unverified=(key,),
            steps=('objects', 'names', 'engine'), error=None, explanations=(), game_name='G',
            game_name_from='auto: x', engine_version='5.1', engine_version_from='auto: x', stem='5.1-G',
            warnings=(), seconds=0.01,
            context=mock.Mock(to_meta=mock.Mock(return_value={'globals': {'GObjects': {'decrypted': False}}})))

        with mock.patch('nylib.ue.pipeline.probe_opened', return_value=report) as m_probe, \
             mock.patch('nylib.ue.engine.context.EngineContext.from_snapshot') as m_from_snapshot:
            with tempfile.TemporaryDirectory() as root:
                with self.assertRaises(errors.UnverifiedOffsetsError) as cm:
                    runtime.Unreal.attach(1, write=True, out=root, _open_target=open_target)
        self.assertIn(key, cm.exception.keys)
        m_probe.assert_called_once()
        m_from_snapshot.assert_not_called()

    def test_dump_auto_gates_before_snapshot_load(self):
        key = 'Off.InSDK.Text.InTextDataStringOffset'
        info = _fake_target_info()

        def open_target(target, *, write, remote_calls, cache_bytes):
            return pipeline.OpenedTarget(source=_make_image(), info=info, process=None,
                                         check_alive=lambda: True, closer=lambda: None)

        dump_result = pipeline.DumpResult(path='<fake-dump-path>', target=info, report=mock.Mock(), counts={},
                                          unverified=(key,), exports=(), export_paths=(), warnings=(), seconds=0.01)

        with mock.patch('nylib.ue.store.find_snapshots', return_value=[]), \
             mock.patch('nylib.ue.pipeline.dump', return_value=dump_result) as m_dump, \
             mock.patch('nylib.ue.snapshot.Snapshot.load') as m_load:
            with tempfile.TemporaryDirectory() as root:
                with self.assertRaises(errors.UnverifiedOffsetsError) as cm:
                    runtime.Unreal.attach(1, write=True, dump='auto', out=root, _open_target=open_target)
        self.assertIn(key, cm.exception.keys)
        m_dump.assert_called_once()
        m_load.assert_not_called()


class ReadOnlyTests(unittest.TestCase):
    """G9.2: a read-only session must refuse every write, at both gates (descriptor codec and accessor)."""

    def test_codec_set_refused(self):
        image = _make_image()
        ctx = _FakeContext(image, write=False)
        addr = _IMAGE_BASE + 0x100
        image.write(addr, (7).to_bytes(4, 'little', signed=True))
        codec = rt_codecs.make_codec(ctx, PropType('IntProperty', 'IntProperty'))
        before = image.read(addr, 4)
        with self.assertRaises(errors.ReadOnlySessionError):
            codec.set(ctx, addr, 9, 'Test.Int')
        self.assertEqual(image.read(addr, 4), before)

    def test_accessor_write_refused(self):
        image = _make_image()
        ctx = _FakeContext(image, write=False)
        acc = rt_accessor.RuntimeAccessor(image)
        acc.ctx = ctx
        addr = _IMAGE_BASE + 0x200
        image.write(addr, bytes(4))
        before = image.read(addr, 4)
        with self.assertRaises(errors.ReadOnlySessionError):
            acc.write(addr, b'\xff\xff\xff\xff')
        self.assertEqual(image.read(addr, 4), before)

    def test_real_context_check_write_text(self):
        image = _make_image()
        addr = _IMAGE_BASE + 0x220
        image.write(addr, (7).to_bytes(4, 'little', signed=True))
        external = ' (opens the target with VM_WRITE | VM_OPERATION).'
        for mode, tail in (('external', external), ('capture', external), ('internal', '.')):
            with self.subTest(mode=mode):
                ctx = session.RuntimeContext(_FakeContext(image).e, write=False, calls=None, mode=mode)
                ctx.acc = rt_accessor.RuntimeAccessor(image)
                ctx.acc.ctx = ctx
                codec = rt_codecs.make_codec(ctx, PropType('IntProperty', 'IntProperty'))
                before = image.read(addr, 4)
                with self.assertRaises(errors.ReadOnlySessionError) as cm:
                    codec.set(ctx, addr, 9, 'Actor.Health')
                self.assertEqual(str(cm.exception), f'cannot write Actor.Health: the session is read-only. Attach with write=True{tail}')
                self.assertEqual(cm.exception.member, 'Actor.Health')
                self.assertEqual(image.read(addr, 4), before)


class HandleRightsTests(unittest.TestCase):
    """G9.3: a session must open the target with exactly its declared policy's rights, no more."""

    def test_policies_recorded(self):
        class _Sentinel(Exception):
            pass

        calls = []

        def spy(target, *, write, remote_calls, cache_bytes):
            calls.append((write, remote_calls))
            raise _Sentinel()

        cases = [
            (dict(write=False, calls=None), (False, False)),
            (dict(write=True, calls=None), (True, False)),
            (dict(write=False, calls='remote-thread'), (False, True)),
        ]
        for kwargs, expected in cases:
            with self.subTest(**kwargs):
                with self.assertRaises(_Sentinel):
                    runtime.Unreal.attach(1, _open_target=spy, **kwargs)
                self.assertEqual(calls[-1], expected)

    def test_insufficient_rights_refuse_write(self):
        with _Child() as child:
            process = memory.open_process(child.pid, write=False)
            try:
                source = memory.ProcessSource(process)
                self.assertEqual(source.read(child.addr, 4), bytes(4))  # the buffer is readable
                with self.assertRaises(errors.MemoryWriteError) as cm:
                    source.write(child.addr, b'\x01\x02\x03\x04')
                self.assertIn('winerror 5', cm.exception.reason)
            finally:
                process.close()

    def test_open_target_read_only_refuses_write(self):
        with _Child() as child:
            opened = pipeline.open_target(child.pid)
            try:
                self.assertEqual(opened.source.read(child.addr, 4), bytes(4))
                with self.assertRaises(errors.MemoryWriteError) as cm:
                    opened.source.write(child.addr, b'\x01\x02\x03\x04')
                self.assertIn('winerror 5', cm.exception.reason)
            finally:
                opened.close()


class NoLocalAccessorTests(unittest.TestCase):
    """G9.4: a dynamic class must never construct without a real target address and accessor."""

    def test_self_alloc_and_bad_accessor_refused(self):
        image = _make_image()
        ctx = _FakeContext(image)
        rec = StructRecord(path='/Script/Engine.Vector', name='Vector', cpp_name='FVector',
                           package='/Script/Engine', super=None, size=0xC, min_alignment=4, properties=[])
        ctx.types.records[rec.path] = rec
        factory = rt_types.ClassFactory(ctx)
        cls = factory.struct_for(rec.path)

        with self.assertRaises(TypeError):
            cls()
        with self.assertRaises(TypeError):
            cls(_address_=_IMAGE_BASE + 0x10)
        with self.assertRaises(TypeError):
            cls(_address_=_IMAGE_BASE + 0x10, _accessor_=object())

        view = accessor_view(cls, _IMAGE_BASE + 0x10, ctx.acc)
        with self.assertRaises(TypeError):
            ctype.copy(view)

    def test_proxy_and_raw_bases_refused(self):
        image = _make_image()
        ctx = _FakeContext(image)
        rec = ClassRecord(path='/Script/Engine.Actor', name='Actor', cpp_name='AActor',
                          package='/Script/Engine', super=None, size=8, min_alignment=8, properties=[])
        ctx.types.records[rec.path] = rec
        factory = rt_types.ClassFactory(ctx)
        for cls in (factory.class_for(rec.path), factory.base_proxy(), factory.raw_class()):
            with self.subTest(cls=cls.__name__):
                with self.assertRaises(TypeError):
                    cls()
                with self.assertRaises(TypeError):
                    cls(_address_=_IMAGE_BASE + 0x10)
                with self.assertRaises(TypeError):
                    cls(_address_=_IMAGE_BASE + 0x10, _accessor_=object())
                view = accessor_view(cls, _IMAGE_BASE + 0x10, ctx.acc)
                with self.assertRaises(TypeError):
                    ctype.copy(view)


class UnknownMemberTests(unittest.TestCase):
    """G9.5: a mistyped member assignment must raise, not silently become a stray python attribute."""

    def test_typo_assignment_raises(self):
        image = _make_image()
        ctx = _FakeContext(image)
        addr = _IMAGE_BASE + 0x300
        prop = PropertyRecord(name='TimeDilation', offset=0, size=4, array_dim=1, flags=0,
                              type=PropType('FloatProperty', 'FloatProperty'))
        rec = ClassRecord(path='/Script/Engine.Actor', name='Actor', cpp_name='AActor',
                          package='/Script/Engine', super=None, size=4, min_alignment=4, properties=[prop])
        ctx.types.records[rec.path] = rec
        factory = rt_types.ClassFactory(ctx)
        cls = factory.class_for(rec.path)
        obj = accessor_view(cls, addr, ctx.acc)

        before = image.read(addr, 4)
        with self.assertRaises(AttributeError):
            obj.CustomTimeDilaton = 2.0
        self.assertEqual(image.read(addr, 4), before)


class BoolBitTests(unittest.TestCase):
    """G9.6: a bitfield write must touch only its own bit; a native bool only writes 1 or 0."""

    def test_bitfield_preserves_neighbor_bits(self):
        image = _make_image()
        ctx = _FakeContext(image)
        addr = _IMAGE_BASE + 0x400
        image.write(addr, bytes([0xFB]))
        ptype = PropType('BoolProperty', 'BoolProperty', field_size=1, byte_offset=0, byte_mask=0x04, field_mask=0x04)
        codec = rt_codecs.make_codec(ctx, ptype, size=1)
        self.assertFalse(codec.get(ctx, addr, 'Test.Bit'))
        codec.set(ctx, addr, True, 'Test.Bit')
        self.assertEqual(image.read(addr, 1), bytes([0xFF]))
        codec.set(ctx, addr, False, 'Test.Bit')
        self.assertEqual(image.read(addr, 1), bytes([0xFB]))

    def test_native_bool_writes_one_or_zero(self):
        image = _make_image()
        ctx = _FakeContext(image)
        addr = _IMAGE_BASE + 0x410
        image.write(addr, bytes([0x7F]))
        ptype = PropType('BoolProperty', 'BoolProperty', field_size=1, byte_offset=0, byte_mask=0x01, field_mask=0xFF)
        codec = rt_codecs.make_codec(ctx, ptype, size=1)
        codec.set(ctx, addr, True, 'Test.Native')
        self.assertEqual(image.read(addr, 1), bytes([1]))
        codec.set(ctx, addr, False, 'Test.Native')
        self.assertEqual(image.read(addr, 1), bytes([0]))


class GrowthTests(unittest.TestCase):
    """G9.7: a write past a container's current capacity must be refused, not overrun the buffer."""

    def test_string_overflow_refused(self):
        image = _make_image()
        ctx = _FakeContext(image)
        buf_addr = _IMAGE_BASE + 0x1000
        hdr_addr = _IMAGE_BASE + 0x1100
        image.write(buf_addr, 'abc\0'.encode('utf-16-le'))  # 4 units: capacity exactly fits 'abc' + NUL
        image.write(hdr_addr, buf_addr.to_bytes(8, 'little'))
        image.write(hdr_addr + 8, (4).to_bytes(4, 'little', signed=True))
        image.write(hdr_addr + 0xC, (4).to_bytes(4, 'little', signed=True))
        codec = rt_containers.string_codec(ctx, 'StrProperty')
        self.assertEqual(codec.get(ctx, hdr_addr, 'Test.Str'), 'abc')

        before = image.read(buf_addr, 8) + image.read(hdr_addr, 0x10)
        with self.assertRaises(ValueError):
            codec.set(ctx, hdr_addr, 'abcd', 'Test.Str')  # needs 5 units (4 chars + NUL), only 4 fit
        self.assertEqual(image.read(buf_addr, 8) + image.read(hdr_addr, 0x10), before)

    def test_array_overflow_refused(self):
        image = _make_image()
        ctx = _FakeContext(image)
        data_addr = _IMAGE_BASE + 0x1200
        hdr_addr = _IMAGE_BASE + 0x1300
        for i in range(2):
            image.write(data_addr + i * 4, (i + 1).to_bytes(4, 'little', signed=True))
        image.write(hdr_addr, data_addr.to_bytes(8, 'little'))
        image.write(hdr_addr + 8, (2).to_bytes(4, 'little', signed=True))
        image.write(hdr_addr + 0xC, (2).to_bytes(4, 'little', signed=True))
        inner = rt_codecs.make_codec(ctx, PropType('IntProperty', 'IntProperty'))
        codec = rt_containers.array_codec(ctx, inner)
        self.assertEqual(codec.get(ctx, hdr_addr, 'Test.Array').to_list(), [1, 2])

        before = image.read(data_addr, 8) + image.read(hdr_addr, 0x10)
        with self.assertRaises(ValueError):
            codec.set(ctx, hdr_addr, [1, 2, 3], 'Test.Array')  # 3 elements, only 2 (Max) fit
        self.assertEqual(image.read(data_addr, 8) + image.read(hdr_addr, 0x10), before)

    def test_map_new_key_refused(self):
        image = _make_image()
        ctx = _FakeContext(image)
        pair_addr = _IMAGE_BASE + 0x1400
        hdr_addr = _IMAGE_BASE + 0x1500
        # TPair<IntProperty, IntProperty>: key @0, value @4 (align(4,4)), pair size align(8,4) = 8.
        image.write(pair_addr, (5).to_bytes(4, 'little', signed=True))
        image.write(pair_addr + 4, (42).to_bytes(4, 'little', signed=True))
        image.write(hdr_addr, pair_addr.to_bytes(8, 'little'))             # Data.Data
        image.write(hdr_addr + 8, (1).to_bytes(4, 'little', signed=True))  # Data.NumElements
        image.write(hdr_addr + 0xC, (1).to_bytes(4, 'little', signed=True))  # Data.MaxElements
        image.write(hdr_addr + 0x10, (1).to_bytes(4, 'little'))            # AllocationFlags word0: slot 0 set
        image.write(hdr_addr + 0x14, bytes(4))
        image.write(hdr_addr + 0x18, bytes(4))
        image.write(hdr_addr + 0x1C, bytes(4))
        image.write(hdr_addr + 0x20, bytes(8))                            # secondary bit pointer: 0 (use inline)
        image.write(hdr_addr + 0x28, (1).to_bytes(4, 'little', signed=True))  # NumBits
        image.write(hdr_addr + 0x2C, (1).to_bytes(4, 'little', signed=True))  # MaxBits
        image.write(hdr_addr + 0x30, (-1).to_bytes(4, 'little', signed=True))  # FirstFreeIndex
        image.write(hdr_addr + 0x34, bytes(4))                            # NumFreeIndices
        image.write(hdr_addr + 0x38, bytes(0x10))                         # Hash
        image.write(hdr_addr + 0x48, bytes(4))                            # HashSize

        key_codec = rt_codecs.make_codec(ctx, PropType('IntProperty', 'IntProperty'))
        value_codec = rt_codecs.make_codec(ctx, PropType('IntProperty', 'IntProperty'))
        codec = rt_containers.map_codec(ctx, key_codec, value_codec)
        tmap = codec.get(ctx, hdr_addr, 'Test.Map')
        self.assertEqual(tmap[5], 42)

        before = image.read(pair_addr, 8) + image.read(hdr_addr, 0x50)
        with self.assertRaises(NotImplementedError):
            tmap[7] = 1  # a key not already present
        self.assertEqual(image.read(pair_addr, 8) + image.read(hdr_addr, 0x50), before)


class BuildBindingTests(unittest.TestCase):
    """G9.8: a snapshot or a live target from another build must never be accepted silently."""

    def test_pe_timestamp_mismatch_refused(self):
        with tempfile.TemporaryDirectory() as root:
            exe = 'Game-Win64-Shipping.exe'
            when = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
            folder = store.new_snapshot_dir(root, 'Synthetic', when)
            meta = {'target': {
                'exe': exe, 'module': {'base': '0x140000000', 'size': '0x3000', 'pe_timestamp': '0xAAAAAAAA'},
                'game_name': 'Synthetic', 'engine_version': '5.1',
            }}
            snapshot.write_snapshot(folder, meta, {}, [], [], [])
            store.publish(folder, [])

            info = _fake_target_info(exe=exe, pe_timestamp=0xBBBBBBBB, size_of_image=0x3000, module_base=0x140000000)

            def open_target(target, *, write, remote_calls, cache_bytes):
                return pipeline.OpenedTarget(source=_make_image(), info=info, process=None,
                                             check_alive=lambda: True, closer=lambda: None)

            with self.assertRaises(errors.DumpMismatchError):
                runtime.Unreal.attach(1, dump='latest', out=root, _open_target=open_target)
            with self.assertRaises(errors.DumpMismatchError):
                runtime.Unreal.attach(1, dump=folder, out=root, _open_target=open_target)

    def test_mismatch_texts(self):
        with tempfile.TemporaryDirectory() as root:
            exe = 'Game-Win64-Shipping.exe'
            folder = store.new_snapshot_dir(root, 'Synthetic', datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc))
            meta = {'target': {
                'exe': exe, 'module': {'base': '0x140000000', 'size': '0x3000', 'pe_timestamp': '0xAAAAAAAA'},
                'game_name': 'Synthetic', 'engine_version': '5.1',
            }}
            snapshot.write_snapshot(folder, meta, {}, [], [], [])
            store.publish(folder, [])
            info = _fake_target_info(exe=exe, pe_timestamp=0xBBBBBBBB, size_of_image=0x3000)

            def open_target(target, *, write, remote_calls, cache_bytes):
                return pipeline.OpenedTarget(source=_make_image(), info=info, process=None,
                                             check_alive=lambda: True, closer=lambda: None)

            with self.assertRaises(errors.DumpMismatchError) as cm:
                runtime.Unreal.attach(1, dump='latest', out=root, _open_target=open_target)
            self.assertEqual(str(cm.exception),
                             f'no snapshot matches the running build\n  running   {exe}  pe 0xBBBBBBBB / 0x3000\n'
                             f'  newest    {folder}  pe 0xAAAAAAAA / 0x3000\n'
                             f'  The game was updated; offsets from an older build are not safe to write through.\n'
                             f'  Run:  python -m nylib.ue dump {exe} --out {root}\n'
                             f"  or attach with dump='auto' to do that automatically.")
            self.assertEqual((cm.exception.running, cm.exception.newest, cm.exception.out_root),
                             ((exe, 0xBBBBBBBB, 0x3000), folder, root))

            with self.assertRaises(errors.DumpMismatchError) as cm:
                runtime.Unreal.attach(1, dump=folder, out=root, _open_target=open_target)
            self.assertEqual(str(cm.exception),
                             f'snapshot {folder} is for another build\n  running   {exe}  pe 0xBBBBBBBB / 0x3000\n'
                             f'  snapshot  {exe}  pe 0xAAAAAAAA / 0x3000\n'
                             f'  Offsets from another build are not safe to write through.\n'
                             f'  Run:  python -m nylib.ue dump {exe} --out {root}')
            self.assertEqual((cm.exception.running, cm.exception.snapshot, cm.exception.out_root),
                             ((exe, 0xBBBBBBBB, 0x3000), folder, root))

        with tempfile.TemporaryDirectory() as empty:
            with self.assertRaises(errors.DumpMismatchError) as cm:
                runtime.Unreal.attach(1, dump='latest', out=empty, _open_target=open_target)
            self.assertEqual(str(cm.exception),
                             f'no snapshot matches the running build\n  running   {exe}  pe 0xBBBBBBBB / 0x3000\n'
                             f'  newest    none under {empty}\n'
                             f'  Run:  python -m nylib.ue dump {exe} --out {empty}\n'
                             f"  or attach with dump='auto' to do that automatically.")


def _object_table(*paths: str) -> ObjectTable:
    return ObjectTable(ObjectRecord(index=i, address=0x1000 + 0x100 * i, flags=0, class_index=-1, outer_index=-1, name=p)
                       for i, p in enumerate(paths))


class IndexFindTests(unittest.TestCase):
    """I5: a path absent from the table is a miss without a rebuild; a stale row rebuilds the table alone."""

    @staticmethod
    def _index(*tables: ObjectTable):
        idx = rt_index.ObjectIndex(types.SimpleNamespace(), lambda c, n: '', threading.RLock())
        builds = []

        def build():
            builds.append(1)
            return tables[min(len(builds), len(tables)) - 1]
        idx._build_table = build
        idx._serial_offset = 0x10
        idx._super_cache[0x2000] = (0x2000,)
        idx._cast_flags_cache[0x2000] = 1
        return idx, builds

    def _assert_memos_kept(self, idx):
        self.assertEqual(idx._serial_offset, 0x10)
        self.assertEqual(idx._super_cache, {0x2000: (0x2000,)})
        self.assertEqual(idx._cast_flags_cache, {0x2000: 1})

    def test_find_miss_builds_table_once(self):
        idx, builds = self._index(_object_table('/Script/Engine'))
        with mock.patch.object(rt_index, 'LiveResolver') as m_resolver:
            self.assertIsNone(idx.find('/Script/NoSuch'))
            self.assertIsNone(idx.find('/Script/NoSuch'))
        self.assertEqual(len(builds), 1)
        m_resolver.assert_not_called()
        self._assert_memos_kept(idx)

    def test_live_mismatch_rebuilds_table_only(self):
        idx, builds = self._index(_object_table('/Script/Engine'), _object_table('/Script/Other', '/Script/Engine'))
        live = {0x1000: '/Script/Other', 0x1100: '/Script/Engine'}
        with mock.patch.object(rt_index, 'LiveResolver') as m_resolver:
            m_resolver.return_value.path.side_effect = live.get
            self.assertEqual(idx.find('/Script/Engine'), 0x1100)
        self.assertEqual(len(builds), 2)
        self._assert_memos_kept(idx)


class SerialFinderTests(unittest.TestCase):
    """I6 (RT2): a serial-number candidate qualifies only when its values are all distinct."""

    @staticmethod
    def _items(*, duplicated: bool, distinct: bool):
        items = []
        for i in range(200):
            item = bytearray(0x18)
            item[0:8] = (0x100000 + 0x100 * i).to_bytes(8, 'little')
            if duplicated:
                item[0xC:0x10] = (2000 + i // 2).to_bytes(4, 'little')  # 100 values, each twice
            if distinct:
                item[0x10:0x14] = (1001 + i).to_bytes(4, 'little')
            items.append((i, bytes(item)))
        return items

    @staticmethod
    def _find(items):
        e = types.SimpleNamespace(objects=types.SimpleNamespace(SizeOfFUObjectItem=0x18, FUObjectItemInitialOffset=0))
        with mock.patch.object(rt_index, '_iter_item_bytes', lambda _e: iter(items)):
            return rt_index.find_serial_number_offset(e)

    def test_duplicate_valued_candidate_rejected(self):
        self.assertEqual(self._find(self._items(duplicated=True, distinct=True)), 0x10)
        self.assertIsNone(self._find(self._items(duplicated=True, distinct=False)))


class _SlowTypeSource(_FakeTypeSource):
    """A type source slow enough that two threads both miss the factory's cache."""

    def type(self, path, address=None):
        time.sleep(0.02)
        return super().type(path, address)


class FactoryLockTests(unittest.TestCase):
    """I7 (RT6): two threads building one path get the same dynamic class or enum."""

    def test_concurrent_class_for_builds_one_class(self):
        ctx = _FakeContext(_make_image())
        ctx.types = _SlowTypeSource()
        for rec in (
                ClassRecord(path='/Script/Engine.Actor', name='Actor', cpp_name='AActor', package='/Script/Engine', super=None,
                            size=8, min_alignment=8, properties=[]),
                StructRecord(path='/Script/CoreUObject.Vector', name='Vector', cpp_name='FVector', package='/Script/CoreUObject',
                             super=None, size=0xC, min_alignment=4, properties=[]),
                EnumRecord(path='/Script/Engine.ENetRole', name='ENetRole', cpp_name='ENetRole', package='/Script/Engine',
                           underlying_size=1, underlying_size_from='reflection', underlying_signed=False,
                           values=[('ROLE_None', 0), ('ROLE_Authority', 3)])):
            ctx.types.records[rec.path] = rec
        factory = rt_types.ClassFactory(ctx)
        for method, path in (('class_for', '/Script/Engine.Actor'), ('struct_for', '/Script/CoreUObject.Vector'),
                             ('enum_for', '/Script/Engine.ENetRole')):
            with self.subTest(method=method):
                barrier = threading.Barrier(2)
                results = []

                def build():
                    barrier.wait()
                    results.append(getattr(factory, method)(path))
                threads = [threading.Thread(target=build) for _ in range(2)]
                for t in threads:
                    t.start()
                for t in threads:
                    t.join()
                self.assertEqual(len(results), 2)
                self.assertIs(results[0], results[1])


class AttachCleanupTests(unittest.TestCase):
    """M1 (RT8 step 4): a snapshot loaded during attach is closed when building the engine context fails."""

    def test_latest_snapshot_closed_when_from_snapshot_raises(self):
        info = _fake_target_info()

        def open_target(target, *, write, remote_calls, cache_bytes):
            return pipeline.OpenedTarget(source=_make_image(), info=info, process=None,
                                         check_alive=lambda: True, closer=lambda: None)

        ref = types.SimpleNamespace(path='<fake-snapshot>', schema_version=f'{snapshot.SCHEMA_MAJOR}.0')
        dump_result = pipeline.DumpResult(path='<fake-dump-path>', target=info, report=mock.Mock(), counts={},
                                          unverified=(), exports=(), export_paths=(), warnings=(), seconds=0.01)
        for dump, found in (('latest', [ref]), ('auto', [])):
            with self.subTest(dump=dump):
                snap = mock.Mock()
                with mock.patch('nylib.ue.store.find_snapshots', return_value=found), \
                     mock.patch('nylib.ue.pipeline.dump', return_value=dump_result), \
                     mock.patch('nylib.ue.snapshot.Snapshot.load', return_value=snap), \
                     mock.patch('nylib.ue.engine.context.EngineContext.from_snapshot', side_effect=ValueError('planted')):
                    with tempfile.TemporaryDirectory() as root:
                        with self.assertRaisesRegex(ValueError, 'planted'):
                            runtime.Unreal.attach(1, dump=dump, out=root, _open_target=open_target)
                snap.close.assert_called_once_with()


class _FakePool:
    """E6 duck type: an FNamePool whose ByIndex follows `_by_index_name_pool` and whose every entry decodes."""

    FNameBlockOffsetBits = 16
    NameEntryStride = 2

    def __init__(self, chunks: int, cursor: int):
        self.chunks, self.cursor = chunks, cursor

    def get_num_chunks(self):
        return self.chunks

    def get_byte_cursor(self):
        return self.cursor

    def get_name_entry(self, index):
        block, offset = index >> self.FNameBlockOffsetBits, (index & 0xFFFF) * self.NameEntryStride
        beyond = block > self.chunks or (block == self.chunks and offset > self.cursor)
        return types.SimpleNamespace(address=0 if beyond or block < 0 else 0x100000 + index, get_wstring=lambda: f'N{index:x}')

    def at(self, block: int, offset: int) -> int:
        return (block << self.FNameBlockOffsetBits) | (offset // self.NameEntryStride)


class NameDecodeTests(unittest.TestCase):
    """M5: an FName index at or past the pool's (block, byte cursor) end is refused, not decoded from free bytes."""

    def test_index_past_byte_cursor_refused(self):
        pool = _FakePool(chunks=2, cursor=0x40)
        e = types.SimpleNamespace(off=Off(), settings=Settings(), names=pool)
        e.settings.Internal.bUseNamePool = True
        decoder = rt_names.NameDecoder(e, threading.RLock())
        self.assertEqual(decoder.decode(pool.at(0, 0x1F000), 0), f'N{pool.at(0, 0x1F000):x}')
        self.assertEqual(decoder.decode(pool.at(2, 0x3E), 1), f'N{pool.at(2, 0x3E):x}_0')
        for block, offset in ((2, 0x40), (2, 0x42), (3, 0)):
            with self.subTest(block=block, offset=offset):
                with self.assertRaises(ValueError):
                    decoder.decode(pool.at(block, offset), 0)
        pool.cursor = 0x50
        self.assertEqual(decoder.decode(pool.at(2, 0x40), 0), f'N{pool.at(2, 0x40):x}')


class IndexLayoutTests(unittest.TestCase):
    """M7: a GObjects chunk size of 0 or less is refused, not walked until an unreadable chunk pointer."""

    def test_zero_chunk_size_refused(self):
        e = types.SimpleNamespace(off=Off(), settings=Settings(), mem=_make_image())
        e.off.FUObjectArray.bIsChunked = True
        e.objects = types.SimpleNamespace(GObjects=_IMAGE_BASE, NumElementsPerChunk=0, SizeOfFUObjectItem=0x18,
                                          FUObjectItemInitialOffset=0, num=lambda: 10)
        for per in (0, -1):
            with self.subTest(per=per):
                e.objects.NumElementsPerChunk = per
                with self.assertRaises(errors.DetectionError):
                    rt_index.ObjectIndex(e, lambda c, n: '', threading.RLock()).table()
                with self.assertRaises(errors.DetectionError):
                    rt_index.find_serial_number_offset(e)


class ContainerStringTests(unittest.TestCase):
    """C1/M2: containers of strings build real codecs; an FString read stays inside its header's Num."""

    @staticmethod
    def _fstring(image, hdr, buf, text, num=None, mx=None):
        units = (text + '\0').encode('utf-16-le')
        image.write(buf, units)
        n = len(units) // 2
        image.write(hdr, buf.to_bytes(8, 'little') + (n if num is None else num).to_bytes(4, 'little', signed=True)
                    + (n if mx is None else mx).to_bytes(4, 'little', signed=True))

    def test_array_of_fstring_reads(self):
        image = _make_image()
        ctx = _FakeContext(image)
        base = _IMAGE_BASE + 0x2000
        elems, hdr = base + 0x100, base + 0x200
        self._fstring(image, elems, base, 'abc')
        self._fstring(image, elems + 0x10, base + 0x40, 'xy')
        image.write(hdr, elems.to_bytes(8, 'little') + (2).to_bytes(4, 'little') + (2).to_bytes(4, 'little'))
        ptype = PropType('ArrayProperty', 'ArrayProperty', inner=PropType('StrProperty', 'StrProperty'))
        codec = rt_codecs.make_codec(ctx, ptype, 0x10)
        self.assertEqual(codec.get(ctx, hdr, 'Test.Arr')[0], 'abc')
        self.assertEqual(codec.get(ctx, hdr, 'Test.Arr').to_list(), ['abc', 'xy'])

    def test_map_of_fstring_reads(self):
        image = _make_image()
        ctx = _FakeContext(image)
        base = _IMAGE_BASE + 0x2400
        slots, hdr = base + 0x100, base + 0x200
        image.write(slots, (5).to_bytes(4, 'little', signed=True))  # TPair<int32, FString>: value at 8
        self._fstring(image, slots + 8, base, 'five')
        image.write(hdr, slots.to_bytes(8, 'little') + (1).to_bytes(4, 'little') + (1).to_bytes(4, 'little'))
        image.write(hdr + 0x10, (1).to_bytes(4, 'little'))
        image.write(hdr + 0x28, (1).to_bytes(4, 'little'))
        string = PropType('StrProperty', 'StrProperty')
        codec = rt_codecs.make_codec(ctx, PropType('MapProperty', 'MapProperty', key=PropType('IntProperty', 'IntProperty'),
                                                   value=string), 0x50)
        self.assertEqual(codec.get(ctx, hdr, 'Test.Map').items(), [(5, 'five')])
        self.assertEqual(rt_codecs.make_codec(ctx, PropType('SetProperty', 'SetProperty', element=string)).size, 0x50)

    def test_fstring_corrupt_header_raises(self):
        image = _make_image()
        ctx = _FakeContext(image)
        hdr = _IMAGE_BASE + 0x2800
        self._fstring(image, hdr, hdr + 0x100, 'abcd', num=5, mx=4)
        with self.assertRaises(ValueError):
            rt_containers.string_codec(ctx, 'StrProperty').get(ctx, hdr, 'Test.Str')

    def test_fstring_reads_at_most_num_minus_one(self):
        image = _make_image()
        ctx = _FakeContext(image)
        hdr = _IMAGE_BASE + 0x2900
        self._fstring(image, hdr, hdr + 0x100, 'abcdef', num=3, mx=8)
        self.assertEqual(rt_containers.string_codec(ctx, 'StrProperty').get(ctx, hdr, 'Test.Str'), 'ab')


class ObjectWriteTests(unittest.TestCase):
    """I1/I2: object, class and weak-pointer writes check the value's runtime class, read fresh."""

    _OBJECT, _LEVEL, _GI, _CLASS = ('/Script/CoreUObject.Object', '/Script/Engine.Level', '/Script/Engine.GameInstance',
                                    '/Script/CoreUObject.Class')

    def _ctx(self):
        image = _make_image()
        ctx = _FakeContext(image)
        ctx.e.off.UObject.Class = 0x10
        ctx.e.provenance = {}
        for path, sup in ((self._OBJECT, None), (self._LEVEL, self._OBJECT), (self._GI, self._OBJECT), (self._CLASS, self._OBJECT)):
            package, name = path.rsplit('.', 1)
            ctx.types.records[path] = ClassRecord(path=path, name=name, cpp_name='U' + name, package=package, super=sup,
                                                  size=0x30, min_alignment=8, properties=[])
        self.class_addr = {p: _IMAGE_BASE + 0x8000 + i * 0x100 for i, p in enumerate(ctx.types.records)}
        paths = {a: p for p, a in self.class_addr.items()}
        ctx.types.path_of = paths.get
        for a in self.class_addr.values():
            image.write(a + 0x10, self.class_addr[self._CLASS].to_bytes(8, 'little'))

        def is_subclass(path, base):
            for _ in range(8):
                if path == base:
                    return True
                rec = ctx.types.records.get(path)
                if rec is None or rec.super is None:
                    return False
                path = rec.super
            return False
        ctx.is_subclass = is_subclass
        ctx.factory = rt_types.ClassFactory(ctx)
        return image, ctx

    def _object(self, image, ctx, address, runtime_class, proxy_class):
        image.write(address + 0x10, self.class_addr[runtime_class].to_bytes(8, 'little'))
        return accessor_view(ctx.factory.class_for(proxy_class), address, ctx.acc)

    def test_object_set_refuses_cast_proxy(self):
        image, ctx = self._ctx()
        target = _IMAGE_BASE + 0x100
        codec = rt_codecs.make_codec(ctx, PropType('ObjectProperty', 'ObjectProperty', cls=self._LEVEL), 8)
        gi_as_level = self._object(image, ctx, _IMAGE_BASE + 0x9000, self._GI, self._LEVEL)
        with self.assertRaises(TypeError):
            codec.set(ctx, target, gi_as_level, 'World.PersistentLevel')
        self.assertEqual(image.read(target, 8), bytes(8))
        level = self._object(image, ctx, _IMAGE_BASE + 0x9100, self._LEVEL, self._LEVEL)
        codec.set(ctx, target, level, 'World.PersistentLevel')
        self.assertEqual(int.from_bytes(image.read(target, 8), 'little'), _IMAGE_BASE + 0x9100)

    def test_weak_set_refuses_wrong_class(self):
        image, ctx = self._ctx()
        ctx.weak_ref = lambda obj: (7, 99)
        target = _IMAGE_BASE + 0x100
        codec = rt_codecs.make_codec(ctx, PropType('WeakObjectProperty', 'WeakObjectProperty', cls=self._LEVEL), 8)
        gi = self._object(image, ctx, _IMAGE_BASE + 0x9000, self._GI, self._GI)
        with self.assertRaises(TypeError):
            codec.set(ctx, target, gi, 'Test.Weak')
        self.assertEqual(image.read(target, 8), bytes(8))
        level = self._object(image, ctx, _IMAGE_BASE + 0x9100, self._LEVEL, self._LEVEL)
        codec.set(ctx, target, level, 'Test.Weak')
        self.assertEqual(image.read(target, 8), (7).to_bytes(4, 'little') + (99).to_bytes(4, 'little'))

    def test_class_set_checks_class_object(self):
        image, ctx = self._ctx()
        target = _IMAGE_BASE + 0x100
        codec = rt_codecs.make_codec(ctx, PropType('ClassProperty', 'ClassProperty', meta_class=self._LEVEL), 8)
        gi_as_class = self._object(image, ctx, _IMAGE_BASE + 0x9000, self._GI, self._CLASS)
        with self.assertRaises(TypeError):
            codec.set(ctx, target, gi_as_class, 'Test.Class')
        self.assertEqual(image.read(target, 8), bytes(8))
        level_class = accessor_view(ctx.factory.class_for(self._CLASS), self.class_addr[self._LEVEL], ctx.acc)
        codec.set(ctx, target, level_class, 'Test.Class')
        self.assertEqual(int.from_bytes(image.read(target, 8), 'little'), self.class_addr[self._LEVEL])


class AtomicSetTests(unittest.TestCase):
    """I3: a refused struct, array or fixed-array set leaves every target byte unchanged."""

    @staticmethod
    def _int_prop(name, offset, array_dim=1):
        return PropertyRecord(name=name, offset=offset, size=4, array_dim=array_dim, flags=0,
                              type=PropType('IntProperty', 'IntProperty'))

    @staticmethod
    def _struct_ctx(*props, size=0x10):
        image = _make_image()
        ctx = _FakeContext(image)
        ctx.types.records['/Script/Test.S'] = StructRecord(path='/Script/Test.S', name='S', cpp_name='FS', package='/Script/Test',
                                                           super=None, size=size, min_alignment=4, properties=list(props))
        codec = rt_codecs.make_codec(ctx, PropType('StructProperty', 'StructProperty', struct='/Script/Test.S'), size)
        return image, ctx, codec

    def test_array_set_bad_element_leaves_bytes(self):
        image = _make_image()
        ctx = _FakeContext(image)
        data, hdr = _IMAGE_BASE + 0x1200, _IMAGE_BASE + 0x1300
        image.write(data, (1).to_bytes(4, 'little') + (2).to_bytes(4, 'little'))
        image.write(hdr, data.to_bytes(8, 'little') + (2).to_bytes(4, 'little') + (2).to_bytes(4, 'little'))
        codec = rt_containers.array_codec(ctx, rt_codecs.make_codec(ctx, PropType('IntProperty', 'IntProperty')))
        with self.assertRaises(TypeError):
            codec.set(ctx, hdr, [5, 'x'], 'Test.Arr')
        self.assertEqual(codec.get(ctx, hdr, 'Test.Arr').to_list(), [1, 2])

    def test_fixed_array_set_bad_element_leaves_bytes(self):
        image = _make_image()
        ctx = _FakeContext(image)
        addr = _IMAGE_BASE + 0x1400
        codec = rt_containers.fixed_array_codec(rt_codecs.make_codec(ctx, PropType('IntProperty', 'IntProperty')), 3)
        for bad, exc in (([1, 'x', 3], TypeError), ([1, 2, 1 << 40], ValueError)):
            with self.subTest(bad=bad):
                with self.assertRaises(exc):
                    codec.set(ctx, addr, bad, 'Test.Fixed')
                self.assertEqual(image.read(addr, 12), bytes(12))

    def test_struct_dict_unknown_key_leaves_bytes(self):
        image, ctx, codec = self._struct_ctx(self._int_prop('A', 0), self._int_prop('B', 4))
        addr = _IMAGE_BASE + 0x1500
        with self.assertRaises(AttributeError):
            codec.set(ctx, addr, {'A': 5, 'Nope': 1}, 'Test.S')
        self.assertEqual(image.read(addr, 8), bytes(8))

    def test_struct_bits_sharing_a_byte(self):
        def bit(name, mask):
            return PropertyRecord(name=name, offset=0, size=1, array_dim=1, flags=0, type=PropType(
                'BoolProperty', 'BoolProperty', field_size=1, byte_offset=0, byte_mask=mask, field_mask=mask))
        image, ctx, codec = self._struct_ctx(bit('bA', 0x01), bit('bB', 0x02), size=4)
        addr = _IMAGE_BASE + 0x1600
        image.write(addr, bytes([0x80]))
        codec.set(ctx, addr, {'bA': True, 'bB': True}, 'Test.S')
        self.assertEqual(image.read(addr, 1), bytes([0x83]))
        codec.set(ctx, addr, (False, True), 'Test.S')
        self.assertEqual(image.read(addr, 1), bytes([0x82]))


class SparseHeaderTests(unittest.TestCase):
    """I4: the TSet/TMap header invariant is on DataNum; NumBits and Data must cover it."""

    @staticmethod
    def _tset(image, hdr, data, *, data_num, num_free, num_bits, word0):
        image.write(hdr, data.to_bytes(8, 'little') + data_num.to_bytes(4, 'little') + data_num.to_bytes(4, 'little'))
        image.write(hdr + 0x10, word0.to_bytes(4, 'little'))
        image.write(hdr + 0x28, num_bits.to_bytes(4, 'little') + num_bits.to_bytes(4, 'little'))
        image.write(hdr + 0x34, num_free.to_bytes(4, 'little'))

    def _codec(self, ctx):
        return rt_containers.set_codec(ctx, rt_codecs.make_codec(ctx, PropType('IntProperty', 'IntProperty')))

    def test_set_more_free_than_live_reads(self):
        image = _make_image()
        ctx = _FakeContext(image)
        data, hdr = _IMAGE_BASE + 0x3000, _IMAGE_BASE + 0x3200
        live = (0, 3, 5, 9)
        for i in live:
            image.write(data + i * 12, (i * 10 + 1).to_bytes(4, 'little'))  # SetElement<int32>: 12-byte slots
        self._tset(image, hdr, data, data_num=10, num_free=6, num_bits=10, word0=sum(1 << i for i in live))
        value = self._codec(ctx).get(ctx, hdr, 'Test.Set')
        self.assertEqual(len(value), 4)
        self.assertEqual(value.to_list(), [1, 31, 51, 91])

    def test_set_short_bits_is_corrupt(self):
        image = _make_image()
        ctx = _FakeContext(image)
        data, hdr = _IMAGE_BASE + 0x3000, _IMAGE_BASE + 0x3200
        self._tset(image, hdr, data, data_num=10, num_free=2, num_bits=8, word0=0xFF)
        with self.assertRaises(ValueError):
            len(self._codec(ctx).get(ctx, hdr, 'Test.Set'))

    def test_set_null_data_is_corrupt(self):
        image = _make_image()
        ctx = _FakeContext(image)
        hdr = _IMAGE_BASE + 0x3200
        self._tset(image, hdr, 0, data_num=2, num_free=0, num_bits=2, word0=0x3)
        with self.assertRaises(ValueError):
            len(self._codec(ctx).get(ctx, hdr, 'Test.Set'))


class CodecBuildTests(unittest.TestCase):
    """M3/M9/C1: build-time data errors become error codecs that re-raise their own type; containers have a layout."""

    def test_struct_type_memoryreaderror_gives_error_codec(self):
        image = _make_image()
        ctx = _FakeContext(image)

        def unreadable(path, address=None):
            raise errors.MemoryReadError(0x1234, 8, 'unreadable')
        ctx.types.type = unreadable
        codec = rt_codecs.make_codec(ctx, PropType('StructProperty', 'StructProperty', struct='/Script/Test.Torn'), 0x10)
        for call in (lambda: codec.get(ctx, _IMAGE_BASE, 'Test.S'), lambda: codec.set(ctx, _IMAGE_BASE, {}, 'Test.S')):
            with self.assertRaises(errors.MemoryReadError) as cm:
                call()
            self.assertTrue(str(cm.exception).startswith('Test.S: '), str(cm.exception))
            self.assertEqual(cm.exception.address, 0x1234)

    def test_container_kind_layout(self):
        ctx = _FakeContext(_make_image())
        int_t = PropType('IntProperty', 'IntProperty')
        cases = (
            (PropType('ArrayProperty', 'ArrayProperty', inner=int_t), (0x10, 8)),
            (PropType('StrProperty', 'StrProperty'), (0x10, 8)),
            (PropType('SetProperty', 'SetProperty', element=int_t), (0x50, 8)),
            (PropType('MapProperty', 'MapProperty', key=int_t, value=int_t), (0x50, 8)),
            (PropType('MulticastInlineDelegateProperty', 'MulticastInlineDelegateProperty'),
             (PropertySizes().MulticastInlineDelegateProperty, 8)),
        )
        for ptype, layout in cases:
            with self.subTest(kind=ptype.kind):
                self.assertEqual(rt_codecs.kind_layout(ctx, ptype), layout)

    def test_nested_container_error_is_error_codec(self):
        ctx = _FakeContext(_make_image())
        bad = PropType('ArrayProperty', 'ArrayProperty', inner=PropType('StructProperty', 'StructProperty', struct='/Script/Test.Missing'))
        codec = rt_codecs.make_codec(ctx, PropType('MapProperty', 'MapProperty', key=bad, value=PropType('IntProperty', 'IntProperty')), 0x50)
        with self.assertRaises(LookupError):
            codec.get(ctx, _IMAGE_BASE, 'Test.Map')
        with self.assertRaises(LookupError):
            rt_codecs.kind_layout(ctx, bad)


class StructSetTests(unittest.TestCase):
    """M4: struct set takes Python-name dict keys (first duplicate wins), copies any member of a view, keeps fixed arrays."""

    def test_dict_python_name_key_and_first_duplicate(self):
        image, ctx, codec = AtomicSetTests._struct_ctx(AtomicSetTests._int_prop('My Value', 0), AtomicSetTests._int_prop('HP', 4), AtomicSetTests._int_prop('HP', 8))
        addr = _IMAGE_BASE + 0x1700
        codec.set(ctx, addr, {'My_Value': 3, 'HP': 7}, 'Test.S')
        self.assertEqual(image.read(addr, 12), (3).to_bytes(4, 'little') + (7).to_bytes(4, 'little') + bytes(4))

    def test_view_copy_non_identifier_member(self):
        image, ctx, codec = AtomicSetTests._struct_ctx(AtomicSetTests._int_prop('(x)', 0), AtomicSetTests._int_prop('cast', 4))
        ctx.factory = rt_types.ClassFactory(ctx)
        src, dst = _IMAGE_BASE + 0x1800, _IMAGE_BASE + 0x1900
        image.write(src, (11).to_bytes(4, 'little') + (22).to_bytes(4, 'little'))
        codec.set(ctx, dst, accessor_view(ctx.factory.struct_for('/Script/Test.S'), src, ctx.acc), 'Test.S')
        self.assertEqual(image.read(dst, 8), image.read(src, 8))

    def test_fixed_array_member_set(self):
        image, ctx, codec = AtomicSetTests._struct_ctx(AtomicSetTests._int_prop('Arr', 0, array_dim=3), AtomicSetTests._int_prop('B', 12))
        addr = _IMAGE_BASE + 0x1A00
        codec.set(ctx, addr, {'Arr': [1, 2, 3], 'B': 4}, 'Test.S')
        self.assertEqual(image.read(addr, 16), b''.join(i.to_bytes(4, 'little') for i in (1, 2, 3, 4)))


if __name__ == '__main__':
    unittest.main()
