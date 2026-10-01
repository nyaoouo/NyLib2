"""Capture-free guards for nylib.ue.runtime (## Guards, G9.1-G9.8): never skip. Most build a fake
RuntimeContext (RT0's duck-typed members) over a writable in-memory ImageSource, as the frozen node
describes; G9.3's second case and G9.8 use a real child process and a real on-disk snapshot.
See test_runtime_captures.py for the capture-backed checks (G9.9, G9.10, ## Verification)."""
import datetime
import subprocess
import sys
import tempfile
import threading
import types
import unittest
from unittest import mock

from ... import ctype
from .. import errors, memory, pipeline, runtime, snapshot, store
from ..capture import ImageSource
from ..engine.accessor import SourceAccessor, view as accessor_view
from ..engine.state import Off, PropertySizes, Settings
from ..model import ClassRecord, PropType, PropertyRecord, StructRecord
from ..runtime import accessor as rt_accessor
from ..runtime import codecs as rt_codecs
from ..runtime import containers as rt_containers
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


if __name__ == '__main__':
    unittest.main()
