import struct
import unittest

from nylib.ue.errors import CaptureError, MemoryReadError, MemoryWriteError, UeError
from nylib.ue.memory import (
    MEM_COMMIT, MEM_RESERVE, MEM_PRIVATE,
    PAGE_NOACCESS, PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOPY,
    PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE,
    PAGE_GUARD, PAGE_NOCACHE,
    ADDRESS_LIMIT, USER_MIN, USER_MAX,
    Module, MemorySource, Region,
)

BASE = 0x20000


class _Blob(MemorySource):
    """Backs reads/writes with one bytearray at a fixed base; records write payload types."""

    def __init__(self, data: bytes, base: int = BASE, *, writable: bool = True):
        self._data = bytearray(data)
        self._base = base
        self._writable = writable
        self.write_types = []
        self._mods = []

    def _read(self, address, size):
        off = address - self._base
        if off < 0 or off + size > len(self._data):
            raise MemoryReadError(address, size, 'past end of blob')
        return bytes(self._data[off:off + size])

    def _readable_ranges(self, address, size):
        end = self._base + len(self._data)
        lo, hi = max(address, self._base), min(address + size, end)
        return [(lo, hi - lo)] if hi > lo else []

    def _write(self, address, data):
        if not self._writable:
            raise MemoryWriteError(address, len(data), 'source is read-only')
        self.write_types.append(type(data))
        off = address - self._base
        self._data[off:off + len(data)] = data

    def set_modules(self, mods):
        self._mods = mods

    def modules(self):
        return self._mods


class _ShortReadBlob(_Blob):
    def _read(self, address, size):
        return b'abc'


class _FixedRangesBlob(_Blob):
    def __init__(self, ranges, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._ranges = ranges

    def _readable_ranges(self, address, size):
        return self._ranges


class _AlwaysReadableBlob(MemorySource):
    """Reports every requested window as readable, to isolate valid_ptr's own bounds."""

    def _readable_ranges(self, address, size):
        return [(address, size)]


class _ReadOnlyBlob(MemorySource):
    """Read-only source that relies on the base class's default _write (F2), not its own."""

    def __init__(self, data: bytes, base: int = BASE):
        self._data = bytes(data)
        self._base = base

    def _read(self, address, size):
        off = address - self._base
        if off < 0 or off + size > len(self._data):
            raise MemoryReadError(address, size, 'past end of blob')
        return self._data[off:off + size]

    def _readable_ranges(self, address, size):
        end = self._base + len(self._data)
        lo, hi = max(address, self._base), min(address + size, end)
        return [(lo, hi - lo)] if hi > lo else []


class _RaisingBlob(_Blob):
    def __init__(self, exc, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._exc = exc

    def _read(self, address, size):
        raise self._exc


class _BytearrayReadBlob(_Blob):
    def _read(self, address, size):
        return bytearray(super()._read(address, size))


class _MemoryviewReadBlob(_Blob):
    def _read(self, address, size):
        return memoryview(super()._read(address, size))


class _BadTypeReadBlob(_Blob):
    def _read(self, address, size):
        return 'not bytes-like'


class _ProbeBlob(MemorySource):
    """Records hook calls instead of backing real memory, to observe what the base class calls."""

    def __init__(self):
        self.calls = []

    def _read(self, address, size):
        self.calls.append(('read', address, size))
        raise MemoryReadError(address, size, 'not backed')

    def _readable_ranges(self, address, size):
        self.calls.append(('ranges', address, size))
        return []


class _WriteProbeBlob(MemorySource):
    def __init__(self):
        self.writes = []

    def _write(self, address, data):
        self.writes.append((address, bytes(data)))


class _OverriddenReadableBlob(_Blob):
    def readable(self, address, size=1):
        return True


class MemorySourceTests(unittest.TestCase):
    def test_zero_size(self):
        blob = _Blob(b'\x00' * 16)
        self.assertEqual(blob.read(BASE, 0), b'')
        blob.write(BASE, b'')
        self.assertEqual(blob.write_types, [])

    def test_out_of_range(self):
        blob = _Blob(b'\x00' * 16)
        with self.assertRaises(MemoryReadError) as cm:
            blob.read(-1, 4)
        self.assertEqual(cm.exception.reason, 'address out of range')
        with self.assertRaises(MemoryReadError) as cm:
            blob.read(2 ** 64 - 2, 4)
        self.assertEqual(cm.exception.reason, 'address out of range')
        with self.assertRaises(MemoryWriteError) as cm:
            blob.write(-1, b'x')
        self.assertEqual(cm.exception.reason, 'address out of range')

    def test_argument_checks(self):
        blob = _Blob(b'\x00' * 16)
        with self.assertRaises(ValueError):
            blob.read(BASE, -1)
        with self.assertRaises(TypeError):
            blob.read(BASE, 1.0)
        with self.assertRaises(TypeError):
            blob.write(1.0, b'x')
        with self.assertRaises(TypeError):
            blob.write(BASE, 'x')

    def test_read_past_end_raises(self):
        blob = _Blob(b'\x00' * 4)
        with self.assertRaises(MemoryReadError):
            blob.read(BASE, 8)

    def test_short_read_result(self):
        blob = _ShortReadBlob(b'\x00' * 16)
        with self.assertRaises(MemoryReadError) as cm:
            blob.read(BASE, 4)
        self.assertIn('source returned 3 of 4 bytes', str(cm.exception))

    def test_try_read(self):
        blob = _Blob(b'\x00' * 16)
        self.assertIsNone(blob.try_read(BASE + 100, 4))
        self.assertEqual(blob.try_read(BASE, 4), b'\x00' * 4)
        with self.assertRaises(TypeError):
            blob.try_read(1.0, 4)
        with self.assertRaises(ValueError):
            blob.try_read(BASE, -1)

    def test_readable_ranges_normalization(self):
        b = BASE
        blob = _FixedRangesBlob([(b + 8, 8), (b, 8), (b + 4, 2), (b - 100, 50), (b + 16, 0)], b'\x00' * 32, base=b)
        self.assertEqual(blob.readable_ranges(b, 16), [(b, 16)])
        self.assertTrue(blob.readable(b, 16))

    def test_readable_ranges_bad_hook_element(self):
        b = BASE
        blob = _FixedRangesBlob([(b, 1.0)], b'\x00' * 32, base=b)
        with self.assertRaises(TypeError):
            blob.readable_ranges(b, 4)

    def test_typed_readers(self):
        asc = bytes(range(1, 9))  # 0x01..0x08
        blob = _Blob(asc)
        self.assertEqual(blob.u8(BASE), 1)
        self.assertEqual(blob.u16(BASE), 0x0201)
        self.assertEqual(blob.u32(BASE), 0x04030201)
        self.assertEqual(blob.u64(BASE), 0x0807060504030201)
        self.assertEqual(blob.ptr(BASE), 0x0807060504030201)
        self.assertEqual(blob.i8(BASE), 1)
        self.assertEqual(blob.i16(BASE), 0x0201)
        self.assertEqual(blob.i32(BASE), 0x04030201)
        self.assertEqual(blob.i64(BASE), 0x0807060504030201)

        ff = b'\xff' * 8
        fblob = _Blob(ff)
        self.assertEqual(fblob.u8(BASE), 255)
        self.assertEqual(fblob.u16(BASE), 0xFFFF)
        self.assertEqual(fblob.u32(BASE), 0xFFFFFFFF)
        self.assertEqual(fblob.u64(BASE), 0xFFFFFFFFFFFFFFFF)
        self.assertEqual(fblob.ptr(BASE), 0xFFFFFFFFFFFFFFFF)
        self.assertEqual(fblob.i8(BASE), -1)
        self.assertEqual(fblob.i16(BASE), -1)
        self.assertEqual(fblob.i32(BASE), -1)
        self.assertEqual(fblob.i64(BASE), -1)

        f_blob = _Blob(struct.pack('<f', 1.5))
        self.assertEqual(f_blob.f32(BASE), 1.5)
        d_blob = _Blob(struct.pack('<d', 2.25))
        self.assertEqual(d_blob.f64(BASE), 2.25)

    def test_try_read_propagates_non_memory_read_error(self):
        blob = _RaisingBlob(CaptureError('x', 'closed'), b'\x00' * 16)
        with self.assertRaises(CaptureError):
            blob.try_read(BASE, 4)
        blob2 = _RaisingBlob(UeError('boom'), b'\x00' * 16)
        with self.assertRaises(UeError):
            blob2.try_read(BASE, 4)

    def test_read_converts_bytearray_and_memoryview_hook_result(self):
        for cls in (_BytearrayReadBlob, _MemoryviewReadBlob):
            blob = cls(b'\x01\x02\x03\x04')
            result = blob.read(BASE, 4)
            self.assertIs(type(result), bytes)
            self.assertEqual(result, b'\x01\x02\x03\x04')

    def test_read_hook_non_bytes_like_raises_typeerror(self):
        blob = _BadTypeReadBlob(b'\x00' * 16)
        with self.assertRaises(TypeError):
            blob.read(BASE, 4)

    def test_size_zero_ignores_range(self):
        blob = _Blob(b'\x00' * 16)
        for addr in (-1, ADDRESS_LIMIT + 1):
            self.assertEqual(blob.read(addr, 0), b'')
            self.assertEqual(blob.try_read(addr, 0), b'')
            self.assertTrue(blob.readable(addr, 0))
            self.assertEqual(blob.readable_ranges(addr, 0), [])

    def test_boundary_address_size_in_range(self):
        top = ADDRESS_LIMIT - 4
        blob = _ProbeBlob()
        with self.assertRaises(MemoryReadError) as cm:
            blob.read(top, 4)
        self.assertEqual(cm.exception.reason, 'not backed')
        self.assertIn(('read', top, 4), blob.calls)

    def test_readable_ranges_clips_upper_end(self):
        b = BASE
        blob = _FixedRangesBlob([(b - 4, 20)], b'\x00' * 32, base=b)
        self.assertEqual(blob.readable_ranges(b, 8), [(b, 8)])

    def test_write_memoryview_sized_by_nbytes(self):
        mv = memoryview(b'\x01\x02\x03\x04').cast('I')
        self.assertEqual(len(mv), 1)
        self.assertEqual(mv.nbytes, 4)
        blob = _WriteProbeBlob()
        top = ADDRESS_LIMIT
        with self.assertRaises(MemoryWriteError) as cm:
            blob.write(top - 2, mv)
        self.assertEqual(cm.exception.reason, 'address out of range')
        self.assertEqual(blob.writes, [])

    def test_readable_argument_checks(self):
        blob = _Blob(b'\x00' * 16)
        with self.assertRaises(TypeError):
            blob.readable(1.0)
        with self.assertRaises(TypeError):
            blob.readable(BASE, 1.0)
        with self.assertRaises(ValueError):
            blob.readable(BASE, -1)
        # size 0 must not short-circuit past readable's own type check (review: a variant
        # skipping _check_address_size but keeping the size==0 fast path would pass otherwise).
        with self.assertRaises(TypeError):
            blob.readable(1.0, 0)
        with self.assertRaises(TypeError):
            blob.readable_ranges(1.0, 4)
        with self.assertRaises(TypeError):
            blob.readable_ranges(BASE, 1.0)
        with self.assertRaises(ValueError):
            blob.readable_ranges(BASE, -1)

    def test_module_at_first_match_on_overlap(self):
        blob = _Blob(b'\x00' * 16)
        m1 = Module('a.exe', BASE, 0x2000)
        m2 = Module('b.dll', BASE + 0x10, 0x10)  # overlaps m1
        blob.set_modules([m1, m2])
        self.assertIs(blob.module_at(BASE + 0x10), m1)

    def test_valid_ptr_honours_overridden_readable(self):
        blob = _OverriddenReadableBlob(b'\x00' * 16)
        far = BASE + 0x100000  # inside user space, but out of the blob's real backing
        self.assertTrue(blob.valid_ptr(far, 8))

    def test_valid_ptr(self):
        blob = _Blob(b'\x00' * 16, base=BASE)
        self.assertFalse(blob.valid_ptr(0x100))
        self.assertFalse(blob.valid_ptr(USER_MAX - 4, 8))
        self.assertTrue(blob.valid_ptr(BASE, 8))
        with self.assertRaises(TypeError):
            blob.valid_ptr(1.0)
        with self.assertRaises(TypeError):
            blob.valid_ptr(BASE, 1.0)
        with self.assertRaises(ValueError):
            blob.valid_ptr(BASE, 0)

    def test_valid_ptr_bounds(self):
        blob = _AlwaysReadableBlob()
        self.assertFalse(blob.valid_ptr(USER_MIN - 1))
        self.assertTrue(blob.valid_ptr(USER_MIN))
        self.assertTrue(blob.valid_ptr(USER_MAX - 8))
        self.assertFalse(blob.valid_ptr(USER_MAX - 7))

    def test_write_read_only(self):
        blob = _Blob(b'\x00' * 16, writable=False)
        with self.assertRaises(MemoryWriteError) as cm:
            blob.write(BASE, b'x')
        self.assertEqual(cm.exception.reason, 'source is read-only')

    def test_write_read_only_base_default(self):
        blob = _ReadOnlyBlob(b'\x00' * 16)
        with self.assertRaises(MemoryWriteError) as cm:
            blob.write(BASE, b'x')
        self.assertEqual(cm.exception.reason, 'source is read-only')
        self.assertEqual(cm.exception.address, BASE)
        self.assertEqual(cm.exception.size, 1)

    def test_write_receives_bytes(self):
        blob = _Blob(b'\x00' * 16)
        blob.write(BASE, bytearray(b'x'))
        blob.write(BASE, memoryview(b'x'))
        self.assertEqual(blob.write_types, [bytes, bytes])

    def test_fresh_is_self(self):
        blob = _Blob(b'\x00' * 16)
        self.assertIs(blob.fresh, blob)

    def test_module_lookup(self):
        blob = _Blob(b'\x00' * 16)
        with self.assertRaises(UeError):
            _ = blob.main_module
        m1 = Module('a.exe', BASE, 0x1000)
        m2 = Module('b.dll', BASE + 0x2000, 0x1000)
        blob.set_modules([m1, m2])
        self.assertIs(blob.main_module, m1)
        self.assertIs(blob.module_at(BASE + 0x10), m1)
        self.assertIsNone(blob.module_at(BASE + 0x5000))
        self.assertIsNone(blob.module_at(-1))
        with self.assertRaises(TypeError):
            blob.module_at('x')

    def test_module_contains(self):
        m = Module('a.exe', BASE, 0x1000)
        self.assertTrue(m.contains(BASE))
        self.assertFalse(m.contains(BASE + 0x1000))
        with self.assertRaises(TypeError):
            m.contains('x')


class RegionTests(unittest.TestCase):
    def test_readable_truth_table(self):
        cases = [
            (MEM_COMMIT, PAGE_READWRITE, True),
            (MEM_COMMIT, PAGE_READWRITE | PAGE_GUARD, False),
            (MEM_COMMIT, PAGE_NOACCESS, False),
            (MEM_RESERVE, PAGE_READWRITE, False),
            (MEM_COMMIT, PAGE_EXECUTE, False),
            (MEM_COMMIT, PAGE_EXECUTE_READ, True),
            (MEM_COMMIT, PAGE_READWRITE | PAGE_NOCACHE, True),
        ]
        for state, protect, expected in cases:
            r = Region(BASE, 0x1000, protect, state, MEM_PRIVATE)
            self.assertEqual(r.readable, expected, (state, protect))

    def test_writable_truth_table(self):
        cases = [
            (MEM_COMMIT, PAGE_READWRITE, True),
            (MEM_COMMIT, PAGE_WRITECOPY, True),
            (MEM_COMMIT, PAGE_EXECUTE_READWRITE, True),
            (MEM_COMMIT, PAGE_READONLY, False),
            (MEM_COMMIT, PAGE_EXECUTE_READ, False),
            (MEM_COMMIT, PAGE_READWRITE | PAGE_GUARD, False),
            (MEM_RESERVE, PAGE_READWRITE, False),
        ]
        for state, protect, expected in cases:
            r = Region(BASE, 0x1000, protect, state, MEM_PRIVATE)
            self.assertEqual(r.writable, expected, (state, protect))


if __name__ == '__main__':
    unittest.main()
