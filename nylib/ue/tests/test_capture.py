import json
import os
import pathlib
import random
import sys
import tempfile
import threading
import time
import tracemalloc
import unittest
import zipfile
from unittest import mock

from nylib.ue.capture import CAPTURE_FORMAT, CAPTURE_VERSION, CHUNK_SIZE, ImageSource, RecordingSource, wide_capture_ranges, write_capture
from nylib.ue.errors import CaptureError, MemoryReadError, MemoryWriteError
from nylib.ue.memory import (
    ADDRESS_LIMIT, MEM_COMMIT, MEM_IMAGE, MEM_MAPPED, MEM_PRIVATE, MEM_RESERVE,
    PAGE_EXECUTE_READ, PAGE_GUARD, PAGE_NOACCESS, PAGE_READONLY, PAGE_READWRITE,
    MemorySource, Module, Region,
)

BASE = 0x7FF6_0000_0000  # CHUNK_SIZE-aligned
_PERIOD = bytes(range(256)) * 0x1001


def _rand(n: int, seed: int = 1) -> bytes:
    return random.Random(seed).randbytes(n)


def _pattern(address: int, size: int) -> bytes:
    """Deterministic bytes of a synthetic address space; each MiB has its own phase."""
    out, pos, end = [], address, address + size
    while pos < end:
        nxt = min((pos | (CHUNK_SIZE - 1)) + 1, end)
        off = (pos + (pos >> 20) * 37) & 0xFF
        out.append(_PERIOD[off:off + nxt - pos])
        pos = nxt
    return b''.join(out)


def _member(address: int) -> str:
    return f'chunks/{address:016X}.bin'


class _GenSource(MemorySource):
    """Readable over spans, bytes generated on demand; reads touching a bad span fail, and the first failure swaps in after_fail."""

    def __init__(self, spans, bad=(), mods=(), after_fail=None):
        self.spans, self.bad, self.mods, self.after_fail = list(spans), list(bad), list(mods), after_fail
        self.reads = []

    def _readable_ranges(self, address, size):
        return list(self.spans)

    def _read(self, address, size):
        self.reads.append((address, size))
        end = address + size
        for lo, n in self.bad:
            if lo < end and address < lo + n:
                self._failed()
                raise MemoryReadError(address, size, 'bad span')
        if not any(lo <= address and end <= lo + n for lo, n in self.spans):
            self._failed()
            raise MemoryReadError(address, size, 'unmapped')
        return _pattern(address, size)

    def _failed(self):
        if self.after_fail is not None:
            self.spans, self.after_fail = list(self.after_fail), None

    def modules(self):
        return list(self.mods)


class _Spy(MemorySource):
    """Wraps a source and logs every public call made on it."""

    def __init__(self, inner):
        self.inner, self.calls = inner, []

    def read(self, address, size):
        self.calls.append(('read', address, size))
        return self.inner.read(address, size)

    def try_read(self, address, size):
        self.calls.append(('try_read', address, size))
        return self.inner.try_read(address, size)

    def readable(self, address, size=1):
        self.calls.append(('readable', address, size))
        return self.inner.readable(address, size)

    def readable_ranges(self, address, size):
        self.calls.append(('readable_ranges', address, size))
        return self.inner.readable_ranges(address, size)

    def modules(self):
        self.calls.append(('modules',))
        return self.inner.modules()


class _FreshPair(MemorySource):
    """A writable blob whose fresh view is a distinct object over the same bytes."""

    def __init__(self, data: bytearray, base: int, fresh_of=None):
        self.data, self.base, self._fresh_of = data, base, fresh_of
        self._fresh = None

    @property
    def fresh(self):
        if self._fresh_of is not None:
            return self
        if self._fresh is None:
            self._fresh = _FreshPair(self.data, self.base, fresh_of=self)
        return self._fresh

    def _read(self, address, size):
        off = address - self.base
        if off < 0 or off + size > len(self.data):
            raise MemoryReadError(address, size, 'outside')
        return bytes(self.data[off:off + size])

    def _readable_ranges(self, address, size):
        return [(self.base, len(self.data))]

    def _write(self, address, data):
        off = address - self.base
        if off < 0 or off + len(data) > len(self.data):
            raise MemoryWriteError(address, len(data), 'outside')
        self.data[off:off + len(data)] = data

    def modules(self):
        return [Module('pair.exe', self.base, 0x100)]


def _merge(spans):
    out = []
    for lo, hi in sorted(spans):
        if out and lo <= out[-1][1]:
            out[-1] = (out[-1][0], max(hi, out[-1][1]))
        else:
            out.append((lo, hi))
    return out


def _manifest(path) -> dict:
    with zipfile.ZipFile(path) as zf:
        return json.loads(zf.read('capture.json'))


def _rewrite(src, dst, *, manifest=None, drop=(), replace=None, stored=False):
    """Copy a capture zip, optionally with a new manifest, dropped members or replaced member bytes."""
    replace = replace or {}
    with zipfile.ZipFile(src) as zin, zipfile.ZipFile(dst, 'w', zipfile.ZIP_STORED if stored else zipfile.ZIP_DEFLATED) as zout:
        for info in zin.infolist():
            if info.filename in drop:
                continue
            if info.filename == 'capture.json' and manifest is not None:
                data = manifest if isinstance(manifest, bytes) else json.dumps(manifest).encode()
            else:
                data = replace.get(info.filename, zin.read(info.filename))
            zout.writestr(info.filename, data)


def _flip_stored_byte(path, member, offset=5):
    """Flip one byte of a ZIP_STORED member in place, leaving its CRC stale."""
    with zipfile.ZipFile(path) as zf:
        info = zf.getinfo(member)
        assert info.compress_type == zipfile.ZIP_STORED
        header_offset = info.header_offset
    with open(path, 'r+b') as f:
        f.seek(header_offset + 26)
        name_len, extra_len = int.from_bytes(f.read(2), 'little'), int.from_bytes(f.read(2), 'little')
        pos = header_offset + 30 + name_len + extra_len + offset
        f.seek(pos)
        b = f.read(1)[0]
        f.seek(pos)
        f.write(bytes([b ^ 0xFF]))


def _patch_directory(path, member, field, value, size):
    """Rewrite one field of a member's central-directory entry (42: local-header offset, 10: method, 6: version needed)."""
    raw = bytearray(pathlib.Path(path).read_bytes())
    with zipfile.ZipFile(path) as zf:
        pos = zf.start_dir
    while raw[pos:pos + 4] == b'PK\x01\x02':
        name_len, extra_len, comment_len = (int.from_bytes(raw[pos + k:pos + k + 2], 'little') for k in (28, 30, 32))
        if raw[pos + 46:pos + 46 + name_len].decode() == member:
            raw[pos + field:pos + field + size] = value.to_bytes(size, 'little')
            pathlib.Path(path).write_bytes(bytes(raw))
            return
        pos += 46 + name_len + extra_len + comment_len
    raise AssertionError(f'{member} not in central directory')


def _assert_released(path):
    """On Windows an open handle makes the rename fail, so this proves no handle leaked."""
    moved = str(path) + '.moved'
    os.replace(path, moved)
    os.replace(moved, path)


class ImageSourceTests(unittest.TestCase):
    def test_domain(self):
        with self.assertRaises(ValueError):
            ImageSource([(0x1000, b'a' * 16), (0x1008, b'b' * 16)])
        with self.assertRaises(ValueError):
            ImageSource([(0x1008, b'b' * 16), (0x1000, b'a' * 9)])
        img = ImageSource([(0x2000, b'B' * 0x10), (0x1FF0, b'A' * 0x10), (0x3000, b'C' * 0x10)])
        self.assertEqual(img.read(0x1FF8, 0x10), b'A' * 8 + b'B' * 8)
        self.assertIs(type(img.read(0x1FF8, 0x10)), bytes)
        self.assertEqual(img.read(0x1FF0, 0x20), b'A' * 16 + b'B' * 16)
        self.assertEqual(img.readable_ranges(0x1F00, 0x2000), [(0x1FF0, 0x20), (0x3000, 0x10)])
        self.assertEqual(img.readable_ranges(0x2008, 0x1000), [(0x2008, 0x8), (0x3000, 0x8)])
        self.assertTrue(img.readable(0x1FF0, 0x20))
        self.assertFalse(img.readable(0x1FF0, 0x21))
        self.assertFalse(img.readable(0x1FEF, 1))
        self.assertTrue(img.readable(0x300F, 1))
        self.assertFalse(img.readable(0x3010, 1))
        for addr, size, first in ((0x1FF8, 0x20, 0x2010), (0x1FEF, 2, 0x1FEF), (0x2010, 1, 0x2010), (0x2FFF, 2, 0x2FFF),
                                  (0x3008, 0x10, 0x3010), (0x10, 4, 0x10), (0x5000, 4, 0x5000), (0x1FF0, 0x21, 0x2010),
                                  (0x300F, 2, 0x3010)):
            with self.assertRaises(MemoryReadError) as cm:
                img.read(addr, size)
            self.assertEqual((cm.exception.address, cm.exception.size, cm.exception.reason), (addr, size, f'not in image at {first:#x}'))
            self.assertIsNone(img.try_read(addr, size))

        mods = [Module('game.exe', 0x1000, 0x100, 'C:/g/game.exe'), Module('late.dll', 0x5008, 0x100)]
        img = ImageSource([(0x1000, b'x' * 0x20), (0x1040, b'y' * 0x10), (0x5000, b'z' * 0x10), (0x9000, b'w')], mods)
        self.assertEqual(img.regions(), [
            Region(0x1000, 0x20, PAGE_READONLY, MEM_COMMIT, MEM_IMAGE),
            Region(0x1040, 0x10, PAGE_READONLY, MEM_COMMIT, MEM_IMAGE),
            Region(0x5000, 0x10, PAGE_READONLY, MEM_COMMIT, MEM_PRIVATE),  # the module holds a later byte, not the base
            Region(0x9000, 0x1, PAGE_READONLY, MEM_COMMIT, MEM_PRIVATE),
        ])
        self.assertEqual(img.modules(), mods)
        self.assertIsNot(img.modules(), img.modules())
        img.regions().clear()
        self.assertEqual(len(img.regions()), 4)
        self.assertEqual(img.main_module, mods[0])
        self.assertEqual(img.module_at(0x5010), mods[1])
        self.assertEqual([r.protect for r in ImageSource([(0x1000, b'x')], writable=True).regions()], [PAGE_READWRITE])
        self.assertEqual(ImageSource([(0x1000, b'x')], writable=1).writable, True)
        self.assertIs(ImageSource([(0x1000, b'x')], writable=[]).writable, False)

        for bad in ([(1.0, b'')], [(0x1000, 'abc')], [(0x1000, memoryview(b'ab'))], [(0x1000, b'a', 1)], [0x1000], [None]):
            with self.assertRaises(TypeError, msg=repr(bad)):
                ImageSource(bad)
        with self.assertRaises(TypeError):
            ImageSource([(0x1000, b'a')], [('game.exe', 0x1000, 0x10, '')])
        with self.assertRaises(ValueError):
            ImageSource([(-1, b'a')])
        with self.assertRaises(ValueError):
            ImageSource([(ADDRESS_LIMIT - 1, b'ab')])
        with self.assertRaises(ValueError):
            ImageSource([(0x1000, b'a')], meta={'x': object()})
        with self.assertRaises(TypeError):
            ImageSource([(0x1000, b'a')], meta=[])
        edge = ImageSource([(ADDRESS_LIMIT - 4, b'abcd')])
        self.assertEqual(edge.read(ADDRESS_LIMIT - 4, 4), b'abcd')

        self.assertEqual(ImageSource([(0x1000, b''), (0x2000, bytearray())]).regions(), [])
        self.assertEqual(ImageSource([(0x1000, b'abcd'), (0x1002, b'')]).read(0x1000, 4), b'abcd')
        src = bytearray(b'orig')
        img = ImageSource(((0x1000, src),))
        src[:] = b'XXXX'
        self.assertEqual(img.read(0x1000, 4), b'orig')
        self.assertEqual(img.meta, {})
        meta = {'k': [1, 2]}
        self.assertEqual(ImageSource([], meta=meta).meta, meta)
        self.assertIsNone(img.path)
        self.assertEqual(img.excluded, ())

    def test_write(self):
        ro = ImageSource([(0x1000, b'a' * 16)])
        with self.assertRaises(MemoryWriteError) as cm:
            ro.write(0x1000, b'x')
        self.assertEqual(cm.exception.reason, 'image is read-only')
        self.assertEqual(ro.read(0x1000, 16), b'a' * 16)
        ro.write(0x1000, b'')
        ro.write(0x9000, bytearray())

        img = ImageSource([(0x1000, b'a' * 16), (0x1010, b'b' * 16), (0x1030, b'c' * 16)], writable=True)
        for addr, data, first in ((0x101E, b'xyzw', 0x1020), (0x0FFE, b'xyzw', 0x0FFE), (0x1028, b'xxxxxxxxxx', 0x1028)):
            with self.assertRaises(MemoryWriteError) as cm:
                img.write(addr, data)
            self.assertEqual((cm.exception.address, cm.exception.size, cm.exception.reason), (addr, len(data), f'not in image at {first:#x}'))
        self.assertEqual(img.read(0x1000, 0x20), b'a' * 16 + b'b' * 16)
        self.assertEqual(img.read(0x1030, 0x10), b'c' * 16)
        img.write(0x100C, b'1234')
        img.write(0x101F, bytearray(b'Z'))
        img.write(0x1030, memoryview(b'MV'))
        self.assertEqual(img.read(0x1000, 0x20), b'a' * 12 + b'1234' + b'b' * 15 + b'Z')
        self.assertEqual(img.read(0x1030, 4), b'MVcc')
        img.write(0x1000, b'')
        self.assertEqual(len(img.regions()), 2)

    def test_fresh_close(self):
        img = ImageSource([(0x1000, b'abcd')])
        self.assertIs(img.fresh, img)
        img.close()
        img.close()
        self.assertEqual(img.read(0x1000, 4), b'abcd')
        with img as x:
            self.assertIs(x, img)
        self.assertEqual(img.try_read(0x1000, 4), b'abcd')
        self.assertIsNone(img.path)


class WriteCaptureTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = pathlib.Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def test_chunking(self):
        data = _rand(3 * CHUNK_SIZE)
        start = BASE + 0x80000
        img = ImageSource([(start, data)], [Module('game.exe', BASE, 0x400000, 'C:/game.exe')], meta={'game': 'x'})
        p = self.dir / 'c.zip'
        result = write_capture(p, img, [(start, len(data))], meta={'game': 'x'})
        self.assertEqual({k: result[k] for k in ('bytes', 'chunks', 'skipped_bytes')}, {'bytes': 3 * CHUNK_SIZE, 'chunks': 4, 'skipped_bytes': 0})
        self.assertIsInstance(result['seconds'], float)
        self.assertGreaterEqual(result['seconds'], 0)
        expected = [(start, 0x80000), (BASE + 0x100000, CHUNK_SIZE), (BASE + 0x200000, CHUNK_SIZE), (BASE + 0x300000, 0x80000)]
        doc = _manifest(p)
        self.assertEqual(doc['chunks'], [[a, n, _member(a)] for a, n in expected])
        self.assertEqual(doc['chunks'][0][2], 'chunks/00007FF600080000.bin')
        self.assertEqual((doc['format'], doc['version'], doc['pointer_size']), (CAPTURE_FORMAT, CAPTURE_VERSION, 8))
        self.assertEqual(('nylib.ue.capture', 1), (CAPTURE_FORMAT, CAPTURE_VERSION))
        self.assertEqual(doc['modules'], [['game.exe', BASE, 0x400000, 'C:/game.exe']])
        self.assertEqual(doc['excluded'], [])
        self.assertEqual(doc['meta'], {'game': 'x'})
        with zipfile.ZipFile(p) as zf:
            self.assertEqual(sorted(zf.namelist()), sorted(['capture.json'] + [_member(a) for a, _ in expected]))
            for a, n in expected:
                info = zf.getinfo(_member(a))
                self.assertEqual((info.file_size, info.compress_type), (n, zipfile.ZIP_DEFLATED))
                self.assertLessEqual(n, CHUNK_SIZE)
                self.assertEqual(a // CHUNK_SIZE, (a + n - 1) // CHUNK_SIZE)
                self.assertEqual(zf.read(_member(a)), data[a - start:a - start + n])
            self.assertEqual(zf.getinfo('capture.json').compress_type, zipfile.ZIP_DEFLATED)

        # overlapping and touching ranges merge; zero sizes are dropped
        p2 = self.dir / 'c2.zip'
        src = ImageSource([(BASE, _rand(0x3000, 2))])
        write_capture(str(p2), src, [(BASE + 0x2000, 0x800), (BASE, 0x1000), (BASE + 0x800, 0x1000), (BASE + 0x1800, 0x800), (BASE + 0x2F00, 0)])
        self.assertEqual(_manifest(p2)['chunks'], [[BASE, 0x2800, _member(BASE)]])

    def test_skips_unreadable(self):
        C = CHUNK_SIZE
        src = _GenSource([(BASE, 3 * C)], bad=[(BASE + C + 0x10, 8)])
        p = self.dir / 'c.zip'
        calls = []
        result = write_capture(p, src, [(BASE, 3 * C)], modules=[], progress=lambda d, t: calls.append((d, t)))
        self.assertEqual((result['bytes'], result['chunks'], result['skipped_bytes']), (2 * C, 2, C))
        self.assertEqual(src.reads, [(BASE, C), (BASE + C, C), (BASE + C, C), (BASE + 2 * C, C)])  # exactly one retry
        self.assertEqual(calls[-1], (3 * C, 3 * C))
        self.assertEqual(_manifest(p)['excluded'], [[BASE + C, C, 'read failed']])
        with ImageSource.load(p) as img:
            self.assertEqual(img.excluded, ((BASE + C, C, 'read failed'),))
            self.assertEqual(img.read(BASE, 16), _pattern(BASE, 16))
            self.assertEqual(img.read(BASE + 2 * C, 16), _pattern(BASE + 2 * C, 16))
            self.assertEqual(img.read(BASE + 3 * C - 16, 16), _pattern(BASE + 3 * C - 16, 16))
            for addr in (BASE + C, BASE + C - 4, BASE + C + 0x10, BASE + 2 * C - 4):
                with self.assertRaises(MemoryReadError) as cm:
                    img.read(addr, 8)
                self.assertEqual(cm.exception.reason, f'not captured at {max(addr, BASE + C):#x} (read failed)')
            self.assertIsNone(img.try_read(BASE + C + 0x100, 8))
            self.assertEqual(img.readable_ranges(BASE, 3 * C), [(BASE, C), (BASE + 2 * C, C)])

        # the first failure frees a page at each end of the next piece: the retry keeps what is still mapped,
        # adjacent failures merge, and a caller's exclusion touching them stays separate
        src = _GenSource([(BASE, 3 * C)], bad=[(BASE + 0x10, 8), (BASE + 2 * C + 0x20, 8)],
                         after_fail=[(BASE + 0x1000, 2 * C - 0x2000), (BASE + 2 * C, C)])
        p = self.dir / 'r.zip'
        calls.clear()
        result = write_capture(p, src, [(BASE, 3 * C)], modules=[], excluded=[(BASE + 3 * C, 0x10, 'MEM_MAPPED')],
                               progress=lambda d, t: calls.append((d, t)))
        self.assertEqual((result['bytes'], result['chunks'], result['skipped_bytes']), (2 * C - 0x2000, 2, C + 0x2000))
        self.assertEqual(src.reads, [(BASE, C), (BASE + 0x1000, C - 0x1000), (BASE + C, C), (BASE + C, C - 0x1000),
                                     (BASE + 2 * C, C), (BASE + 2 * C, C)])
        self.assertEqual(calls, [(C, 3 * C), (2 * C, 3 * C), (3 * C, 3 * C)])
        doc = _manifest(p)
        self.assertEqual(doc['chunks'], [[BASE + 0x1000, C - 0x1000, _member(BASE + 0x1000)], [BASE + C, C - 0x1000, _member(BASE + C)]])
        self.assertEqual(doc['excluded'], [[BASE, 0x1000, 'read failed'], [BASE + 2 * C - 0x1000, C + 0x1000, 'read failed'],
                                           [BASE + 3 * C, 0x10, 'MEM_MAPPED']])
        with ImageSource.load(p) as img:
            self.assertEqual(img.read(BASE + 0x1000, 2 * C - 0x2000), _pattern(BASE + 0x1000, 2 * C - 0x2000))
            self.assertEqual(img.readable_ranges(BASE, 4 * C), [(BASE + 0x1000, 2 * C - 0x2000)])
            for addr, reason in ((BASE + 8, 'read failed'), (BASE + 2 * C - 0x1000, 'read failed'), (BASE + 2 * C + 0x20, 'read failed'),
                                 (BASE + 3 * C - 1, 'read failed'), (BASE + 3 * C, 'MEM_MAPPED')):
                with self.assertRaises(MemoryReadError) as cm:
                    img.read(addr, 1)
                self.assertEqual(cm.exception.reason, f'not captured at {addr:#x} ({reason})')

        # only the readable pieces are read, split at CHUNK_SIZE boundaries
        src = _GenSource([(BASE + 0x1000, 0x1000), (BASE + CHUNK_SIZE - 0x800, 0x1000)])
        result = write_capture(self.dir / 'd.zip', src, [(BASE, 2 * CHUNK_SIZE)], modules=[])
        self.assertEqual(sorted(src.reads), [(BASE + 0x1000, 0x1000), (BASE + CHUNK_SIZE - 0x800, 0x800), (BASE + CHUNK_SIZE, 0x800)])
        self.assertEqual((result['bytes'], result['chunks'], result['skipped_bytes']), (0x2000, 3, 0))
        with ImageSource.load(self.dir / 'd.zip') as img:
            self.assertEqual(img.read(BASE + CHUNK_SIZE - 0x800, 0x1000), _pattern(BASE + CHUNK_SIZE - 0x800, 0x1000))
            self.assertEqual(img.regions()[1], Region(BASE + CHUNK_SIZE - 0x800, 0x1000, PAGE_READONLY, MEM_COMMIT, MEM_PRIVATE))

    def test_progress_and_atomicity(self):
        src = _GenSource([(BASE, 0x1000), (BASE + 0x2000, 2 * CHUNK_SIZE + 0x800)], mods=[Module('m', BASE, 0x10)])
        calls, synced = [], []
        p = self.dir / 'c.zip'

        def progress(done, total):
            calls.append((done, total))
            self.assertEqual([n.startswith('c.zip.') for n in os.listdir(self.dir) if n.endswith('.tmp')], [True])

        real_fsync, real_replace = os.fsync, os.replace
        with (mock.patch.object(os, 'fsync', lambda fd: (synced.append(('fsync', os.fstat(fd).st_size)), real_fsync(fd))[1]),
              mock.patch.object(os, 'replace', lambda a, b: (synced.append(('replace', os.path.dirname(a))), real_replace(a, b))[1])):
            write_capture(p, src, [(BASE, 3 * CHUNK_SIZE)], progress=progress)
        self.assertEqual(synced, [('fsync', p.stat().st_size), ('replace', str(self.dir))])
        total = 0x1000 + 2 * CHUNK_SIZE + 0x800
        self.assertEqual([t for _, t in calls], [total] * len(calls))
        self.assertEqual(len(calls), 4)
        done = [d for d, _ in calls]
        self.assertEqual(done, sorted(set(done)))
        self.assertEqual(done[-1], total)
        self.assertEqual(_manifest(p)['modules'], [['m', BASE, 0x10, '']])

        class Boom(Exception):
            pass

        def failing(done, total):
            if done > CHUNK_SIZE:
                raise Boom

        target = self.dir / 'old.zip'
        target.write_bytes(b'old contents')
        with self.assertRaises(Boom):
            write_capture(target, src, [(BASE, 3 * CHUNK_SIZE)], progress=failing)
        self.assertEqual(target.read_bytes(), b'old contents')
        self.assertEqual(sorted(os.listdir(self.dir)), ['c.zip', 'old.zip'])
        with self.assertRaises(Boom):
            write_capture(self.dir / 'new.zip', src, [(BASE, 3 * CHUNK_SIZE)], progress=failing)
        self.assertEqual(sorted(os.listdir(self.dir)), ['c.zip', 'old.zip'])

        class ExplodingModules(_GenSource):
            def modules(self):
                raise KeyError('no modules here')

        with self.assertRaises(KeyError):
            write_capture(self.dir / 'm.zip', ExplodingModules([(BASE, 0x10)]), [(BASE, 0x10)])
        self.assertEqual(sorted(os.listdir(self.dir)), ['c.zip', 'old.zip'])

        # argument errors are raised before the source is read and before any file exists
        src = _GenSource([(BASE, 0x1000)])
        bad_calls = [
            (TypeError, dict(path=123)), (TypeError, dict(path=b'x.zip')), (TypeError, dict(progress='nope')),
            (TypeError, dict(ranges=[(1.0, 4)])), (TypeError, dict(ranges=[(BASE,)])), (TypeError, dict(ranges=[None])),
            (ValueError, dict(ranges=[(BASE, -1)])),
            (TypeError, dict(meta=[])), (ValueError, dict(meta={'x': {1, 2}})),
            (TypeError, dict(modules=[('m', 1, 2, '')])),
            (ValueError, dict(excluded=[(BASE + 0xFFF, 1, 'MEM_MAPPED')])),
            (ValueError, dict(excluded=[(BASE - 0x10, 0x11, 'MEM_MAPPED')])),
            (TypeError, dict(excluded=[(BASE + 0x2000, 1)])),
        ]
        for exc, kw in bad_calls:
            args = dict(path=self.dir / 'bad.zip', source=src, ranges=[(BASE, 0x1000)]) | kw
            with self.assertRaises(exc, msg=repr(kw)):
                write_capture(args.pop('path'), args.pop('source'), args.pop('ranges'), **args)
            self.assertEqual(src.reads, [], msg=repr(kw))
            self.assertEqual(sorted(os.listdir(self.dir)), ['c.zip', 'old.zip'], msg=repr(kw))

    def test_replace_retry(self):
        # a PermissionError from os.replace (a scanner briefly holding the fresh file) is retried with backoff
        src = _GenSource([(BASE, 0x1000)])
        p = self.dir / 'retry.zip'
        real_replace, calls, sleeps = os.replace, [], []

        def flaky(a, b):
            calls.append((a, b))
            if len(calls) <= 2:
                raise PermissionError(f"[WinError 5] Access is denied: '{a}'")
            real_replace(a, b)

        with mock.patch.object(os, 'replace', flaky), mock.patch.object(time, 'sleep', lambda s: sleeps.append(s)):
            write_capture(p, src, [(BASE, 0x1000)], modules=[])
        self.assertEqual(len(calls), 3)
        self.assertEqual(sleeps, [0.1, 0.2])
        tmp = calls[0][0]
        self.assertFalse(os.path.exists(tmp))
        self.assertTrue(p.exists())
        with ImageSource.load(p) as img:
            self.assertEqual(img.read(BASE, 0x10), _pattern(BASE, 0x10))

    def test_replace_retry_exhausted(self):
        # a PermissionError still raised after 10 retries keeps the complete temp file instead of deleting it
        src = _GenSource([(BASE, 0x1000)])
        p = self.dir / 'stuck.zip'
        calls, sleeps = [], []

        def always_locked(a, b):
            calls.append((a, b))
            raise PermissionError(f"[WinError 5] Access is denied: '{a}'")

        with mock.patch.object(os, 'replace', always_locked), mock.patch.object(time, 'sleep', lambda s: sleeps.append(s)):
            with self.assertRaises(PermissionError) as cm:
                write_capture(p, src, [(BASE, 0x1000)], modules=[])
        self.assertEqual(len(calls), 11)
        self.assertEqual(sleeps, [0.1, 0.2, 0.4, 0.8, 1.6, 1.6, 1.6, 1.6, 1.6, 1.6])
        tmp = calls[0][0]
        self.assertIn(str(tmp), str(cm.exception))
        self.assertFalse(p.exists())
        with ImageSource.load(tmp, verify=True) as img:
            self.assertEqual(img.read(BASE, 0x10), _pattern(BASE, 0x10))
        os.remove(tmp)

    def test_replace_other_error_removes_tmp(self):
        # a non-PermissionError from os.replace is not retried and removes the temp file, as before
        src = _GenSource([(BASE, 0x1000)])
        p = self.dir / 'boom.zip'
        calls = []

        def boom(a, b):
            calls.append((a, b))
            raise OSError('disk full')

        with mock.patch.object(os, 'replace', boom):
            with self.assertRaises(OSError):
                write_capture(p, src, [(BASE, 0x1000)], modules=[])
        self.assertEqual(len(calls), 1)
        tmp = calls[0][0]
        self.assertFalse(os.path.exists(tmp))
        self.assertFalse(p.exists())

    def test_bounded_memory(self):
        size = 64 * CHUNK_SIZE
        src = _GenSource([(BASE, size)])
        p = self.dir / 'big.zip'
        tracemalloc.start()
        try:
            result = write_capture(p, src, [(BASE, size)], modules=[])
            peak = tracemalloc.get_traced_memory()[1]
        finally:
            tracemalloc.stop()
        print(f'\nwrite_capture of {size >> 20} MiB: tracemalloc peak {peak / 2 ** 20:.2f} MiB', file=sys.stderr)
        self.assertEqual((result['bytes'], result['chunks']), (size, 64))
        self.assertLess(peak, 16 * 2 ** 20)
        with ImageSource.load(p, max_resident_bytes=CHUNK_SIZE) as img:
            for a in (BASE, BASE + 17 * CHUNK_SIZE + 0x123, BASE + size - 8):
                self.assertEqual(img.read(a, 8), _pattern(a, 8))

    def test_zip64_member_count(self):
        n = 70000  # past the 65535 members a zip without ZIP64 can hold
        p = self.dir / 'many.zip'
        result = write_capture(p, ImageSource([(BASE + 2 * i, bytes([i & 0xFF])) for i in range(n)]), [(BASE, 2 * n)], modules=[])
        self.assertEqual((result['bytes'], result['chunks']), (n, n))
        with ImageSource.load(p) as img:
            self.assertEqual(len(img.regions()), n)
            self.assertEqual(img.read(BASE + 2 * (n - 1), 1), bytes([(n - 1) & 0xFF]))

    def test_wide_ranges(self):
        R = Region
        regions = [
            R(0x40000, 0x1000, 0x04, MEM_COMMIT, MEM_PRIVATE),          # captured
            R(0x10000, 0x2000, PAGE_EXECUTE_READ, MEM_COMMIT, MEM_IMAGE),  # captured
            R(0x12000, 0x1000, 0x02, MEM_COMMIT, MEM_IMAGE),             # captured, adjacent: not merged
            R(0x20000, 0x1000, 0x02, MEM_COMMIT, MEM_MAPPED),
            R(0x21000, 0x1000, 0x204, MEM_COMMIT, MEM_PRIVATE),
            R(0x22000, 0x1000, 0x404, MEM_COMMIT, MEM_PRIVATE),
            R(0x23000, 0x1000, 0x204, MEM_COMMIT, MEM_MAPPED),
            R(0x24000, 0x1000, 0x604, MEM_COMMIT, MEM_IMAGE),
            R(0x25000, 0x1000, 0x04, MEM_COMMIT, 0x80000),
            R(0x26000, 0x1000, PAGE_NOACCESS, MEM_COMMIT, MEM_PRIVATE),
            R(0x27000, 0x1000, 0x04 | PAGE_GUARD, MEM_COMMIT, MEM_PRIVATE),
            R(0x28000, 0x1000, 0x04, MEM_RESERVE, MEM_PRIVATE),
            R(0x29000, 0x1000, 0, 0x10000, 0),
        ]
        ranges, excluded = wide_capture_ranges(iter(regions))
        self.assertEqual(ranges, [(0x10000, 0x2000), (0x12000, 0x1000), (0x40000, 0x1000)])
        self.assertEqual(excluded, [
            (0x20000, 0x1000, 'MEM_MAPPED'), (0x21000, 0x1000, 'PAGE_NOCACHE'), (0x22000, 0x1000, 'PAGE_WRITECOMBINE'),
            (0x23000, 0x1000, 'MEM_MAPPED'), (0x24000, 0x1000, 'PAGE_NOCACHE'), (0x25000, 0x1000, 'type 0x80000'),
        ])
        self.assertEqual(wide_capture_ranges([]), ([], []))
        with self.assertRaises(TypeError):
            wide_capture_ranges([regions[0], (0x1000, 0x1000, 4, MEM_COMMIT, MEM_PRIVATE)])
        # the recipe feeds write_capture directly
        src = ImageSource([(0x10000, _rand(0x3000, 3)), (0x40000, _rand(0x1000, 4))])
        p = self.dir / 'w.zip'
        write_capture(p, src, ranges, modules=[], excluded=excluded)
        with ImageSource.load(p) as img:
            self.assertEqual(img.excluded, tuple(excluded))
            self.assertEqual(img.read(0x10000, 0x3000), src.read(0x10000, 0x3000))


class CaptureTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = pathlib.Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def _load_error(self, p, **kw) -> CaptureError:
        try:
            ImageSource.load(p, **kw)
        except CaptureError as e:
            err = e  # keeps the failing frames (and any leaked handle) alive
        else:
            self.fail(f'load({p}) did not raise')
        self.assertEqual(err.path, str(p))
        _assert_released(p)
        return err

    def _valid(self) -> pathlib.Path:
        p = self.dir / 'valid.zip'
        img = ImageSource([(BASE, _rand(0x100, 5)), (BASE + CHUNK_SIZE, _rand(0x200, 6))],
                          [Module('g.exe', BASE, 0x1000, 'C:/g.exe')], meta={'a': 1}, excluded=[(BASE + 0x1000, 0x10, 'MEM_MAPPED')])
        img.save(p)
        return p

    def test_roundtrip(self):
        segs = [(BASE, _rand(CHUNK_SIZE + 0x345, 7)), (BASE + 0x200000, _rand(0x10, 8)), (BASE + 0x300000 - 0x10, _rand(0x20, 9))]
        mods = [Module('game.exe', BASE, 0x1000, 'C:/Games/game.exe'), Module('x.dll', BASE + 0x300000, 0x10, '')]
        meta = {'engine': 'UE5', 'nested': {'list': [1, 2.5, None, True], 'u': '\u00e9'}}
        img = ImageSource(segs, mods, meta=meta, writable=True)
        p = self.dir / 'rt.zip'
        self.assertIsNone(img.save(p))
        with ImageSource.load(p) as got:
            for a, data in segs:
                self.assertEqual(got.read(a, len(data)), data)
            self.assertEqual(got.read(BASE + 0x300000 - 0x10, 0x20), segs[2][1])
            self.assertEqual(got.modules(), mods)
            self.assertEqual(got.meta, meta)
            self.assertIs(got.writable, False)
            self.assertEqual(got.path, str(p))
            self.assertEqual(got.excluded, ())
            self.assertEqual(got.regions(), [Region(r.base, r.size, PAGE_READONLY, r.state, r.type) for r in img.regions()])
            self.assertEqual(len(got.regions()), 3)
            with self.assertRaises(MemoryWriteError):
                got.write(BASE, b'x')
            self.assertEqual(got.fresh, got)
        with ImageSource.load(str(p), max_resident_bytes=CHUNK_SIZE) as got:
            self.assertEqual(got.path, str(p))
            self.assertEqual(got.u64(BASE + CHUNK_SIZE - 4), int.from_bytes(segs[0][1][CHUNK_SIZE - 4:CHUNK_SIZE + 4], 'little'))
        future = self.dir / 'future.zip'  # a later writer's additive key and extra member
        _rewrite(p, future, manifest=_manifest(p) | {'future_key': {'x': [1]}})
        with zipfile.ZipFile(future, 'a') as zf:
            zf.writestr('notes/extra.txt', b'not a chunk')
        with ImageSource.load(future, verify=True) as got:
            self.assertEqual((got.read(BASE, 0x10), got.meta, got.modules()), (segs[0][1][:0x10], meta, mods))
            self.assertEqual(len(got.regions()), 3)
        empty = self.dir / 'empty.zip'
        ImageSource([]).save(empty)
        with ImageSource.load(empty) as got:
            self.assertEqual((got.regions(), got.modules(), got.meta), ([], [], {}))

    def test_lazy(self):
        names = []
        real_open = zipfile.ZipFile.open

        def counting_open(zf, name, *args, **kwargs):
            n = name.filename if isinstance(name, zipfile.ZipInfo) else name
            if n.startswith('chunks/'):
                names.append(n)
            return real_open(zf, name, *args, **kwargs)

        A, B, C = BASE, BASE + CHUNK_SIZE, BASE + 2 * CHUNK_SIZE
        p = self.dir / 'lazy.zip'
        ImageSource([(A, _rand(3 * CHUNK_SIZE, 10))]).save(p)
        with mock.patch.object(zipfile.ZipFile, 'open', counting_open):
            with ImageSource.load(p, max_resident_bytes=CHUNK_SIZE) as img:
                self.assertEqual(names, [])
                for a in (A, B, A):
                    img.read(a + 8, 8)
                self.assertEqual(names, [_member(A), _member(B), _member(A)])
            names.clear()
            with ImageSource.load(p, max_resident_bytes=3 * CHUNK_SIZE) as img:
                for a in (A, B, A):
                    img.read(a + 8, 8)
                self.assertEqual(names, [_member(A), _member(B)])
            names.clear()
            with ImageSource.load(p, max_resident_bytes=2 * CHUNK_SIZE) as img:
                for a in (A, B, A, C, A, B):  # C evicts B, the least recently used
                    img.read(a, 8)
                self.assertEqual(names, [_member(A), _member(B), _member(C), _member(B)])
            names.clear()
            with ImageSource.load(p, max_resident_bytes=2 * CHUNK_SIZE - 1) as img:
                img.read(A, 8)
                img.read(B, 8)
                img.read(A, 8)
                self.assertEqual(names, [_member(A), _member(B), _member(A)])
            names.clear()
            with ImageSource.load(p, verify=True) as img:
                self.assertEqual(sorted(names), [_member(A), _member(B), _member(C)])
            names.clear()
            with ImageSource.load(p) as img:
                img.read(B - 4, 8)  # one read spanning two chunks
                self.assertTrue(img.readable(A, 3 * CHUNK_SIZE))
                img.regions()
                self.assertEqual(names, [_member(A), _member(B)])

            half = self.dir / 'half.zip'
            ImageSource([(A, _rand(0x80000, 11)), (B, _rand(0x80000, 12))]).save(half)
            names.clear()
            with ImageSource.load(half, max_resident_bytes=CHUNK_SIZE) as img:
                for a in (A, B, A, B):
                    img.read(a, 8)
                self.assertEqual(names, [_member(A), _member(B)])

            mixed, third, D = self.dir / 'mixed.zip', CHUNK_SIZE // 3, C + CHUNK_SIZE
            ImageSource([(A, _rand(third, 24)), (B, _rand(third, 25)), (C, _rand(third, 26)), (D, _rand(CHUNK_SIZE, 27))]).save(mixed)
            img = ImageSource.load(mixed, max_resident_bytes=CHUNK_SIZE)
            with img:
                for a in (A, B, C, D, A, B):  # D evicts all three small chunks, A evicts D
                    img.read(a, 8)
                    self.assertLessEqual(img._resident, CHUNK_SIZE)
                    self.assertEqual(img._resident, sum(len(v) for v in img._lru.values()))
                self.assertEqual(list(img._lru), [_member(A), _member(B)])
            self.assertEqual((len(img._lru), img._resident), (0, 0))

    def test_errors(self):
        good = self._valid()
        doc = _manifest(good)
        (junk := self.dir / 'junk.zip').write_bytes(b'this is not a zip file at all' * 4)
        self.assertEqual(self._load_error(junk).reason, 'not a zip archive')
        (empty := self.dir / 'empty.zip').write_bytes(b'')
        self.assertEqual(self._load_error(empty).reason, 'not a zip archive')

        def case(reason, *, manifest=None, drop=(), replace=None):
            p = self.dir / 'case.zip'
            _rewrite(good, p, manifest=manifest, drop=drop, replace=replace)
            err = self._load_error(p)
            if reason is not None:
                self.assertEqual(err.reason, reason)
            return err

        c0, c1 = doc['chunks']
        case('capture.json missing', drop=('capture.json',))
        self.assertTrue(case(None, manifest=b'{"format": ').reason.startswith('capture.json is not JSON'))
        case(None, manifest=b'\xff\xfe\x00garbage')
        case('capture.json is not an object', manifest=b'[]')
        case('capture.json is not an object', manifest=b'"text"')
        case("format 'nylib.ue.snapshot' is not 'nylib.ue.capture'", manifest=doc | {'format': 'nylib.ue.snapshot'})
        case('unsupported version 2', manifest=doc | {'version': 2})
        case("unsupported version '1'", manifest=doc | {'version': '1'})
        case('unsupported version True', manifest=doc | {'version': True})
        case('unsupported version None', manifest={k: v for k, v in doc.items() if k != 'version'})
        case('unsupported pointer_size 4', manifest=doc | {'pointer_size': 4})
        case(f'member {c1[2]} missing', drop=(c1[2],))
        case(f'member {c0[2]} holds 255 bytes, chunk says 256', replace={c0[2]: b'x' * 0xFF})
        case(f'member {c0[2]} holds 257 bytes, chunk says 256', replace={c0[2]: b'x' * 0x101})
        a = BASE + 0x80
        ov = doc | {'chunks': [c0, [a, 0x100, _member(a)]]}
        p = self.dir / 'ov.zip'
        _rewrite(good, p, manifest=ov, replace={_member(a): b'y' * 0x100})
        self.assertEqual(self._load_error(p).reason, 'chunks[1] overlaps or is out of order')
        case('chunks[1] overlaps or is out of order', manifest=doc | {'chunks': [c1, c0]})
        case('chunks[1] overlaps or is out of order', manifest=doc | {'chunks': [c0, c0]})
        case('chunks[0] crosses a chunk boundary', manifest=doc | {'chunks': [[BASE + CHUNK_SIZE - 8, 16, _member(BASE + CHUNK_SIZE - 8)]]})
        case('chunks[0] has an invalid address or size', manifest=doc | {'chunks': [[BASE, CHUNK_SIZE + 1, _member(BASE)]]})
        case('chunks[0] has an invalid address or size', manifest=doc | {'chunks': [[BASE, 0, _member(BASE)]]})
        case('chunks[0] has an invalid address or size', manifest=doc | {'chunks': [[-0x100, 0x100, 'chunks/neg.bin']]})
        case('chunks[0] has an invalid address or size', manifest=doc | {'chunks': [[ADDRESS_LIMIT, 1, _member(ADDRESS_LIMIT)]]})
        case('chunks[0] is malformed', manifest=doc | {'chunks': [[BASE, 0x100]]})
        case('chunks[0] is malformed', manifest=doc | {'chunks': [[BASE, 256.0, c0[2]]]})
        case('chunks[1] is malformed', manifest=doc | {'chunks': [c0, {'a': 1}]})
        case("chunks[0] names member 'chunks/x.bin'", manifest=doc | {'chunks': [[BASE, 0x100, 'chunks/x.bin']]})
        case(f"chunks[0] names member '{c0[2].lower()}'", manifest=doc | {'chunks': [[BASE, 0x100, c0[2].lower()]]})
        case('chunks is not a list', manifest=doc | {'chunks': {}})
        case('chunks is not a list', manifest={k: v for k, v in doc.items() if k != 'chunks'})
        case('modules[0] is malformed', manifest=doc | {'modules': [['a', 1, 2]]})
        case('modules[0] is malformed', manifest=doc | {'modules': [['a', -1, 2, '']]})
        case('modules[0] is malformed', manifest=doc | {'modules': [['a', 1, -2, '']]})
        case('modules[1] is malformed', manifest=doc | {'modules': [['a', 1, 2, ''], [1, 1, 2, '']]})
        case('modules is not a list', manifest=doc | {'modules': 'game.exe'})
        case('meta is not an object', manifest=doc | {'meta': []})
        case('meta is not an object', manifest={k: v for k, v in doc.items() if k != 'meta'})
        for member in (c1[2], 'capture.json'):
            p = self.dir / 'offset.zip'
            _rewrite(good, p)
            _patch_directory(p, member, 42, 0x7FFF_FFF0, 4)
            self.assertEqual(self._load_error(p).reason, f'member {member} has an invalid offset')
        for member, method in ((c0[2], 12), (c0[2], 93), ('capture.json', 14)):  # BZIP2, Zstandard (zipfile 3.14+), LZMA
            p = self.dir / 'method.zip'
            _rewrite(good, p)
            _patch_directory(p, member, 10, method, 2)
            self.assertEqual(self._load_error(p).reason, f'member {member} uses compression method {method}')
        case(f'excluded range overlaps a chunk at {BASE + CHUNK_SIZE + 0x10:#x}', manifest=doc | {'excluded': [[BASE + CHUNK_SIZE + 0x10, 4, 'r']]})
        p = self.dir / 'version.zip'
        _rewrite(good, p)
        _patch_directory(p, c0[2], 6, 0xF9, 2)  # zipfile raises NotImplementedError for this
        self.assertEqual(self._load_error(p).reason, 'not a zip archive')

        with self.assertRaises(FileNotFoundError):
            ImageSource.load(self.dir / 'missing.zip')
        with self.assertRaises(ValueError):
            ImageSource.load(good, max_resident_bytes=10)
        with self.assertRaises(ValueError):
            ImageSource.load(good, max_resident_bytes=CHUNK_SIZE - 1)
        with self.assertRaises(TypeError):
            ImageSource.load(good, max_resident_bytes='10')
        with self.assertRaises(TypeError):
            ImageSource.load(123)
        ImageSource.load(good, max_resident_bytes=CHUNK_SIZE).close()
        _assert_released(good)

    def test_corrupt_member(self):
        src = ImageSource([(BASE, _rand(0x2000, 13)), (BASE + CHUNK_SIZE, _rand(0x100, 14))])
        for stored in (True, False):
            deflated = self.dir / 'deflated.zip'
            src.save(deflated)
            p = self.dir / 'corrupt.zip'
            if stored:
                _rewrite(deflated, p, stored=True)
                _flip_stored_byte(p, _member(BASE), offset=0x123)
            else:
                _rewrite(deflated, p)
                with zipfile.ZipFile(p) as zf:
                    blob = zf.getinfo(_member(BASE))
                    start = blob.header_offset + 30 + len(blob.filename.encode()) + len(blob.extra)
                    mid = start + blob.compress_size // 2
                raw = bytearray(p.read_bytes())
                raw[mid:mid + 16] = bytes(b ^ 0x5A for b in raw[mid:mid + 16])
                p.write_bytes(bytes(raw))
            with self.subTest(stored=stored):
                with ImageSource.load(p) as img:
                    for call in (lambda: img.read(BASE + 8, 8), lambda: img.try_read(BASE, 1), lambda: img.u64(BASE + 0x1FF8)):
                        with self.assertRaises(CaptureError) as cm:
                            call()
                        self.assertEqual((cm.exception.path, cm.exception.reason), (str(p), f'corrupt member {_member(BASE)}'))
                    self.assertEqual(img.read(BASE + CHUNK_SIZE, 0x100), src.read(BASE + CHUNK_SIZE, 0x100))
                    self.assertTrue(img.readable(BASE, 0x2000))
                err = self._load_error(p, verify=True)
                self.assertEqual(err.reason, f'corrupt member {_member(BASE)}')
        with ImageSource.load(deflated, verify=True) as img:
            self.assertEqual(img.read(BASE, 0x2000), src.read(BASE, 0x2000))

    def test_closed(self):
        p = self._valid()
        img = ImageSource.load(p)
        self.assertEqual(img.read(BASE, 4), _rand(0x100, 5)[:4])
        regions, modules = img.regions(), img.modules()
        img.close()
        with self.assertRaisesRegex(ValueError, '^capture is closed$'):
            img.read(BASE, 4)
        with self.assertRaisesRegex(ValueError, '^capture is closed$'):
            img.try_read(BASE + CHUNK_SIZE, 4)
        with self.assertRaisesRegex(ValueError, '^capture is closed$'):
            img.read(BASE + 0x1000, 4)
        self.assertTrue(img.readable(BASE, 0x100))
        self.assertFalse(img.readable(BASE, 0x101))
        self.assertTrue(img.valid_ptr(BASE + CHUNK_SIZE, 8))
        self.assertEqual(img.readable_ranges(BASE, 2 * CHUNK_SIZE), [(BASE, 0x100), (BASE + CHUNK_SIZE, 0x200)])
        self.assertEqual((img.regions(), img.modules()), (regions, modules))
        img.close()
        os.remove(p)  # fails on Windows while the zip is open

        p = self._valid()
        with ImageSource.load(p) as img:
            self.assertEqual(img.u8(BASE), _rand(0x100, 5)[0])
            before = set(os.listdir(self.dir))
            with mock.patch.object(time, 'sleep', lambda s: None):
                with self.assertRaises(OSError):
                    img.save(p)  # replacing the file this image reads from: the lock never clears, so retries
                    # exhaust and the complete temp file is kept (contract F9) instead of being deleted
            tmp = self.dir / (set(os.listdir(self.dir)) - before).pop()
            with ImageSource.load(tmp, verify=True) as kept:
                self.assertEqual(kept.read(BASE, 4), _rand(0x100, 5)[:4])
            os.remove(tmp)
            self.assertEqual(sorted(os.listdir(self.dir)), ['valid.zip'])
            self.assertEqual(img.read(BASE + CHUNK_SIZE, 4), _rand(0x200, 6)[:4])
        with self.assertRaises(ValueError):
            img.read(BASE, 1)
        os.remove(p)

        with self.assertRaises(ValueError):
            with ImageSource.load(self._valid()) as img:
                raise ValueError('inside')
        with self.assertRaisesRegex(ValueError, 'closed'):
            img.read(BASE, 1)
        _assert_released(self.dir / 'valid.zip')

    def test_excluded(self):
        x = BASE + 0x3000
        src = ImageSource([(BASE, _rand(0x2000, 15))])
        p = self.dir / 'ex.zip'
        write_capture(p, src, [(BASE, 0x2000)], excluded=[(x + 0x4000, 0x10, 'PAGE_NOCACHE'), (x, 0x1000, 'MEM_MAPPED')])
        self.assertEqual(_manifest(p)['excluded'], [[x, 0x1000, 'MEM_MAPPED'], [x + 0x4000, 0x10, 'PAGE_NOCACHE']])
        with ImageSource.load(p) as img:
            self.assertEqual(img.excluded, ((x, 0x1000, 'MEM_MAPPED'), (x + 0x4000, 0x10, 'PAGE_NOCACHE')))
            for addr, reason in ((x, f'not captured at {x:#x} (MEM_MAPPED)'),
                                 (x + 0xFF8, f'not captured at {x + 0xFF8:#x} (MEM_MAPPED)'),
                                 (x + 0xFF9, f'not captured at {x + 0xFF9:#x} (MEM_MAPPED)'),
                                 (x + 0x1000, f'not in image at {x + 0x1000:#x}'),
                                 (x - 4, f'not in image at {x - 4:#x}'),
                                 (BASE + 0x1FFC, f'not in image at {BASE + 0x2000:#x}'),
                                 (x + 0x400F, f'not captured at {x + 0x400F:#x} (PAGE_NOCACHE)'),
                                 (x + 0x4010, f'not in image at {x + 0x4010:#x}'),
                                 (BASE - 8, f'not in image at {BASE - 8:#x}')):
                with self.assertRaises(MemoryReadError) as cm:
                    img.read(addr, 8)
                self.assertEqual(cm.exception.reason, reason, msg=hex(addr))
            self.assertFalse(img.readable(x, 8))
            self.assertEqual(img.readable_ranges(BASE, 0x10000), [(BASE, 0x2000)])
            self.assertEqual([(r.base, r.size) for r in img.regions()], [(BASE, 0x2000)])
            p2 = self.dir / 'ex2.zip'
            img.save(p2)
        with ImageSource.load(p2) as img2:
            self.assertEqual(img2.excluded, ((x, 0x1000, 'MEM_MAPPED'), (x + 0x4000, 0x10, 'PAGE_NOCACHE')))

        # in-memory images answer the same way
        mem = ImageSource([(BASE, b'a' * 0x10)], excluded=[(BASE + 0x10, 0x10, 'MEM_MAPPED')])
        with self.assertRaises(MemoryReadError) as cm:
            mem.read(BASE + 8, 16)
        self.assertEqual(cm.exception.reason, f'not captured at {BASE + 0x10:#x} (MEM_MAPPED)')
        self.assertEqual(mem.excluded, ((BASE + 0x10, 0x10, 'MEM_MAPPED'),))
        self.assertEqual(ImageSource([], excluded=[[BASE, 1, 'r']]).excluded, ((BASE, 1, 'r'),))
        self.assertEqual(len(ImageSource([], excluded=[(BASE, 1, 'r'), (BASE + 1, 1, 's')]).excluded), 2)

        # a manifest without the key has no excluded ranges
        doc = _manifest(p)
        p3 = self.dir / 'noex.zip'
        _rewrite(p, p3, manifest={k: v for k, v in doc.items() if k != 'excluded'})
        with ImageSource.load(p3) as img:
            self.assertEqual(img.excluded, ())
            with self.assertRaises(MemoryReadError) as cm:
                img.read(x, 8)
            self.assertEqual(cm.exception.reason, f'not in image at {x:#x}')

        bad_manifests = [
            ([[BASE + 0x1FFF, 2, 'MEM_MAPPED']], 'excluded range overlaps a chunk at 0x7ff600001fff'),
            ([[BASE - 1, 2, 'MEM_MAPPED']], f'excluded range overlaps a chunk at {BASE:#x}'),
            ([[x, 0x10, 'r'], [x + 8, 0x10, 'r']], 'excluded[1] overlaps or is out of order'),
            ([[x + 0x20, 0x10, 'r'], [x, 0x10, 'r']], 'excluded[1] overlaps or is out of order'),
            ([[x, 0, 'r']], 'excluded[0] has an invalid address, size or reason'),
            ([[x, 0x10, '']], 'excluded[0] has an invalid address, size or reason'),
            ([[-0x10, 0x10, 'r']], 'excluded[0] has an invalid address, size or reason'),
            ([[x, 0x10]], 'excluded[0] is malformed'),
            ([[x, 0x10, 5]], 'excluded[0] is malformed'),
            ({}, 'excluded is not a list'),
        ]
        for value, reason in bad_manifests:
            p4 = self.dir / 'badex.zip'
            _rewrite(p, p4, manifest=doc | {'excluded': value})
            self.assertEqual(self._load_error(p4).reason, reason, msg=repr(value))
        adjacent = self.dir / 'adj.zip'
        _rewrite(p, adjacent, manifest=doc | {'excluded': [[BASE - 0x10, 0x10, 'r'], [BASE + 0x2000, 0x10, 'r'], [BASE + 0x2010, 1, 's']]})
        ImageSource.load(adjacent).close()

        # write_capture and the constructor check exclusions against the data before anything happens
        spy = _Spy(src)
        for bad in ([(BASE + 0x1FFF, 1, 'MEM_MAPPED')], [(BASE - 0x10, 0x20, 'MEM_MAPPED')], [(x, 0x10, 'a'), (x + 0xF, 1, 'b')],
                    [(x, 0, 'a')], [(x, 1, '')], [(-1, 1, 'a')], [(ADDRESS_LIMIT - 1, 2, 'a')]):
            with self.assertRaises(ValueError, msg=repr(bad)):
                write_capture(self.dir / 'never.zip', spy, [(BASE, 0x1000), (BASE + 0x1000, 0x1000)], modules=[], excluded=bad)
        for bad in ([(1.0, 2, 'r')], [(x, 2)], [(x, 2, b'r')], [x]):
            with self.assertRaises(TypeError, msg=repr(bad)):
                write_capture(self.dir / 'never.zip', spy, [(BASE, 0x1000)], modules=[], excluded=bad)
            with self.assertRaises(TypeError, msg=repr(bad)):
                ImageSource([(BASE, b'a')], excluded=bad)
        self.assertEqual(spy.calls, [])
        self.assertFalse((self.dir / 'never.zip').exists())
        with self.assertRaises(ValueError):
            ImageSource([(BASE, b'a' * 0x10)], excluded=[(BASE + 0xF, 0x10, 'MEM_MAPPED')])
        with self.assertRaises(ValueError):
            ImageSource([(BASE, b'a' * 0x10), (BASE + 0x20, b'b')], excluded=[(BASE + 0x10, 0x11, 'MEM_MAPPED')])
        ImageSource([(BASE, b'a' * 0x10), (BASE + 0x20, b'b')], excluded=[(BASE + 0x10, 0x10, 'MEM_MAPPED')])

    def test_random_layouts(self):
        C = CHUNK_SIZE
        for seed in range(16):
            rng = random.Random(seed)
            points = sorted({BASE + k * C + rng.choice((-2, -1, 0, 1, 2, 0x345)) for k in range(1, 5)} | {BASE + rng.randrange(5 * C) for _ in range(3)})
            segs, excluded = [], []
            for lo, hi in zip(points, points[1:]):
                if (r := rng.random()) < 0.6:
                    segs.append((lo, _pattern(lo, hi - lo)))
                elif r < 0.8:
                    excluded.append((lo, hi - lo, 'MEM_MAPPED'))
            runs = [(lo, hi - lo) for lo, hi in _merge([(a, a + len(d)) for a, d in segs])]
            p = self.dir / f'layout{seed}.zip'
            ImageSource(segs, excluded=excluded).save(p)
            doc = _manifest(p)
            for a, n, name in doc['chunks']:
                self.assertEqual((a // C, name), ((a + n - 1) // C, _member(a)), msg=(seed, hex(a)))
            with ImageSource.load(p, max_resident_bytes=C * rng.choice((1, 2))) as img:
                self.assertEqual(img.readable_ranges(BASE - 0x10, 6 * C), runs, msg=seed)
                self.assertEqual(img.excluded, tuple(excluded))
                for lo, n in runs:
                    self.assertEqual(img.read(lo, n), _pattern(lo, n), msg=(seed, hex(lo)))
                    for a in (lo - 1, lo + n - 1):
                        self.assertIsNone(img.try_read(a, 2), msg=(seed, hex(a)))
                img.save(p2 := self.dir / f'layout{seed}b.zip')  # a loaded image re-chunks identically
            self.assertEqual(_manifest(p2), doc, msg=seed)

    def test_concurrent_reads(self):
        data = _rand(4 * CHUNK_SIZE, 16)
        p = self.dir / 'mt.zip'
        ImageSource([(BASE, data)]).save(p)
        errors = []
        real_open = zipfile.ZipFile.open

        def slow_open(zf, *args, **kwargs):  # widens the window between a cache miss and the insert
            time.sleep(0.01)
            return real_open(zf, *args, **kwargs)

        with ImageSource.load(p, max_resident_bytes=2 * CHUNK_SIZE) as img, mock.patch.object(zipfile.ZipFile, 'open', slow_open):
            def worker(seed):
                rng = random.Random(seed)
                try:
                    for _ in range(30):
                        off = rng.randrange(0, len(data) - 64)
                        if img.read(BASE + off, 64) != data[off:off + 64]:
                            errors.append(('mismatch', off))
                except Exception as e:  # collected and asserted below
                    errors.append(e)
            threads = [threading.Thread(target=worker, args=(i,)) for i in range(6)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
            self.assertLessEqual(img._resident, 2 * CHUNK_SIZE)
            self.assertEqual(img._resident, sum(len(v) for v in img._lru.values()))
        self.assertEqual(errors, [])


class RecordingTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = pathlib.Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def test_replay(self):
        heap = BASE + 0x10000
        mem = bytearray(_rand(0x1000, 17))
        mem[0x10:0x18] = (heap + 0x80).to_bytes(8, 'little')
        inner = ImageSource([(BASE, bytes(mem)), (heap, _rand(0x200, 18))], [Module('game.exe', BASE, 0x1000, 'C:/game.exe')], meta={'inner': 1})
        rec = RecordingSource(inner)
        self.assertIs(rec.inner, inner)
        self.assertEqual(rec.meta, {})
        rec.meta['game'] = {'name': 'x'}

        def script(src):
            ptr = src.ptr(BASE + 0x10)
            return [
                ptr, src.read(ptr, 16), src.try_read(BASE + 0x100, 4), src.try_read(heap + 0x1FC, 8),
                src.try_read(BASE + 0x2000, 4), src.valid_ptr(heap + 0x40), src.valid_ptr(heap + 0x1FC),
                src.valid_ptr(0x100), src.readable(BASE + 0x800, 32), src.readable(BASE + 0xFF0, 0x20),
                src.readable(heap + 0x300, 1), src.u32(BASE + 0x804), src.i16(heap + 0x100), src.f64(BASE + 0x200),
                src.readable(BASE + 0x900, 0), src.try_read(BASE + 0x100, 0),
            ]

        expected = script(rec)
        self.assertEqual(expected[0], heap + 0x80)
        self.assertEqual([expected[i] for i in (4, 5, 6, 7, 8, 9, 10)], [None, True, False, False, True, False, False])
        img = rec.to_image()
        self.assertEqual(script(img), expected)
        self.assertEqual(img.modules(), inner.modules())
        self.assertEqual(img.meta, {'game': {'name': 'x'}})
        self.assertIs(img.writable, False)
        self.assertEqual(img.excluded, ())
        rec.meta['game']['name'] = 'changed'
        self.assertEqual(img.meta, {'game': {'name': 'x'}})
        p = self.dir / 'rec.zip'
        rec.meta['game']['name'] = 'x'
        self.assertIsNone(rec.save(p))
        with ImageSource.load(p) as loaded:
            self.assertEqual(script(loaded), expected)
            self.assertEqual(loaded.modules(), inner.modules())
            self.assertEqual(loaded.meta, {'game': {'name': 'x'}})
            for addr in (BASE + 0x400, BASE + 0x7FF, BASE + 0x820, heap + 0x1F0, heap + 0x48):
                with self.assertRaises(MemoryReadError, msg=hex(addr)):
                    loaded.read(addr, 1)
            self.assertEqual(loaded.read(BASE + 0x800, 32), inner.read(BASE + 0x800, 32))
            self.assertEqual(loaded.read(heap + 0x40, 8), inner.read(heap + 0x40, 8))
            self.assertEqual(loaded.readable_ranges(BASE, 0x20000), rec.to_image().readable_ranges(BASE, 0x20000))
        self.assertEqual(rec.regions(), inner.regions())
        self.assertEqual(rec.readable_ranges(BASE, 0x2000), [(BASE, 0x1000)])
        before = rec.to_image().readable_ranges(BASE, 0x20000)
        rec.readable_ranges(BASE + 0x400, 0x10)
        self.assertEqual(rec.to_image().readable_ranges(BASE, 0x20000), before)
        rec.refresh()
        self.assertEqual(rec.to_image().readable_ranges(BASE, 0x20000), before)
        with self.assertRaises(MemoryReadError):
            rec.read(BASE + 0x2000, 4)
        self.assertEqual(rec.to_image().readable_ranges(BASE, 0x20000), before)

    def test_interval_store(self):
        base = BASE + 0x40000
        rec = RecordingSource(ImageSource([(base, _rand(0x10000, 19))]))
        offsets = [i * 6 for i in range(10000)]
        random.Random(20).shuffle(offsets)
        for off in offsets:
            rec.read(base + off, 8)
        union = 9999 * 6 + 8
        img = rec.to_image()
        self.assertEqual(img.regions(), [Region(base, union, PAGE_READONLY, MEM_COMMIT, MEM_PRIVATE)])
        self.assertEqual(img.read(base, union), rec.inner.read(base, union))
        self.assertEqual([(s, len(b)) for s, b in rec._store.intervals()], [(base, union)])

        rec = RecordingSource(ImageSource([(base, _rand(0x100, 21))]))
        rec.read(base + 8, 8)
        rec.read(base, 8)      # touches on the left
        rec.read(base + 16, 8)  # touches on the right
        rec.read(base + 25, 4)  # one-byte gap
        stored = lambda: [(s, len(b)) for s, b in rec._store.intervals()]
        self.assertEqual(stored(), [(base, 24), (base + 25, 4)])  # to_image() would re-merge touching pieces
        self.assertEqual([(r.base, r.size) for r in rec.to_image().regions()], [(base, 24), (base + 25, 4)])
        rec.read(base + 23, 3)  # bridges the gap
        self.assertEqual([(r.base, r.size) for r in rec.to_image().regions()], [(base, 29)])
        self.assertEqual(rec.to_image().read(base, 29), rec.inner.read(base, 29))
        rec.read(base + 0x40, 4)
        rec.read(base + 0x50, 4)
        rec.read(base + 0x60, 4)
        rec.read(base + 0x3C, 0x30)  # swallows three intervals
        rec.read(base + 0x80, 0x10)
        rec.read(base + 0x6C, 0x34)  # touches the left one and covers another entirely
        self.assertEqual([(r.base, r.size) for r in rec.to_image().regions()], [(base, 29), (base + 0x3C, 0x64)])
        self.assertEqual(stored(), [(base, 29), (base + 0x3C, 0x64)])
        rec.read(base + 0xA0, 4)   # touches the right end only
        rec.read(base + 0x38, 4)   # touches the left start only
        self.assertEqual(stored(), [(base, 29), (base + 0x38, 0x6C)])
        self.assertEqual(rec.to_image().read(base + 0x3C, 0x64), rec.inner.read(base + 0x3C, 0x64))

        rec = RecordingSource(ImageSource([(BASE, _rand(0x30000, 24))]))
        rec.read(BASE + 0xFFF0, 0x20)  # crosses a 64 KiB boundary
        rec.read(BASE + 0x1FFF8, 0x10000)
        self.assertEqual([(r.base, r.size) for r in rec.to_image().regions()], [(BASE + 0xFFF0, 0x20), (BASE + 0x1FFF8, 0x10000)])
        rec.read(BASE + 0x10008, 0xFFF0)  # bridges them
        img = rec.to_image()
        self.assertEqual([(r.base, r.size) for r in img.regions()], [(BASE + 0xFFF0, 0x20008)])
        self.assertEqual(img.read(BASE + 0xFFF0, 0x20008), rec.inner.read(BASE + 0xFFF0, 0x20008))

    def test_overlap_later_wins(self):
        a = BASE + 0x100
        inner = ImageSource([(BASE, bytes(0x400))], writable=True)
        rec = RecordingSource(inner)
        rec.read(a, 16)
        inner.write(a + 8, b'\x11' * 16)
        self.assertEqual(rec.read(a + 4, 16), bytes(4) + b'\x11' * 12)
        inner.write(a - 8, b'\x22' * 12)
        rec.read(a - 8, 12)
        inner.write(a + 2, b'\x33' * 2)
        rec.read(a + 2, 2)
        inner.write(a + 16, b'\x44' * 8)
        rec.read(a + 16, 8)
        expect = b'\x22' * 8 + b'\x22' * 4 + bytes(4) + b'\x11' * 16
        expect = expect[:10] + b'\x33\x33' + expect[12:]
        expect = expect[:24] + b'\x44' * 8
        img = rec.to_image()
        self.assertEqual([(r.base, r.size) for r in img.regions()], [(a - 8, 32)])
        self.assertEqual(img.read(a - 8, 32), expect)
        inner.write(a - 16, b'\x55' * 48)
        self.assertIs(rec.readable(a - 12, 20), True)
        self.assertEqual(rec.to_image().read(a - 12, 36), b'\x55' * 20 + expect[16:])
        with self.assertRaises(MemoryReadError):
            rec.to_image().read(a - 13, 1)

    def test_readable_validates_first(self):
        a = BASE + 0x10
        spy = _Spy(ImageSource([(BASE, b'z' * 0x40)]))
        rec = RecordingSource(spy)
        with self.assertRaises(TypeError):
            rec.readable(1.0)
        with self.assertRaises(TypeError):
            rec.readable(a, 1.0)
        with self.assertRaises(TypeError):
            rec.readable('a', 1)
        with self.assertRaises(ValueError):
            rec.readable(a, -1)
        self.assertIs(rec.readable(-1, 4), False)
        self.assertIs(rec.readable(ADDRESS_LIMIT - 2, 4), False)
        self.assertIs(rec.readable(a, 0), True)
        self.assertIs(rec.readable(-5, 0), True)
        self.assertIs(rec.valid_ptr(0x1000), False)
        self.assertEqual(spy.calls, [])
        self.assertIs(rec.readable(a), True)
        self.assertIs(rec.readable(BASE + 0x3C, 8), False)
        self.assertEqual(spy.calls, [('try_read', a, 1), ('try_read', BASE + 0x3C, 8)])
        self.assertEqual([(r.base, r.size) for r in rec.to_image().regions()], [(a, 1)])

    def test_fresh_and_write(self):
        base = BASE + 0x2000
        inner = _FreshPair(bytearray(_rand(0x100, 22)), base)
        rec = RecordingSource(inner)
        f = rec.fresh
        self.assertIsNot(f, rec)
        self.assertIsInstance(f, RecordingSource)
        self.assertIs(rec.fresh, f)
        self.assertIs(f.fresh, f)
        self.assertIs(f.inner, inner.fresh)
        rec.meta['k'] = 1
        self.assertIs(f.meta, rec.meta)
        rec.meta = {'swapped': True}
        self.assertEqual(f.meta, {'swapped': True})
        f.read(base + 0x10, 4)
        rec.read(base + 0x40, 4)
        f.readable(base + 0x80, 2)
        self.assertEqual([(r.base, r.size) for r in rec.to_image().regions()], [(base + 0x10, 4), (base + 0x40, 4), (base + 0x80, 2)])
        self.assertEqual(f.to_image().read(base + 0x10, 4), inner.read(base + 0x10, 4))
        self.assertEqual(rec.to_image().meta, {'swapped': True})
        self.assertEqual(rec.to_image().modules(), inner.modules())

        img_inner = ImageSource([(base, bytes(0x40))], writable=True)
        rec2 = RecordingSource(img_inner)
        self.assertIs(rec2.fresh, rec2)
        rec2.write(base + 8, b'xyz')
        self.assertEqual(img_inner.read(base + 8, 3), b'xyz')
        self.assertEqual(rec2.to_image().read(base + 8, 3), b'xyz')
        self.assertEqual([(r.base, r.size) for r in rec2.to_image().regions()], [(base + 8, 3)])
        with self.assertRaises(MemoryWriteError):
            rec2.write(base + 0x3E, b'abcd')
        self.assertEqual([(r.base, r.size) for r in rec2.to_image().regions()], [(base + 8, 3)])
        rec2.write(base + 0x20, b'')
        self.assertEqual(len(rec2.to_image().regions()), 1)

        f.write(base + 0x90, b'FW')
        self.assertEqual(inner.data[0x90:0x92], b'FW')
        self.assertEqual(rec.to_image().read(base + 0x90, 2), b'FW')
        with self.assertRaises(MemoryWriteError):
            RecordingSource(ImageSource([(base, bytes(4))])).write(base, b'x')

    def test_concurrent_recording(self):
        base = BASE + 0x80000
        data = _rand(0x8000, 23)
        rec = RecordingSource(ImageSource([(base, data)]))

        def worker(seed):
            rng = random.Random(seed)
            for _ in range(2000):
                off = rng.randrange(0, 0x8000 - 16)
                rec.read(base + off, 16)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        img = rec.to_image()
        for lo, n in img.readable_ranges(base, 0x8000):
            self.assertEqual(img.read(lo, n), data[lo - base:lo - base + n])


if __name__ == '__main__':
    unittest.main()
