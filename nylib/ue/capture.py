import bisect
import collections
import contextlib
import copy
import json
import os
import tempfile
import threading
import time
import typing
import zipfile
import zlib

from .errors import CaptureError, MemoryReadError, MemoryWriteError
from .memory import (
    ADDRESS_LIMIT, MEM_COMMIT, MEM_IMAGE, MEM_MAPPED, MEM_PRIVATE,
    PAGE_NOCACHE, PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOMBINE,
    MemorySource, Module, Region,
)

CAPTURE_FORMAT, CAPTURE_VERSION = 'nylib.ue.capture', 1
CHUNK_SIZE = 0x100000  # no chunk crosses a CHUNK_SIZE-aligned boundary
_READABLE_VERSIONS = {1}  # every version this loader ever wrote
_MANIFEST = 'capture.json'
_STORE_BLOCK = 0x10000  # recorded intervals never cross a _STORE_BLOCK-aligned boundary
_CORRUPT = (zipfile.BadZipFile, zlib.error, EOFError, RuntimeError, ValueError)  # decompression failures of one member


def _in_range(address: int, size: int) -> bool:
    return address >= 0 and address + size <= ADDRESS_LIMIT


def _is_int(x) -> bool:
    return isinstance(x, int) and not isinstance(x, bool)


def _member_name(address: int) -> str:
    return f'chunks/{address:016X}.bin'


def _merge_spans(spans) -> list[tuple[int, int]]:
    """Sort (start, end) spans and merge the ones that overlap or touch."""
    out = []
    for lo, hi in sorted(spans):
        if out and lo <= out[-1][1]:
            if hi > out[-1][1]:
                out[-1] = (out[-1][0], hi)
        else:
            out.append((lo, hi))
    return out


def _first_overlap(a: list[tuple[int, int]], b: list[tuple[int, int]]) -> int | None:
    """First address shared by two sorted lists of disjoint (start, end) spans."""
    i = j = 0
    while i < len(a) and j < len(b):
        if (lo := max(a[i][0], b[j][0])) < min(a[i][1], b[j][1]):
            return lo
        if a[i][1] <= b[j][1]:
            i += 1
        else:
            j += 1
    return None


def _check_meta(meta) -> dict:
    if meta is None:
        return {}
    if not isinstance(meta, dict):
        raise TypeError(f'meta must be a dict or None, got {type(meta).__name__}')
    try:
        json.dumps(meta)
    except (TypeError, ValueError, RecursionError) as e:
        raise ValueError(f'meta is not JSON-serialisable: {e}') from e
    return meta


def _check_excluded(excluded, data: list[tuple[int, int]]) -> tuple[tuple[int, int, str], ...]:
    """Validate excluded (address, size, reason) triples against the merged (start, end) data spans."""
    out = []
    for item in excluded:
        try:
            address, size, reason = item
        except (TypeError, ValueError):
            raise TypeError(f'excluded range must be an (int, int, str) triple, got {item!r}') from None
        if not isinstance(address, int) or not isinstance(size, int) or not isinstance(reason, str):
            raise TypeError(f'excluded range must be an (int, int, str) triple, got {item!r}')
        if size < 1 or not _in_range(address, size) or not reason:
            raise ValueError(f'invalid excluded range {item!r}')
        out.append((address, size, reason))
    out.sort()
    for (a, n, _), (b, _, _) in zip(out, out[1:]):
        if a + n > b:
            raise ValueError(f'excluded ranges overlap at {b:#x}')
    if (hit := _first_overlap([(a, a + n) for a, n, _ in out], data)) is not None:
        raise ValueError(f'excluded range overlaps captured data at {hit:#x}')
    return tuple(out)


def _decompress(zf: zipfile.ZipFile, path: str, name: str, size: int) -> bytes:
    try:
        with zf.open(name) as f:
            data = f.read()
    except _CORRUPT as e:
        raise CaptureError(path, f'corrupt member {name}') from e
    if len(data) != size:
        raise CaptureError(path, f'corrupt member {name}')
    return data


def _read_manifest(zf: zipfile.ZipFile, path: str, file_size: int):
    """Parse and validate capture.json; returns (modules, chunks, excluded, meta)."""
    def bad(reason):
        return CaptureError(path, reason)

    def member(name):
        info = zf.getinfo(name)
        if not 0 <= info.header_offset < file_size:  # a corrupt directory entry would seek outside the file
            raise bad(f'member {name} has an invalid offset')
        if info.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
            raise bad(f'member {name} uses compression method {info.compress_type}')
        return info

    try:
        member(_MANIFEST)
        raw = zf.read(_MANIFEST)
    except KeyError:
        raise bad(f'{_MANIFEST} missing') from None
    except _CORRUPT as e:
        raise bad(f'corrupt member {_MANIFEST}') from e
    try:
        doc = json.loads(raw)
    except (ValueError, RecursionError) as e:
        raise bad(f'{_MANIFEST} is not JSON: {e}') from e
    if not isinstance(doc, dict):
        raise bad(f'{_MANIFEST} is not an object')
    if (fmt := doc.get('format')) != CAPTURE_FORMAT:
        raise bad(f'format {fmt!r} is not {CAPTURE_FORMAT!r}')
    if not _is_int(version := doc.get('version')) or version not in _READABLE_VERSIONS:
        raise bad(f'unsupported version {version!r}')
    if not _is_int(pointer_size := doc.get('pointer_size')) or pointer_size != 8:
        raise bad(f'unsupported pointer_size {pointer_size!r}')

    if not isinstance(raw_modules := doc.get('modules'), list):
        raise bad('modules is not a list')
    modules = []
    for i, m in enumerate(raw_modules):
        if not (isinstance(m, list) and len(m) == 4 and isinstance(m[0], str) and _is_int(m[1]) and _is_int(m[2])
                and isinstance(m[3], str) and m[2] >= 0 and _in_range(m[1], m[2])):
            raise bad(f'modules[{i}] is malformed')
        modules.append(Module(m[0], m[1], m[2], m[3]))

    if not isinstance(raw_chunks := doc.get('chunks'), list):
        raise bad('chunks is not a list')
    chunks, prev_end = [], 0
    for i, c in enumerate(raw_chunks):
        if not (isinstance(c, list) and len(c) == 3 and _is_int(c[0]) and _is_int(c[1]) and isinstance(c[2], str)):
            raise bad(f'chunks[{i}] is malformed')
        address, size, name = c
        if not 1 <= size <= CHUNK_SIZE or not _in_range(address, size):
            raise bad(f'chunks[{i}] has an invalid address or size')
        if address // CHUNK_SIZE != (address + size - 1) // CHUNK_SIZE:
            raise bad(f'chunks[{i}] crosses a chunk boundary')
        if chunks and address < prev_end:
            raise bad(f'chunks[{i}] overlaps or is out of order')
        if name != _member_name(address):
            raise bad(f'chunks[{i}] names member {name!r}')
        try:
            info = member(name)
        except KeyError:
            raise bad(f'member {name} missing') from None
        if info.file_size != size:
            raise bad(f'member {name} holds {info.file_size} bytes, chunk says {size}')
        chunks.append((address, size, name))
        prev_end = address + size

    if not isinstance(raw_excluded := doc.get('excluded', []), list):
        raise bad('excluded is not a list')
    excluded, prev_end = [], 0
    for i, e in enumerate(raw_excluded):
        if not (isinstance(e, list) and len(e) == 3 and _is_int(e[0]) and _is_int(e[1]) and isinstance(e[2], str)):
            raise bad(f'excluded[{i}] is malformed')
        address, size, reason = e
        if size < 1 or not _in_range(address, size) or not reason:
            raise bad(f'excluded[{i}] has an invalid address, size or reason')
        if excluded and address < prev_end:
            raise bad(f'excluded[{i}] overlaps or is out of order')
        excluded.append((address, size, reason))
        prev_end = address + size
    runs = _merge_spans((a, a + n) for a, n, _ in chunks)
    if (hit := _first_overlap([(a, a + n) for a, n, _ in excluded], runs)) is not None:
        raise bad(f'excluded range overlaps a chunk at {hit:#x}')

    if not isinstance(meta := doc.get('meta'), dict):
        raise bad('meta is not an object')
    return modules, chunks, tuple(excluded), meta


class ImageSource(MemorySource):
    """Static memory image: in-memory segments, or a capture file loaded lazily."""

    def __init__(self, segments: typing.Iterable[tuple[int, bytes | bytearray]], modules: typing.Iterable[Module] = (), *,
                 meta: dict | None = None, writable: bool = False, excluded: typing.Iterable[tuple[int, int, str]] = ()):
        segs = []
        for item in segments:
            try:
                base, data = item
            except (TypeError, ValueError):
                raise TypeError(f'segment must be an (int, bytes | bytearray) pair, got {type(item).__name__}') from None
            if not isinstance(base, int) or not isinstance(data, (bytes, bytearray)):
                raise TypeError(f'segment must be an (int, bytes | bytearray) pair, got ({type(base).__name__}, {type(data).__name__})')
            if not _in_range(base, len(data)):
                raise ValueError(f'segment at {base:#x} of {len(data):#x} bytes is out of range')
            if data:
                segs.append((base, data))
        segs.sort(key=lambda s: s[0])
        runs = []
        for base, data in segs:
            if runs and base < (end := runs[-1][0] + len(runs[-1][1])):
                raise ValueError(f'segments overlap at {base:#x}')
            if runs and base == end:
                runs[-1][1].extend(data)
            else:
                runs.append((base, bytearray(data)))
        modules = list(modules)
        for m in modules:
            if not isinstance(m, Module):
                raise TypeError(f'modules must hold Module, got {type(m).__name__}')
        meta = _check_meta(meta)
        excluded = _check_excluded(excluded, [(s, s + len(b)) for s, b in runs])
        self._setup([(s, len(b), b) for s, b in runs], modules, meta, bool(writable), excluded, None, None, 0)

    def _setup(self, blocks, modules, meta, writable, excluded, path, archive, max_resident):
        self._lock = threading.RLock()
        self._blocks = blocks  # (start, size, bytearray | member name), sorted and disjoint
        self._block_starts = [b[0] for b in blocks]
        self._runs = _merge_spans((s, s + n) for s, n, _ in blocks)
        self._run_starts = [r[0] for r in self._runs]
        self._modules = tuple(modules)
        self.meta = meta
        self.writable = writable
        self.excluded = excluded
        self._excluded_starts = [e[0] for e in excluded]
        self.path = path
        self._archive = archive  # (file, ZipFile) of a loaded image, else None
        self._closed = False
        self._lru = collections.OrderedDict()
        self._resident = 0
        self._max_resident = max_resident
        protect = PAGE_READWRITE if self.writable else PAGE_READONLY
        self._regions = tuple(Region(s, e - s, protect, MEM_COMMIT, MEM_IMAGE if any(m.contains(s) for m in self._modules) else MEM_PRIVATE)
                              for s, e in self._runs)

    def _first_missing(self, lo: int, hi: int) -> int | None:
        i = bisect.bisect_right(self._run_starts, lo) - 1
        if i < 0 or self._runs[i][1] <= lo:
            return lo
        return self._runs[i][1] if self._runs[i][1] < hi else None

    def _missing_reason(self, first: int) -> str:
        i = bisect.bisect_right(self._excluded_starts, first) - 1
        if i >= 0 and first < (e := self.excluded[i])[0] + e[1]:
            return f'not captured at {first:#x} ({e[2]})'
        return f'not in image at {first:#x}'

    def _chunk(self, name: str, size: int) -> bytes:
        if (data := self._lru.get(name)) is not None:
            self._lru.move_to_end(name)
            return data
        data = _decompress(self._archive[1], self.path, name, size)
        while self._lru and self._resident + size > self._max_resident:
            self._resident -= len(self._lru.popitem(last=False)[1])
        self._lru[name] = data
        self._resident += size
        return data

    def _read(self, address: int, size: int) -> bytes:
        end = address + size
        with self._lock:
            if self._closed:
                raise ValueError('capture is closed')
            if (first := self._first_missing(address, end)) is not None:
                raise MemoryReadError(address, size, self._missing_reason(first))
            k, pos, out = bisect.bisect_right(self._block_starts, address) - 1, address, []
            while pos < end:
                start, n, payload = self._blocks[k]
                data = payload if isinstance(payload, bytearray) else self._chunk(payload, n)
                take = min(end, start + n)
                out.append(data[pos - start:take - start])
                pos, k = take, k + 1
            return b''.join(out)

    def _readable_ranges(self, address: int, size: int) -> list[tuple[int, int]]:
        end, out = address + size, []
        i = max(bisect.bisect_right(self._run_starts, address) - 1, 0)
        while i < len(self._runs) and self._runs[i][0] < end:
            if (lo := max(self._runs[i][0], address)) < (hi := min(self._runs[i][1], end)):
                out.append((lo, hi - lo))
            i += 1
        return out

    def _write(self, address: int, data: bytes) -> None:
        if not self.writable:
            raise MemoryWriteError(address, len(data), 'image is read-only')
        with self._lock:
            if (first := self._first_missing(address, address + len(data))) is not None:
                raise MemoryWriteError(address, len(data), f'not in image at {first:#x}')
            start, _, buf = self._blocks[bisect.bisect_right(self._block_starts, address) - 1]
            buf[address - start:address - start + len(data)] = data

    def regions(self) -> list[Region]:
        return list(self._regions)

    def modules(self) -> list[Module]:
        return list(self._modules)

    def save(self, path: str | os.PathLike) -> None:
        write_capture(path, self, [(s, e - s) for s, e in self._runs], modules=self.modules(), meta=self.meta, excluded=self.excluded)

    @classmethod
    def load(cls, path: str | os.PathLike, *, max_resident_bytes: int = 0x10000000, verify: bool = False) -> 'ImageSource':
        """Open a capture file; chunks are decompressed on first access into an LRU of max_resident_bytes."""
        if not isinstance(path, (str, os.PathLike)):
            raise TypeError(f'path must be str or PathLike, got {type(path).__name__}')
        if not isinstance(max_resident_bytes, int):
            raise TypeError(f'max_resident_bytes must be int, got {type(max_resident_bytes).__name__}')
        if max_resident_bytes < CHUNK_SIZE:
            raise ValueError(f'max_resident_bytes {max_resident_bytes:#x} is below CHUNK_SIZE')
        p = str(path)
        fp = open(path, 'rb')
        try:
            try:
                zf = zipfile.ZipFile(fp)
            except (zipfile.BadZipFile, EOFError, ValueError, OverflowError, RuntimeError) as e:
                raise CaptureError(p, 'not a zip archive') from e
            try:
                modules, chunks, excluded, meta = _read_manifest(zf, p, os.fstat(fp.fileno()).st_size)
                if verify:
                    for _, size, name in chunks:
                        _decompress(zf, p, name, size)
            except BaseException:
                zf.close()
                raise
        except BaseException:
            fp.close()
            raise
        image = cls.__new__(cls)
        image._setup(chunks, modules, meta, False, excluded, p, (fp, zf), max_resident_bytes)
        return image

    def close(self) -> None:
        with self._lock:
            if self._archive is None or self._closed:
                return
            self._closed = True
            self._lru.clear()
            self._resident = 0
            fp, zf = self._archive
            try:
                zf.close()
            finally:
                fp.close()

    def __enter__(self) -> 'ImageSource':
        return self

    def __exit__(self, *exc) -> None:
        self.close()


class _Store:
    """Interval store shared by a RecordingSource and its fresh sibling."""
    __slots__ = ('lock', 'blocks', 'meta')

    def __init__(self):
        self.lock = threading.RLock()
        self.blocks = {}  # block index -> (sorted starts, bufs) of disjoint, non-touching intervals inside that block
        self.meta = {}

    def record(self, address: int, data: bytes):
        view, end = memoryview(data), address + len(data)
        with self.lock:
            pos = address
            while pos < end:
                nxt = min((pos // _STORE_BLOCK + 1) * _STORE_BLOCK, end)
                self._record(*self.blocks.setdefault(pos // _STORE_BLOCK, ([], [])), pos, view[pos - address:nxt - address])
                pos = nxt

    def intervals(self) -> list[tuple[int, bytearray]]:
        """(start, bytes) of every interval, sorted; intervals of adjacent blocks may touch."""
        with self.lock:
            return [iv for k in sorted(self.blocks) for iv in zip(*self.blocks[k])]

    @staticmethod
    def _record(starts: list[int], bufs: list[bytearray], address: int, data: memoryview):
        end = address + len(data)
        i = bisect.bisect_left(starts, address)
        if i > 0 and starts[i - 1] + len(bufs[i - 1]) >= address:
            i -= 1
        j = bisect.bisect_right(starts, end)
        if i == j:
            starts.insert(i, address)
            bufs.insert(i, bytearray(data))
            return
        s0 = starts[i]
        if j - i == 1 and s0 <= address:  # inside or extending one interval to the right
            bufs[i][address - s0:end - s0] = data
            return
        new = bytearray(bufs[i][:address - s0]) if s0 < address else bytearray()
        new += data
        if (last_end := starts[j - 1] + len(bufs[j - 1])) > end:
            new += bufs[j - 1][end - starts[j - 1]:]
        starts[i:j] = [min(s0, address)]
        bufs[i:j] = [new]


class RecordingSource(MemorySource):
    """Forwards to inner and records every byte read or written, for offline replay."""

    def __init__(self, inner: MemorySource):
        self.inner = inner
        self._store = _Store()
        self._fresh = None

    @property
    def meta(self) -> dict:
        return self._store.meta

    @meta.setter
    def meta(self, value: dict):
        self._store.meta = value

    @property
    def fresh(self) -> 'RecordingSource':
        if (inner_fresh := self.inner.fresh) is self.inner:
            return self
        with self._store.lock:
            if self._fresh is None:
                sibling = RecordingSource.__new__(RecordingSource)
                sibling.inner, sibling._store, sibling._fresh = inner_fresh, self._store, None
                self._fresh = sibling
            return self._fresh

    def readable(self, address: int, size: int = 1) -> bool:
        if not isinstance(address, int) or not isinstance(size, int):
            raise TypeError('address and size must be int')
        if size < 0:
            raise ValueError('size must be >= 0')
        if size == 0:
            return True
        if not _in_range(address, size):
            return False
        if (data := self.inner.try_read(address, size)) is None:
            return False
        self._store.record(address, data)
        return True

    def _read(self, address: int, size: int) -> bytes:
        data = self.inner.read(address, size)
        self._store.record(address, data)
        return data

    def _readable_ranges(self, address: int, size: int) -> list[tuple[int, int]]:
        return self.inner.readable_ranges(address, size)

    def _write(self, address: int, data: bytes) -> None:
        self.inner.write(address, data)
        self._store.record(address, data)

    def regions(self) -> list[Region]:
        return self.inner.regions()

    def modules(self) -> list[Module]:
        return self.inner.modules()

    def refresh(self) -> None:
        self.inner.refresh()

    def to_image(self) -> ImageSource:
        modules = self.inner.modules()
        with self._store.lock:
            return ImageSource(self._store.intervals(), modules, meta=copy.deepcopy(self.meta))

    def save(self, path: str | os.PathLike) -> None:
        self.to_image().save(path)


def _split_chunks(address: int, size: int):
    end = address + size
    while address < end:
        nxt = min((address // CHUNK_SIZE + 1) * CHUNK_SIZE, end)
        yield address, nxt - address
        address = nxt


_REPLACE_RETRIES = 10  # retries of os.replace after the first attempt, before giving up and keeping tmp
_REPLACE_BACKOFF_CAP = 1.6  # seconds; backoff doubles from 0.1s up to this cap


def _replace_or_keep(tmp: str, target: str) -> None:
    """os.replace(tmp, target), retrying a PermissionError (a scanner briefly holding the fresh file).
    On final failure tmp is left in place, complete, rather than deleting a finished capture."""
    delay = 0.1
    for attempt in range(_REPLACE_RETRIES + 1):
        try:
            os.replace(tmp, target)
            return
        except PermissionError as e:
            if attempt == _REPLACE_RETRIES:
                raise PermissionError(f'{target} is still locked after {attempt} retries; kept the complete capture at {tmp}') from e
            time.sleep(delay)
            delay = min(delay * 2, _REPLACE_BACKOFF_CAP)


def write_capture(path: str | os.PathLike, source: MemorySource, ranges: typing.Iterable[tuple[int, int]], *,
                  modules: typing.Iterable[Module] | None = None, meta: dict | None = None,
                  excluded: typing.Iterable[tuple[int, int, str]] = (),
                  progress: typing.Callable[[int, int], None] | None = None) -> dict:
    """Stream the readable bytes of ranges into a capture file, replacing path only on success."""
    started = time.perf_counter()
    if not isinstance(path, (str, os.PathLike)):
        raise TypeError(f'path must be str or PathLike, got {type(path).__name__}')
    if progress is not None and not callable(progress):
        raise TypeError(f'progress must be callable or None, got {type(progress).__name__}')
    spans = []
    for item in ranges:
        try:
            address, size = item
        except (TypeError, ValueError):
            raise TypeError(f'range must be an (int, int) pair, got {item!r}') from None
        if not isinstance(address, int) or not isinstance(size, int):
            raise TypeError(f'range must be an (int, int) pair, got {item!r}')
        if size < 0:
            raise ValueError(f'range at {address:#x} has negative size {size}')
        if size:
            spans.append((address, address + size))
    merged = _merge_spans(spans)
    excluded = _check_excluded(excluded, merged)
    meta = _check_meta(meta)
    modules = list(source.modules() if modules is None else modules)
    for m in modules:
        if not isinstance(m, Module):
            raise TypeError(f'modules must hold Module, got {type(m).__name__}')
    pieces = [p for lo, hi in merged for p in source.readable_ranges(lo, hi - lo)]
    total = sum(n for _, n in pieces)

    target = os.path.abspath(os.fspath(path))
    fd, tmp = tempfile.mkstemp(prefix=os.path.basename(target) + '.', suffix='.tmp', dir=os.path.dirname(target))
    chunks, failed, written, done = [], [], 0, 0

    def put(address, data):
        zf.writestr(_member_name(address), data)
        chunks.append([address, len(data), _member_name(address)])
        return len(data)

    def fail(address, size):
        if failed and failed[-1][0] + failed[-1][1] == address:
            failed[-1] = (failed[-1][0], failed[-1][1] + size, 'read failed')
        else:
            failed.append((address, size, 'read failed'))

    try:
        with os.fdopen(fd, 'w+b') as f:
            with zipfile.ZipFile(f, 'w', zipfile.ZIP_DEFLATED, allowZip64=True, compresslevel=1) as zf:
                for piece in pieces:
                    for address, size in _split_chunks(*piece):
                        if (data := source.try_read(address, size)) is not None:
                            written += put(address, data)
                        else:  # retry once over the re-queried ranges; what still fails is excluded as 'read failed'
                            pos = address
                            for lo, n in source.readable_ranges(address, size):
                                if lo > pos:
                                    fail(pos, lo - pos)
                                if (data := source.try_read(lo, n)) is None:
                                    fail(lo, n)
                                else:
                                    written += put(lo, data)
                                pos = lo + n
                            if pos < address + size:
                                fail(pos, address + size - pos)
                        data = None
                        done += size
                        if progress is not None:
                            progress(done, total)
                skipped = sum(n for _, n, _ in failed)
                excluded = sorted((*excluded, *failed))
                zf.writestr(_MANIFEST, json.dumps({
                    'format': CAPTURE_FORMAT, 'version': CAPTURE_VERSION, 'pointer_size': 8,
                    'modules': [[m.name, m.base, m.size, m.path] for m in modules],
                    'chunks': chunks,
                    'excluded': [list(e) for e in excluded],
                    'meta': meta,
                }))
            f.flush()
            os.fsync(f.fileno())
    except BaseException:
        with contextlib.suppress(OSError):
            os.remove(tmp)
        raise
    try:
        _replace_or_keep(tmp, target)
    except PermissionError:
        raise  # tmp is kept as the finished capture, see _replace_or_keep
    except BaseException:
        with contextlib.suppress(OSError):
            os.remove(tmp)
        raise
    return {'bytes': written, 'chunks': len(chunks), 'skipped_bytes': skipped, 'seconds': time.perf_counter() - started}


def wide_capture_ranges(regions: typing.Iterable[Region]) -> tuple[list[tuple[int, int]], list[tuple[int, int, str]]]:
    """Stage-20 wide-capture recipe: (ranges to capture, readable ranges excluded with a reason)."""
    ranges, excluded = [], []
    for r in regions:
        if not isinstance(r, Region):
            raise TypeError(f'regions must hold Region, got {type(r).__name__}')
        if not r.readable:
            continue
        if r.type in (MEM_PRIVATE, MEM_IMAGE) and not r.protect & (PAGE_NOCACHE | PAGE_WRITECOMBINE):
            ranges.append((r.base, r.size))
        elif r.type == MEM_MAPPED:
            excluded.append((r.base, r.size, 'MEM_MAPPED'))
        elif r.protect & PAGE_NOCACHE:
            excluded.append((r.base, r.size, 'PAGE_NOCACHE'))
        elif r.protect & PAGE_WRITECOMBINE:
            excluded.append((r.base, r.size, 'PAGE_WRITECOMBINE'))
        else:
            excluded.append((r.base, r.size, f'type {r.type:#x}'))
    ranges.sort()
    excluded.sort()
    return ranges, excluded
