import bisect
import collections
import contextlib
import dataclasses
import struct
import threading
import time

from ..process import Process
from .errors import MemoryReadError, MemoryWriteError, TargetError, UeError

MEM_COMMIT, MEM_RESERVE, MEM_FREE = 0x1000, 0x2000, 0x10000
MEM_PRIVATE, MEM_MAPPED, MEM_IMAGE = 0x20000, 0x40000, 0x1000000
PAGE_NOACCESS, PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOPY = 0x01, 0x02, 0x04, 0x08
PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY = 0x10, 0x20, 0x40, 0x80
PAGE_GUARD, PAGE_NOCACHE, PAGE_WRITECOMBINE = 0x100, 0x200, 0x400
READABLE_PROTECT = frozenset((0x02, 0x04, 0x08, 0x20, 0x40, 0x80))
WRITABLE_PROTECT = frozenset((0x04, 0x08, 0x40, 0x80))
USER_MIN = 0x10000
USER_MAX = 0x7FFF_FFFF_0000  # exclusive upper bound of user space and of valid_ptr targets
ADDRESS_LIMIT = 1 << 64


def _in_range(address: int, size: int) -> bool:
    return address >= 0 and address + size <= ADDRESS_LIMIT


def _check_address_size(address, size):
    if not isinstance(address, int) or not isinstance(size, int):
        raise TypeError('address and size must be int')
    if size < 0:
        raise ValueError('size must be >= 0')


def _normalize_ranges(raw, address: int, size: int) -> list[tuple[int, int]]:
    end = address + size
    pieces = []
    for item in raw:
        try:
            a, n = item
        except (TypeError, ValueError):
            raise TypeError(f'invalid readable range {item!r}')
        if not isinstance(a, int) or not isinstance(n, int):
            raise TypeError(f'invalid readable range {item!r}')
        lo, hi = max(a, address), min(a + n, end)
        if hi > lo:
            pieces.append((lo, hi))
    pieces.sort()
    merged = []
    for lo, hi in pieces:
        if merged and lo <= merged[-1][1]:
            if hi > merged[-1][1]:
                merged[-1] = (merged[-1][0], hi)
        else:
            merged.append((lo, hi))
    return [(lo, hi - lo) for lo, hi in merged]


@dataclasses.dataclass(frozen=True, slots=True)
class Region:
    base: int
    size: int
    protect: int
    state: int
    type: int

    @property
    def end(self) -> int:
        return self.base + self.size

    @property
    def readable(self) -> bool:
        return self.state == MEM_COMMIT and (self.protect & 0xFF) in READABLE_PROTECT and not self.protect & PAGE_GUARD

    @property
    def writable(self) -> bool:
        return self.state == MEM_COMMIT and (self.protect & 0xFF) in WRITABLE_PROTECT and not self.protect & PAGE_GUARD


@dataclasses.dataclass(frozen=True, slots=True)
class Module:
    name: str
    base: int
    size: int
    path: str = ''

    @property
    def end(self) -> int:
        return self.base + self.size

    def contains(self, address: int) -> bool:
        if not isinstance(address, int):
            raise TypeError(f'address must be int, got {type(address).__name__}')
        return self.base <= address < self.end


class MemorySource:
    """Uniform read/write surface over a memory-like backend."""

    pointer_size = 8

    def read(self, address: int, size: int) -> bytes:
        _check_address_size(address, size)
        if size == 0:
            return b''
        if not _in_range(address, size):
            raise MemoryReadError(address, size, 'address out of range')
        data = self._read(address, size)
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise TypeError(f'_read must return bytes-like, got {type(data).__name__}')
        data = bytes(data)
        if len(data) != size:
            raise MemoryReadError(address, size, f'source returned {len(data)} of {size} bytes')
        return data

    def try_read(self, address: int, size: int) -> bytes | None:
        try:
            return self.read(address, size)
        except MemoryReadError:
            return None

    def readable(self, address: int, size: int = 1) -> bool:
        _check_address_size(address, size)
        if size == 0:
            return True
        return self.readable_ranges(address, size) == [(address, size)]

    def readable_ranges(self, address: int, size: int) -> list[tuple[int, int]]:
        _check_address_size(address, size)
        if size == 0 or not _in_range(address, size):
            return []
        return _normalize_ranges(self._readable_ranges(address, size), address, size)

    def write(self, address: int, data: bytes | bytearray | memoryview) -> None:
        if not isinstance(address, int):
            raise TypeError(f'address must be int, got {type(address).__name__}')
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise TypeError(f'data must be bytes-like, got {type(data).__name__}')
        size = data.nbytes if isinstance(data, memoryview) else len(data)
        if size == 0:
            return None
        if not _in_range(address, size):
            raise MemoryWriteError(address, size, 'address out of range')
        self._write(address, bytes(data))
        return None

    def u8(self, address: int) -> int: return int.from_bytes(self.read(address, 1), 'little', signed=False)
    def u16(self, address: int) -> int: return int.from_bytes(self.read(address, 2), 'little', signed=False)
    def u32(self, address: int) -> int: return int.from_bytes(self.read(address, 4), 'little', signed=False)
    def u64(self, address: int) -> int: return int.from_bytes(self.read(address, 8), 'little', signed=False)
    def i8(self, address: int) -> int: return int.from_bytes(self.read(address, 1), 'little', signed=True)
    def i16(self, address: int) -> int: return int.from_bytes(self.read(address, 2), 'little', signed=True)
    def i32(self, address: int) -> int: return int.from_bytes(self.read(address, 4), 'little', signed=True)
    def i64(self, address: int) -> int: return int.from_bytes(self.read(address, 8), 'little', signed=True)
    def f32(self, address: int) -> float: return struct.unpack('<f', self.read(address, 4))[0]
    def f64(self, address: int) -> float: return struct.unpack('<d', self.read(address, 8))[0]
    def ptr(self, address: int) -> int: return self.u64(address)

    def valid_ptr(self, value: int, size: int = 8) -> bool:
        if not isinstance(value, int) or not isinstance(size, int):
            raise TypeError('value and size must be int')
        if size < 1:
            raise ValueError('size must be >= 1')
        if value < USER_MIN or value + size > USER_MAX:
            return False
        return self.readable(value, size)

    @property
    def main_module(self) -> Module:
        mods = self.modules()
        if not mods:
            raise UeError('no modules')
        return mods[0]

    def module_at(self, address: int) -> Module | None:
        if not isinstance(address, int):
            raise TypeError(f'address must be int, got {type(address).__name__}')
        for m in self.modules():
            if m.contains(address):
                return m
        return None

    @property
    def fresh(self) -> 'MemorySource':
        return self

    def _read(self, address: int, size: int) -> bytes:
        raise NotImplementedError

    def _readable_ranges(self, address: int, size: int) -> list[tuple[int, int]]:
        raise NotImplementedError

    def _write(self, address: int, data: bytes) -> None:
        raise MemoryWriteError(address, len(data), 'source is read-only')

    def regions(self) -> list[Region]:
        raise NotImplementedError

    def modules(self) -> list[Module]:
        raise NotImplementedError

    def refresh(self) -> None:
        pass


PROCESS_CREATE_THREAD, PROCESS_VM_OPERATION = 0x0002, 0x0008
PROCESS_VM_READ, PROCESS_VM_WRITE, PROCESS_QUERY_INFORMATION = 0x0010, 0x0020, 0x0400


def handle_rights(*, write: bool = False, remote_calls: bool = False) -> int:
    """Access mask for open_process: query + read, plus write or remote-call rights on request."""
    rights = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ
    if write:
        rights |= PROCESS_VM_OPERATION | PROCESS_VM_WRITE
    if remote_calls:
        rights |= PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE
    return rights


def open_process(pid: int, *, write: bool = False, remote_calls: bool = False) -> 'Process':
    """Open a live process with exactly handle_rights(...); failures raise TargetError."""
    if not isinstance(pid, int):
        raise TypeError(f'pid must be int, got {type(pid).__name__}')
    if pid <= 0:
        raise TargetError(pid, 'invalid pid')
    try:
        process = Process(pid, da=handle_rights(write=write, remote_calls=remote_calls))
    except OSError as e:
        raise TargetError(pid, f'OpenProcess failed: winerror {e.winerror}') from e
    try:
        alive = process.still_alive()
    except OSError as e:
        process.close()
        raise TargetError(pid, f'cannot query process: winerror {e.winerror}') from e
    if not alive:
        process.close()
        raise TargetError(pid, 'process has exited')
    return process


_current_lock = threading.Lock()
_current = None


def current_process() -> 'Process':
    """The shared own-process Process; its reads and writes go through Read/WriteProcessMemory."""
    global _current
    with _current_lock:
        if _current is None:
            _current = Process(Process.current.process_id, Process.current.handle)
        return _current


def _contiguous_regions(mbis, lo: int, hi: int) -> list[Region]:
    out, pos = [], lo
    with contextlib.suppress(OSError):  # the first failed query ends the walk
        for mbi in mbis:
            base, end = max(int(mbi.BaseAddress), pos), min(int(mbi.BaseAddress) + int(mbi.RegionSize), hi)
            if end <= base:
                break
            if base > pos:
                out.append(Region(pos, base - pos, 0, MEM_FREE, 0))
            out.append(Region(base, end - base, int(mbi.Protect), int(mbi.State), int(mbi.Type)))
            if (pos := end) >= hi:
                break
    if pos < hi:
        out.append(Region(pos, hi - pos, 0, MEM_FREE, 0))
    return out


def _first_gap(runs: list[tuple[int, int]], lo: int, hi: int) -> int | None:
    if not runs or runs[0][0] > lo:
        return lo
    return runs[0][1] if runs[0][1] < hi else None


class _Page:
    __slots__ = ('data', 'spans')

    def __init__(self, size: int):
        self.data = bytearray(size)
        self.spans = []  # sorted, merged (lo, hi) offsets of the bytes present

    def add(self, offset: int, data: bytes):
        self.data[offset:offset + len(data)] = data
        merged = []
        for lo, hi in sorted(self.spans + [(offset, offset + len(data))]):
            if merged and lo <= merged[-1][1]:
                merged[-1] = (merged[-1][0], max(merged[-1][1], hi))
            else:
                merged.append((lo, hi))
        self.spans = merged

    def gaps(self, lo: int, hi: int) -> list[tuple[int, int]]:
        out, pos = [], lo
        for s_lo, s_hi in self.spans:
            if s_lo >= hi:
                break
            if s_hi <= pos:
                continue
            if s_lo > pos:
                out.append((pos, s_lo))
            pos = s_hi
        if pos < hi:
            out.append((pos, hi))
        return out


class _SharedState:
    def __init__(self, requery_interval, max_cache_bytes):
        self.lock = threading.RLock()
        self.requery_interval = requery_interval
        self.max_cache_bytes = max_cache_bytes
        self.bases = self.regions = self.stamps = self.modules = None
        self.pages = collections.OrderedDict()


class ProcessSource(MemorySource):
    """Live memory of a Process: self-healing region map, optional page cache, guarded writes."""

    def __init__(self, process: 'Process', *, cache: bool = True, page_size: int = 0x10000,
                 max_cache_bytes: int | None = None, requery_interval: float = 0.25):
        if process is Process.current:
            raise ValueError('ProcessSource cannot wrap Process.current; use current_process()')
        if not isinstance(page_size, int):
            raise TypeError(f'page_size must be int, got {type(page_size).__name__}')
        if page_size < 0x1000 or page_size & (page_size - 1):
            raise ValueError(f'page_size must be a power of two >= 0x1000, got {page_size:#x}')
        if max_cache_bytes is not None:
            if not isinstance(max_cache_bytes, int):
                raise TypeError(f'max_cache_bytes must be int or None, got {type(max_cache_bytes).__name__}')
            if max_cache_bytes < page_size:
                raise ValueError(f'max_cache_bytes {max_cache_bytes:#x} is below page_size {page_size:#x}')
        if not isinstance(requery_interval, (int, float)):
            raise TypeError(f'requery_interval must be int or float, got {type(requery_interval).__name__}')
        if requery_interval != requery_interval or requery_interval < 0:
            raise ValueError(f'requery_interval must be >= 0, got {requery_interval!r}')
        self.process = process
        self.cache = bool(cache)
        self.page_size = page_size
        self._state = _SharedState(requery_interval, max_cache_bytes)
        self._fresh = None

    @property
    def fresh(self) -> 'ProcessSource':
        if not self.cache:
            return self
        with self._state.lock:
            if self._fresh is None:
                fresh = ProcessSource.__new__(ProcessSource)
                fresh.process, fresh.cache, fresh.page_size, fresh._state, fresh._fresh = self.process, False, self.page_size, self._state, None
                self._fresh = fresh
            return self._fresh

    def _ensure_map(self):
        st = self._state
        if st.bases is None:
            stamp = time.monotonic()
            st.regions = _contiguous_regions(self.process.iter_memory_region(0, USER_MAX), 0, USER_MAX)
            st.bases = [r.base for r in st.regions]
            st.stamps = [stamp] * len(st.regions)

    def _query_span(self, lo: int, hi: int):
        pos = lo
        while pos < hi:
            yield (mbi := self.process.virtual_query(pos))
            pos = int(mbi.BaseAddress) + int(mbi.RegionSize)

    def _heal(self, lo: int, hi: int, force: bool = False):
        """Re-walk the map regions meeting [lo, hi): every one if force, else the stale unreadable ones."""
        st, hi = self._state, min(hi, USER_MAX)
        if lo >= hi:
            return
        now = time.monotonic()
        i = bisect.bisect_right(st.bases, lo) - 1
        while i < len(st.bases) and st.bases[i] < hi:
            r = st.regions[i]
            if force or not r.readable and now - st.stamps[i] >= st.requery_interval:
                stamp = time.monotonic()
                new = _contiguous_regions(self._query_span(r.base, r.end), r.base, r.end)
                st.regions[i:i + 1] = new
                st.bases[i:i + 1] = [x.base for x in new]
                st.stamps[i:i + 1] = [stamp] * len(new)
                i += len(new)
            else:
                i += 1

    def _runs(self, lo: int, hi: int, writable: bool = False) -> list[tuple[int, int]]:
        """Merged (start, end) runs of [lo, hi) inside readable (or writable) map regions."""
        st, hi, out = self._state, min(hi, USER_MAX), []
        if lo >= hi:
            return out
        regions, i = st.regions, bisect.bisect_right(st.bases, lo) - 1
        while i < len(regions) and (r := regions[i]).base < hi:
            if r.writable if writable else r.readable:
                s, e = max(r.base, lo), min(r.end, hi)
                if out and out[-1][1] == s:
                    out[-1] = (out[-1][0], e)
                else:
                    out.append((s, e))
            i += 1
        return out

    def _readable_ranges(self, address: int, size: int) -> list[tuple[int, int]]:
        with self._state.lock:
            self._ensure_map()
            self._heal(address, address + size)
            return [(s, e - s) for s, e in self._runs(address, address + size)]

    def _read(self, address: int, size: int) -> bytes:
        st = self._state
        with st.lock:
            if not self.cache:
                return self._read_direct(address, size)
            pbase = address & -self.page_size
            off = address - pbase
            if (rec := st.pages.get(pbase)) is not None and off + size <= self.page_size:
                for lo, hi in rec.spans:
                    if lo <= off and off + size <= hi:
                        if st.max_cache_bytes is not None:
                            st.pages.move_to_end(pbase)
                        return rec.data[off:off + size]
            return self._read_paged(address, size)

    def _read_direct(self, address: int, size: int) -> bytes:
        end = address + size
        self._ensure_map()
        self._heal(address, end)
        if (gap := _first_gap(self._runs(address, end), address, end)) is not None:
            raise MemoryReadError(address, size, f'unreadable at {gap:#x}')
        try:
            return self.process.read(address, size, strict=True)
        except OSError as e:
            self._heal(address, end, force=True)
            raise MemoryReadError(address, size, f'winerror {e.winerror}') from e

    def _read_paged(self, address: int, size: int) -> bytes:
        st, ps, end = self._state, self.page_size, address + size
        first, cap = address & -ps, st.max_cache_bytes
        if cap is not None and (end - first + ps - 1) // ps * ps > cap:
            return self._read_direct(address, size)
        self._ensure_map()
        out = []
        for pbase in range(first, end, ps):
            lo, hi = max(address, pbase) - pbase, min(end, pbase + ps) - pbase
            if (rec := st.pages.get(pbase)) is None:
                rec = self._fill(pbase, None, [(0, ps)])
            else:
                if cap is not None:
                    st.pages.move_to_end(pbase)
                if gaps := rec.gaps(lo, hi):
                    self._fill(pbase, rec, gaps)
            if gaps := [(lo, hi)] if rec is None else rec.gaps(lo, hi):
                raise MemoryReadError(address, size, f'unreadable at {pbase + gaps[0][0]:#x}')
            out.append(rec.data[lo:hi])
        return b''.join(out)

    def _fill(self, pbase: int, rec: '_Page | None', wanted: list[tuple[int, int]]) -> '_Page | None':
        """Heal the wanted page offsets and fetch their readable bytes into rec, which is created on the first bytes."""
        for w_lo, w_hi in wanted:
            self._heal(pbase + w_lo, pbase + w_hi)
            rec = self._fetch(pbase, rec, pbase + w_lo, pbase + w_hi, retry=True)
        return rec

    def _fetch(self, pbase: int, rec: '_Page | None', lo: int, hi: int, retry: bool) -> '_Page | None':
        for s, e in self._runs(lo, hi):
            try:
                data = self.process.read(s, e - s, strict=True)
            except OSError:
                self._heal(s, e, force=True)
                if retry:  # the failed run's now-readable bytes get one more try
                    rec = self._fetch(pbase, rec, s, e, retry=False)
                continue
            if rec is None:
                rec = self._new_page(pbase)
            rec.add(s - pbase, data)
        return rec

    def _new_page(self, pbase: int) -> _Page:
        st = self._state
        if (cap := st.max_cache_bytes) is not None:
            while st.pages and (len(st.pages) + 1) * self.page_size > cap:
                st.pages.popitem(last=False)
        st.pages[pbase] = rec = _Page(self.page_size)
        return rec

    def _write(self, address: int, data: bytes) -> None:
        st, size = self._state, len(data)
        end = address + size
        with st.lock:
            self._ensure_map()
            self._heal(address, end, force=True)
            if (gap := _first_gap(self._runs(address, end, writable=True), address, end)) is not None:
                raise MemoryWriteError(address, size, f'not writable at {gap:#x}')
            try:
                self.process.write(address, data)
            except OSError as e:
                self._heal(address, end, force=True)
                raise MemoryWriteError(address, size, f'winerror {e.winerror}') from e
            ps = self.page_size
            first = address & -ps
            stale = range(first, end, ps) if (end - first + ps - 1) // ps <= len(st.pages) else [p for p in st.pages if first <= p < end]
            for pbase in stale:
                st.pages.pop(pbase, None)

    def regions(self) -> list[Region]:
        with self._state.lock:
            self._ensure_map()
            return list(self._state.regions)

    def modules(self) -> list[Module]:
        st, process = self._state, self.process
        with st.lock:
            if st.modules is None:
                try:
                    text = lambda u: process.read(u.Buffer, u.Length, strict=True).decode('utf-16-le', 'ignore')
                    st.modules = [
                        Module(text(ldr.BaseDllName), int(ldr.DllBase), int(ldr.SizeOfImage), text(ldr.FullDllName))
                        for ldr in process.enum_ldr_data()
                    ]
                except OSError as e:
                    raise TargetError(process.process_id, f'cannot list modules: winerror {e.winerror}') from e
            return list(st.modules)

    def refresh(self) -> None:
        st = self._state
        with st.lock:
            st.bases = st.regions = st.stamps = st.modules = None
            st.pages.clear()


_SUB_PAGE = 0x1000


class _PagedRecord:
    __slots__ = ('data', 'mask')

    def __init__(self, data: bytearray, mask: int):
        self.data = data
        self.mask = mask  # bit k: sub-page k is held


def _paged_int(size: int, signed: bool):
    """A PagedSource typed reader: a hit on one fully held page under the lock, else MemorySource's read."""
    def read_int(self, address: int) -> int:
        if type(address) is int and address >= 0 and (off := address & (self.page_size - 1)) + size <= self.page_size:
            with self._lock:
                if (rec := self._pages.get(pbase := address - off)) is not None and rec.mask == self._full:
                    if self.max_cache_bytes is not None:
                        self._pages.move_to_end(pbase)
                    return int.from_bytes(rec.data[off:off + size], 'little', signed=signed)
        return int.from_bytes(MemorySource.read(self, address, size), 'little', signed=signed)
    return read_int


class PagedSource(MemorySource):
    """Forwards to `inner` through a page cache: 64 KiB pages, then 4 KiB pages, then `inner`'s own read.

    Reads that do not fit the pages go to `inner` unchanged; `fresh` is `inner.fresh`; `refresh()` drops every page.
    A cache hit skips `read`/`_read` and the typed readers' base path, so wrap a source rather than subclass this one.
    """

    def __init__(self, inner: MemorySource, *, page_size: int = 0x10000, max_cache_bytes: int | None = 1 << 30):
        if not isinstance(inner, MemorySource):
            raise TypeError(f'inner must be a MemorySource, got {type(inner).__name__}')
        if not isinstance(page_size, int):
            raise TypeError(f'page_size must be int, got {type(page_size).__name__}')
        if not 0x1000 <= page_size <= 0x100000 or page_size & (page_size - 1):
            raise ValueError(f'page_size must be a power of two from 0x1000 to 0x100000, got {page_size:#x}')
        if max_cache_bytes is not None:
            if not isinstance(max_cache_bytes, int):
                raise TypeError(f'max_cache_bytes must be int or None, got {type(max_cache_bytes).__name__}')
            if max_cache_bytes < page_size:
                raise ValueError(f'max_cache_bytes {max_cache_bytes:#x} is below page_size {page_size:#x}')
        self.inner = inner
        self.page_size = page_size
        self.max_cache_bytes = max_cache_bytes
        self._lock = threading.RLock()
        self._pages = collections.OrderedDict()
        self._bad_pages, self._bad_subs = set(), set()  # the negative map: failed page and sub-page bases
        self._full = (1 << (page_size // _SUB_PAGE)) - 1

    @property
    def pointer_size(self) -> int:
        return self.inner.pointer_size

    @property
    def fresh(self) -> MemorySource:
        return self.inner.fresh

    def read(self, address: int, size: int) -> bytes:
        if type(address) is int and type(size) is int and size > 0 and address >= 0 and (off := address & (self.page_size - 1)) + size <= self.page_size:
            with self._lock:
                if (rec := self._pages.get(pbase := address - off)) is not None and rec.mask == self._full:
                    if self.max_cache_bytes is not None:
                        self._pages.move_to_end(pbase)
                    return bytes(rec.data[off:off + size])
        return MemorySource.read(self, address, size)

    u8, u16, u32, u64 = _paged_int(1, False), _paged_int(2, False), _paged_int(4, False), _paged_int(8, False)
    i8, i16, i32, i64 = _paged_int(1, True), _paged_int(2, True), _paged_int(4, True), _paged_int(8, True)
    ptr = u64

    def _read(self, address: int, size: int) -> bytes:
        ps = self.page_size
        if size > ps:
            return self.inner.read(address, size)
        end = address + size
        with self._lock:
            out = []
            for pbase in range(address & -ps, end, ps):
                lo, hi = max(address, pbase) - pbase, min(end, pbase + ps) - pbase
                rec = self._record(pbase)
                if not self._hold(pbase, rec, lo, hi):
                    return self.inner.read(address, size)
                out.append(rec.data[lo:hi])
            return b''.join(out)

    def _record(self, pbase: int) -> _PagedRecord:
        if (rec := self._pages.get(pbase)) is not None:
            if self.max_cache_bytes is not None:
                self._pages.move_to_end(pbase)
            return rec
        data, mask = None, 0
        if pbase not in self._bad_pages:
            try:
                data = self.inner.read(pbase, self.page_size)
                if len(data) != self.page_size:
                    raise MemoryReadError(pbase, self.page_size, f'source returned {len(data)} of {self.page_size} bytes')
                mask = self._full
            except MemoryReadError:
                data, mask = None, 0
                self._bad_pages.add(pbase)
        if (cap := self.max_cache_bytes) is not None:
            while self._pages and (len(self._pages) + 1) * self.page_size > cap:
                self._pages.popitem(last=False)
        rec = self._pages[pbase] = _PagedRecord(bytearray(data) if data is not None else bytearray(self.page_size), mask)
        return rec

    def _hold(self, pbase: int, rec: _PagedRecord, lo: int, hi: int) -> bool:
        """Fetch the missing sub-pages of [lo, hi) that are not marked failed; True when the record holds every byte."""
        held = True
        for k in range(lo // _SUB_PAGE, (hi - 1) // _SUB_PAGE + 1):
            if rec.mask >> k & 1:
                continue
            sub = pbase + k * _SUB_PAGE
            if self.page_size == _SUB_PAGE or sub in self._bad_subs:
                held = False
                continue
            try:
                data = self.inner.read(sub, _SUB_PAGE)
                if len(data) != _SUB_PAGE:
                    raise MemoryReadError(sub, _SUB_PAGE, f'source returned {len(data)} of {_SUB_PAGE} bytes')
                rec.data[k * _SUB_PAGE:(k + 1) * _SUB_PAGE] = data
                rec.mask |= 1 << k
            except MemoryReadError:
                self._bad_subs.add(sub)
                held = False
        return held

    def _readable_ranges(self, address: int, size: int) -> list[tuple[int, int]]:
        return self.inner.readable_ranges(address, size)

    def _write(self, address: int, data: bytes) -> None:
        ps, end = self.page_size, address + len(data)
        with self._lock:
            try:
                self.inner.write(address, data)
            finally:
                first = address & -ps
                stale = range(first, end, ps) if (end - first + ps - 1) // ps <= len(self._pages) else [p for p in self._pages if first <= p < end]
                for pbase in stale:
                    self._pages.pop(pbase, None)

    def regions(self) -> list[Region]:
        return self.inner.regions()

    def modules(self) -> list[Module]:
        return self.inner.modules()

    def refresh(self) -> None:
        with self._lock:
            self._pages.clear()
            self._bad_pages.clear()
            self._bad_subs.clear()
            self.inner.refresh()
