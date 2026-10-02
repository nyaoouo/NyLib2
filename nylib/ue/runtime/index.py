"""The runtime object index (RT2): a one-pass GObjects table, its lookups and the weak-pointer serial finder."""
import fnmatch
import logging
import threading
import time
import typing
from typing import Callable

from ..engine.unreal import UEClass, UEStruct
from ..errors import DetectionError, MemoryReadError
from ..flags import EClassCastFlags, EObjectFlags
from ..model import ObjectRecord, ObjectTable
from ..reflect import LiveResolver

if typing.TYPE_CHECKING:
    from ..engine.core import Engine

_log = logging.getLogger('nylib.ue.runtime.index')

SERIAL_NUMBER_START = 1000
SERIAL_MIN_SAMPLES = 64
DESTROYED_FLAGS = EObjectFlags.BeginDestroyed | EObjectFlags.FinishDestroyed
SKIPPED_FLAGS = DESTROYED_FLAGS | EObjectFlags.ClassDefaultObject
_SUPER_CHAIN_BOUND = 256  # DV18
_UNSET = object()


def _is_int(value) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _require_chunked(e: 'Engine') -> None:
    if not e.off.FUObjectArray.bIsChunked:
        raise DetectionError('ObjectIndex', 'the GObjects layout is not chunked')
    if e.objects.NumElementsPerChunk <= 0:
        raise DetectionError('ObjectIndex', f'the GObjects chunk size {e.objects.NumElementsPerChunk} is not positive')


def _iter_item_bytes(e: 'Engine'):
    """Yield (slot index, raw item bytes), one read per chunk (ea0dab3's chunked override layout)."""
    _require_chunked(e)
    oa = e.objects
    per, isz = oa.NumElementsPerChunk, oa.SizeOfFUObjectItem
    n = oa.num()
    table = e.mem.ptr(oa.GObjects + e.off.FUObjectArray.get_objects_offset())
    index = 0
    chunk = 0
    while index < n:
        chunk_addr = e.mem.ptr(table + 8 * chunk)
        count = min(per, n - index)
        data = e.mem.read(chunk_addr, count * isz)
        for j in range(count):
            yield index, data[j * isz:(j + 1) * isz]
            index += 1
        chunk += 1


def find_serial_number_offset(e: 'Engine') -> int | None:
    oa = e.objects
    isz, ioff = oa.SizeOfFUObjectItem, oa.FUObjectItemInitialOffset
    candidates: dict[int, list[int]] = {}
    for _, item in _iter_item_bytes(e):
        obj = int.from_bytes(item[ioff:ioff + 8], 'little')
        if obj == 0:
            continue
        for k in range(0, isz - 3, 4):
            if ioff <= k < ioff + 8:
                continue
            v = int.from_bytes(item[k:k + 4], 'little', signed=True)
            if v == 0:
                continue
            candidates.setdefault(k, []).append(v)
    qualifying = [k for k, values in candidates.items()
                  if len(values) >= SERIAL_MIN_SAMPLES and len(set(values)) == len(values) and all(v > SERIAL_NUMBER_START for v in values)]
    if len(qualifying) == 1:
        return qualifying[0]
    _log.debug('find_serial_number_offset: no unique candidate, counts=%s', {k: len(v) for k, v in sorted(candidates.items())})
    return None


class ObjectIndex:
    """A session's GObjects table, built fresh under its lock and cached until refresh()."""

    def __init__(self, e: 'Engine', decode: Callable[[int, int], str], lock: threading.RLock):
        self._e = e
        self._decode = decode
        self._lock = lock
        self._table: ObjectTable | None = None
        self.built: float | None = None
        self.unreadable = 0
        self._super_cache: dict[int, tuple[int, ...]] = {}
        self._cast_flags_cache: dict[int, int] = {}
        self._serial_offset = _UNSET

    def table(self) -> ObjectTable:
        with self._lock:
            if self._table is None:
                self._table = self._build_table()
                self.built = time.monotonic()
            return self._table

    def _build_table(self) -> ObjectTable:
        e = self._e
        off = e.off.UObject
        fname_off = e.off.FName
        fname_size = e.off.InSDK.Name.FNameSize
        header_size = max(off.Flags + 4, off.Index + 4, off.Class + 8, off.Name + fname_size, off.Outer + 8)
        outline = e.settings.Internal.bUseOutlineNumberName
        addr_to_index: dict[int, int] = {}
        raw_rows = []
        unreadable = 0
        for index, item in _iter_item_bytes(e):
            obj = int.from_bytes(item[e.objects.FUObjectItemInitialOffset:e.objects.FUObjectItemInitialOffset + 8], 'little')
            if obj == 0:
                continue
            try:
                h = e.mem.read(obj, header_size)
                flags = int.from_bytes(h[off.Flags:off.Flags + 4], 'little')
                class_ptr = int.from_bytes(h[off.Class:off.Class + 8], 'little')
                outer_ptr = int.from_bytes(h[off.Outer:off.Outer + 8], 'little')
                comp_idx = int.from_bytes(h[off.Name + fname_off.CompIdx:off.Name + fname_off.CompIdx + 4], 'little', signed=True)
                number = 0 if outline else int.from_bytes(h[off.Name + fname_off.Number:off.Name + fname_off.Number + 4], 'little')
                name = self._decode(comp_idx, number)
            except (MemoryReadError, ValueError):
                unreadable += 1
                continue
            addr_to_index.setdefault(obj, index)
            raw_rows.append((index, obj, flags, class_ptr, outer_ptr, name))
        records = [
            ObjectRecord(index=index, address=obj, flags=flags, class_index=addr_to_index.get(class_ptr, -1) if class_ptr else -1,
                         outer_index=addr_to_index.get(outer_ptr, -1) if outer_ptr else -1, name=name)
            for index, obj, flags, class_ptr, outer_ptr, name in raw_rows
        ]
        self.unreadable = unreadable
        return ObjectTable(records)

    def refresh(self) -> None:
        with self._lock:
            self._table = None
            self._super_cache.clear()
            self._cast_flags_cache.clear()
            self._serial_offset = _UNSET

    def find(self, path: str) -> int | None:
        if not isinstance(path, str):
            raise TypeError(f'path must be str, got {type(path).__name__}')
        for attempt in range(2):
            t = self.table()
            if (i := t.index_of_path(path)) is None:
                return None
            address = t[i].address
            try:
                if LiveResolver(self._e).path(address) == path:
                    return address
            except MemoryReadError:
                pass
            if attempt == 0:
                with self._lock:
                    if self._table is t:
                        self._table = None
        return None

    def classes_named(self, name: str) -> list[int]:
        if not isinstance(name, str):
            raise TypeError(f'name must be str, got {type(name).__name__}')
        return [rec.address for rec in self.table() if rec.name == name and self.is_class_object(rec.address)]

    def instances(self, class_address: int) -> list[int]:
        if not _is_int(class_address):
            raise TypeError(f'class_address must be int, got {type(class_address).__name__}')
        t = self.table()
        result = []
        for rec in t:
            if rec.flags & int(SKIPPED_FLAGS) or rec.class_index == -1:
                continue
            if class_address in self.super_chain(t[rec.class_index].address):
                result.append(rec.address)
        return result

    def search(self, pattern: str, class_address: int | None = None) -> list[int]:
        if not isinstance(pattern, str):
            raise TypeError(f'pattern must be str, got {type(pattern).__name__}')
        if class_address is not None and not _is_int(class_address):
            raise TypeError(f'class_address must be int, got {type(class_address).__name__}')
        t = self.table()
        result = []
        for rec in t:
            if rec.flags & int(DESTROYED_FLAGS) or not fnmatch.fnmatchcase(rec.name, pattern):
                continue
            if class_address is not None:
                if rec.class_index == -1 or class_address not in self.super_chain(t[rec.class_index].address):
                    continue
            result.append(rec.address)
        return result

    def owned(self, outer_address: int, class_address: int) -> int | None:
        if not _is_int(outer_address):
            raise TypeError(f'outer_address must be int, got {type(outer_address).__name__}')
        if not _is_int(class_address):
            raise TypeError(f'class_address must be int, got {type(class_address).__name__}')
        t = self.table()
        for rec in t:
            if rec.flags & int(SKIPPED_FLAGS) or rec.outer_index == -1 or t[rec.outer_index].address != outer_address:
                continue
            if rec.class_index == -1 or class_address not in self.super_chain(t[rec.class_index].address):
                continue
            return rec.address
        return None

    def super_chain(self, class_address: int) -> tuple[int, ...]:
        if not _is_int(class_address):
            raise TypeError(f'class_address must be int, got {type(class_address).__name__}')
        if class_address == 0:
            return ()
        with self._lock:
            cached = self._super_cache.get(class_address)
        if cached is not None:
            return cached
        chain = [class_address]
        links = 0
        cur = UEStruct(self._e, class_address)
        while True:
            sup = cur.get_super()
            if not sup:
                break
            links += 1
            if links > _SUPER_CHAIN_BOUND:
                raise MemoryReadError(class_address, 0, f'super chain of {class_address:#x} exceeds {_SUPER_CHAIN_BOUND} links')
            chain.append(sup.address)
            cur = sup
        result = tuple(chain)
        with self._lock:
            self._super_cache[class_address] = result
        return result

    def cast_flags(self, address: int) -> int:
        if not _is_int(address):
            raise TypeError(f'address must be int, got {type(address).__name__}')
        if address == 0:
            return 0
        with self._lock:
            cached = self._cast_flags_cache.get(address)
        if cached is not None:
            return cached
        flags = UEClass(self._e, address).get_cast_flags()
        with self._lock:
            self._cast_flags_cache[address] = flags
        return flags

    def is_class_object(self, address: int) -> bool:
        if not _is_int(address):
            raise TypeError(f'address must be int, got {type(address).__name__}')
        if address == 0:
            return False
        class_ptr = self._e.mem.ptr(address + self._e.off.UObject.Class)
        return bool(self.cast_flags(class_ptr) & int(EClassCastFlags.Class))

    def item(self, index: int) -> tuple[int, int]:
        if not _is_int(index):
            raise TypeError(f'index must be int, got {type(index).__name__}')
        e = self._e
        n = e.objects.num()
        if not (0 <= index < n):
            raise IndexError(index)
        offset = self.serial_offset()
        if offset is None:
            raise DetectionError('FUObjectItem::SerialNumber',
                                 'the weak-pointer serial number offset could not be determined on this target, so weak pointers cannot be checked')
        oa = e.objects
        table = e.mem.ptr(oa.GObjects + e.off.FUObjectArray.get_objects_offset())
        chunk = index // oa.NumElementsPerChunk
        slot = e.mem.ptr(table + 8 * chunk) + (index % oa.NumElementsPerChunk) * oa.SizeOfFUObjectItem
        obj = e.mem.ptr(slot + oa.FUObjectItemInitialOffset)
        serial = e.mem.i32(slot + offset)
        return obj, serial

    def serial_offset(self) -> int | None:
        with self._lock:
            if self._serial_offset is _UNSET:
                self._serial_offset = find_serial_number_offset(self._e)
            return self._serial_offset
