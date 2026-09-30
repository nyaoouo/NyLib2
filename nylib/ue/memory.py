import dataclasses
import struct

from .errors import MemoryReadError, MemoryWriteError, UeError

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
