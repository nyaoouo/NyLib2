"""Remote PE32+ AMD64 header parsing and import-table walking over a MemorySource."""
import dataclasses
import struct

from .errors import MemoryReadError, PeFormatError
from .memory import MemorySource

IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_WRITE = 0x20000000, 0x40000000, 0x80000000

_SECTION_STRUCT = struct.Struct('<8sIIIIIIHHI')  # name, VirtualSize, VirtualAddress, SizeOfRawData, ptr/reloc/line*3, n_reloc, n_line, Characteristics
_DESCRIPTOR_STRUCT = struct.Struct('<IIIII')  # OriginalFirstThunk, TimeDateStamp, ForwarderChain, Name, FirstThunk
_MAX_SECTIONS = 96
_MAX_DESCRIPTORS = 4096
_MAX_THUNKS = 65536
_STRING_WINDOW = 512


@dataclasses.dataclass(frozen=True, slots=True)
class Section:
    name: str
    address: int
    size: int
    characteristics: int

    @property
    def end(self) -> int:
        return self.address + self.size

    @property
    def executable(self) -> bool:
        return bool(self.characteristics & IMAGE_SCN_MEM_EXECUTE)

    @property
    def writable(self) -> bool:
        return bool(self.characteristics & IMAGE_SCN_MEM_WRITE)

    def contains(self, address: int) -> bool:
        if not isinstance(address, int):
            raise TypeError(f'address must be int, got {type(address).__name__}')
        return self.address <= address < self.end


@dataclasses.dataclass(frozen=True, slots=True)
class ImportSlot:
    dll: str
    name: str
    slot: int
    value: int


def _read_cstring(source: MemorySource, address: int) -> str | None:
    """The ASCII bytes up to the first NUL within the readable prefix of [address, address + 512); None if unreadable."""
    ranges = source.readable_ranges(address, _STRING_WINDOW)
    if not ranges or ranges[0][0] != address:
        return None
    _, length = ranges[0]
    data = source.try_read(address, length)
    if data is None:
        return None
    end = data.find(b'\0')
    if end < 0:
        return None
    raw = data[:end]
    if not raw.isascii():
        return None
    return raw.decode('ascii')


class PeImage:
    """PE32+ AMD64 headers and section table read from a remote MemorySource, plus lazy import parsing."""

    def __init__(self, source: MemorySource, base: int):
        if not isinstance(base, int):
            raise TypeError(f'base must be int, got {type(base).__name__}')
        self.source = source
        self.base = base
        try:
            self._parse()
        except MemoryReadError as e:
            raise PeFormatError(base, f'unreadable header: {e.reason}') from e
        self._imports_cache: list[ImportSlot] | None = None

    def _parse(self):
        source, base = self.source, self.base
        if source.read(base, 2) != b'MZ':
            raise PeFormatError(base, 'no MZ signature')
        nt = base + source.u32(base + 0x3C)
        if source.read(nt, 4) != b'PE\0\0':
            raise PeFormatError(base, 'no PE signature')
        machine = source.u16(nt + 4)
        if machine != 0x8664:
            raise PeFormatError(base, f'machine {machine:#x} is not AMD64')
        num_sections = source.u16(nt + 6)
        timestamp = source.u32(nt + 8)
        size_opt = source.u16(nt + 20)
        opt = nt + 24
        magic = source.u16(opt)
        if magic != 0x20B:
            raise PeFormatError(base, 'not PE32+')
        if num_sections > _MAX_SECTIONS:
            raise PeFormatError(base, 'too many sections')
        size_image = source.u32(opt + 0x38)
        sections = []
        sec_table = opt + size_opt
        for i in range(num_sections):
            entry = source.read(sec_table + i * _SECTION_STRUCT.size, _SECTION_STRUCT.size)
            name_raw, virt_size, virt_addr, raw_size, _p1, _p2, _p3, _n1, _n2, chars = _SECTION_STRUCT.unpack(entry)
            name = name_raw.split(b'\0', 1)[0].decode('latin-1')
            sections.append(Section(name, base + virt_addr, virt_size or raw_size, chars))
        self.size = size_image
        self.timestamp = timestamp
        self.machine = machine
        self.sections = tuple(sections)
        self._opt = opt

    def section(self, name: str) -> Section | None:
        if not isinstance(name, str):
            raise TypeError(f'name must be str, got {type(name).__name__}')
        for s in self.sections:
            if s.name == name:
                return s
        return None

    def rva(self, address: int) -> int:
        if not isinstance(address, int):
            raise TypeError(f'address must be int, got {type(address).__name__}')
        return address - self.base

    def import_slots(self, name: str) -> list[ImportSlot]:
        if not isinstance(name, str):
            raise TypeError(f'name must be str, got {type(name).__name__}')
        return [s for s in self.imports() if s.name == name]

    def imports(self) -> list[ImportSlot]:
        if self._imports_cache is None:
            self._imports_cache = self._compute_imports()
        return list(self._imports_cache)

    def _compute_imports(self) -> list[ImportSlot]:
        source, base, opt = self.source, self.base, self._opt
        raw = source.try_read(opt + 0x6C, 4)
        if raw is None or int.from_bytes(raw, 'little') < 2:
            return []
        raw = source.try_read(opt + 0x78, 4)
        if raw is None:
            return []
        import_rva = int.from_bytes(raw, 'little')
        if import_rva == 0:
            return []
        dir_addr = base + import_rva
        slots = []
        for i in range(_MAX_DESCRIPTORS):
            draw = source.try_read(dir_addr + i * _DESCRIPTOR_STRUCT.size, _DESCRIPTOR_STRUCT.size)
            if draw is None or draw == b'\0' * _DESCRIPTOR_STRUCT.size:
                break
            orig_first_thunk, _tds, _fwd, name_rva, first_thunk = _DESCRIPTOR_STRUCT.unpack(draw)
            dll = _read_cstring(source, base + name_rva)
            if dll is None:
                continue
            slots.extend(self._descriptor_slots(dll.lower(), (orig_first_thunk or first_thunk), first_thunk))
        return slots

    def _descriptor_slots(self, dll: str, thunk_rva: int, first_thunk_rva: int) -> list[ImportSlot]:
        source, base = self.source, self.base
        thunk_addr, first_thunk_addr = base + thunk_rva, base + first_thunk_rva
        out = []
        for i in range(_MAX_THUNKS):
            vraw = source.try_read(thunk_addr + 8 * i, 8)
            if vraw is None:
                break
            v = int.from_bytes(vraw, 'little')
            if v == 0:
                break
            if v & (1 << 63):
                name = f'#{v & 0xFFFF}'
            else:
                name = _read_cstring(source, base + (v & 0x7FFFFFFF) + 2)
            slot = first_thunk_addr + 8 * i
            sraw = source.try_read(slot, 8)
            if name is not None and sraw is not None:
                out.append(ImportSlot(dll, name, slot, int.from_bytes(sraw, 'little')))
        return out
