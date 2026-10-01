"""FName values and name-pool lookup (RT1): decode an FName, read one from memory, find one by text."""
import re
import threading
import typing

from ..engine.utfn import wstring_to_string
from ..errors import MemoryReadError

if typing.TYPE_CHECKING:
    from ..engine.core import Engine

_SPLIT_RE = re.compile(r'(.+)_(0|[1-9][0-9]*)')
_MAX_SUFFIX = 0x7FFFFFFF - 1


def _is_int(value) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _find_all(data: bytes, sub: bytes):
    pos = 0
    while (p := data.find(sub, pos)) != -1:
        yield p
        pos = p + 1


class FNameValue(str):
    """UE FName::ToString(): the raw text plus the number suffix, case-sensitive like any str."""

    def __new__(cls, text: str, comparison_index: int, number: int, raw: bytes) -> 'FNameValue':
        self = str.__new__(cls, text)
        self.comparison_index = comparison_index
        self.number = number
        self.raw = raw
        return self

    def __repr__(self) -> str:
        return f'FName({str(self)!r})'


class NameDecoder:
    """Decodes FNames from an engine's name pool and finds a comparison index for text (block scans, K14)."""

    def __init__(self, e: 'Engine', lock: threading.RLock):
        self.e = e
        self._lock = lock
        self.size = e.off.InSDK.Name.FNameSize
        self._lookup_memo: dict[str, tuple[FNameValue | None, int, int]] = {}

    def decode(self, comparison_index: int, number: int) -> str:
        if not _is_int(comparison_index):
            raise TypeError(f'comparison_index must be int, got {type(comparison_index).__name__}')
        if not _is_int(number):
            raise TypeError(f'number must be int, got {type(number).__name__}')
        entry = self.e.names.get_name_entry(comparison_index)
        if entry.address == 0:
            raise ValueError(f'FName comparison index {comparison_index:#x} is outside the name pool')
        base = wstring_to_string(entry.get_wstring())
        if self.e.settings.Internal.bUseOutlineNumberName:
            return base
        m = number & 0xFFFFFFFF
        if m > 0:
            return f'{base}_{m - 1}'
        return base

    def read(self, address: int) -> FNameValue:
        if not _is_int(address):
            raise TypeError(f'address must be int, got {type(address).__name__}')
        raw = self.e.mem.read(address, self.size)
        off = self.e.off
        c = int.from_bytes(raw[off.FName.CompIdx:off.FName.CompIdx + 4], 'little', signed=True)
        if self.e.settings.Internal.bUseOutlineNumberName:
            n = 0
        else:
            n = int.from_bytes(raw[off.FName.Number:off.FName.Number + 4], 'little', signed=False)
        return FNameValue(self.decode(c, n), c, n, raw)

    def lookup(self, text: str) -> FNameValue | None:
        if not isinstance(text, str):
            raise TypeError(f'text must be str, got {type(text).__name__}')
        if text == '':
            return None
        e = self.e
        internal = e.settings.Internal
        if not internal.bUseNamePool or internal.bUseCasePreservingName or internal.bUseOutlineNumberName:
            raise NotImplementedError(
                'FName lookup supports FNamePool engines without case-preserving or outline-number names in v1')
        with self._lock:
            cached = self._lookup_memo.get(text)
            if cached is not None:
                value, cached_chunks, cached_cursor = cached
                if value is not None:
                    return value
                if cached_chunks == e.names.get_num_chunks() and cached_cursor == e.names.get_byte_cursor():
                    return None
            m = _SPLIT_RE.fullmatch(text)
            if m and int(m.group(2)) <= _MAX_SUFFIX:
                base, number = m.group(1), int(m.group(2)) + 1
            else:
                base, number = text, 0
            narrow = all(ord(ch) < 0x80 for ch in base)
            if narrow:
                encoded = base.encode('ascii')
                wide = 0
                units = len(encoded)
            else:
                encoded = base.encode('utf-16-le', 'surrogatepass')
                wide = 1
                units = len(encoded) // 2
            index = self._scan(encoded, wide, units, base, case_insensitive=False)
            if index is None and narrow:
                index = self._scan(encoded, wide, units, base, case_insensitive=True)
            value = None
            if index is not None:
                off = e.off
                raw = bytearray(self.size)
                raw[off.FName.CompIdx:off.FName.CompIdx + 4] = (index & 0xFFFFFFFF).to_bytes(4, 'little')
                raw[off.FName.Number:off.FName.Number + 4] = (number & 0xFFFFFFFF).to_bytes(4, 'little')
                value = FNameValue(self.decode(index, number), index, number, bytes(raw))
            self._lookup_memo[text] = (value, e.names.get_num_chunks(), e.names.get_byte_cursor())
            return value

    def _scan(self, encoded: bytes, wide: int, units: int, base: str, case_insensitive: bool) -> int | None:
        e = self.e
        off, names = e.off, e.names
        string_offset = off.FNameEntry.NamePool.StringOffset
        header_offset = off.FNameEntry.NamePool.HeaderOffset
        stride = names.NameEntryStride
        offset_bits = names.FNameBlockOffsetBits
        shift = names.FNameEntryLengthShiftCount
        block_bytes = stride << offset_bits
        num_chunks = names.get_num_chunks()
        byte_cursor = names.get_byte_cursor()
        base_cf = base.lower() if case_insensitive else None
        pattern = re.compile(re.escape(encoded), re.IGNORECASE) if case_insensitive else None
        for b in range(num_chunks + 1):
            size = byte_cursor if b == num_chunks else block_bytes
            if size <= 0:
                continue
            block_addr = e.mem.ptr(names.GNames + off.NameArray.ChunksStart + 8 * b)
            try:
                data = e.mem.read(block_addr, size)
            except MemoryReadError:
                continue
            positions = (mm.start() for mm in pattern.finditer(data)) if case_insensitive else _find_all(data, encoded)
            for p in positions:
                q = p - string_offset
                if q < 0 or q % stride or q + header_offset + 2 > len(data):
                    continue
                header = int.from_bytes(data[q + header_offset:q + header_offset + 2], 'little')
                if (header >> shift) != units or (header & 1) != wide:
                    continue
                index = (b << offset_bits) | (q // stride)
                decoded = self.decode(index, 0)
                if case_insensitive:
                    if decoded.lower() == base_cf:
                        return index
                elif decoded == base:
                    return index
        return None

    def refresh(self) -> None:
        with self._lock:
            self._lookup_memo.clear()
