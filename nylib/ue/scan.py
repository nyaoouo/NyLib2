"""Section-scoped byte/pattern/string scanning over a PeImage, with a string-ref cache."""
import re
from typing import Iterable

from .. import pattern as _pattern
from .memory import MemorySource
from .pe import PeImage, Section

# REX 0x48|0x4C, 0x8D, modrm with mod=00 rm=101 (RIP-relative, any reg 0-7): candidate 64-bit LEA sites.
_LEA_CANDIDATE = re.compile(rb'[\x48\x4C]\x8D[\x05\x0D\x15\x1D\x25\x2D\x35\x3D]')


def _check_bool_or_none(value, name: str) -> None:
    if value is not None and not isinstance(value, bool):
        raise TypeError(f'{name} must be bool or None, got {type(value).__name__}')


class Scanner:
    """Not thread-safe. Caches section reads and string-reference lookups for its own lifetime."""

    def __init__(self, source: MemorySource, image: PeImage):
        self.source = source
        self.image = image
        self._chunk_cache: dict[tuple[str, int], list[tuple[int, bytes]]] = {}
        self._string_ref_cache: dict[tuple[str, bool], list[int]] = {}

    def chunks(self, section: Section) -> list[tuple[int, bytes]]:
        key = (section.name, section.address)
        if key not in self._chunk_cache:
            fresh = self.source.fresh
            out = []
            for addr, size in self.source.readable_ranges(section.address, section.size):
                data = fresh.try_read(addr, size)
                if data is not None:
                    out.append((addr, data))
                    continue
                # one retry after re-querying the healed map: a transient failure must not drop the whole range.
                for addr2, size2 in fresh.readable_ranges(addr, size):
                    data2 = fresh.try_read(addr2, size2)
                    if data2 is not None:
                        out.append((addr2, data2))
            self._chunk_cache[key] = out
        return self._chunk_cache[key]

    def _sections(self, executable: bool | None) -> tuple[Section, ...]:
        if executable is None:
            return self.image.sections
        return tuple(s for s in self.image.sections if s.executable == executable)

    def _all_chunks(self, executable: bool | None) -> list[tuple[int, bytes]]:
        out = []
        for s in self._sections(executable):
            out.extend(self.chunks(s))
        return out

    def find_pattern(self, pattern: 'str | _pattern.Pattern', *, executable: bool | None = None) -> list[tuple[int, list]]:
        _check_bool_or_none(executable, 'executable')
        if isinstance(pattern, str):
            try:
                compiled = _pattern.compile_pattern(pattern)
            except Exception as e:
                raise ValueError(f'invalid pattern {pattern!r}: {e}') from e
        elif isinstance(pattern, _pattern.Pattern):
            compiled = pattern
        else:
            raise TypeError(f'pattern must be str or nylib.pattern.Pattern, got {type(pattern).__name__}')
        results = []
        for base_addr, data in self._all_chunks(executable):
            for off, args in compiled.finditer(data):
                vals = [a + base_addr if is_ref else a for a, is_ref in zip(args, compiled.res_is_ref)]
                results.append((base_addr + off, vals))
        results.sort(key=lambda t: t[0])
        return results

    def find_bytes(self, needle: bytes, *, align: int = 1, executable: bool | None = None) -> list[int]:
        if not isinstance(needle, (bytes, bytearray)):
            raise TypeError(f'needle must be bytes-like, got {type(needle).__name__}')
        if len(needle) == 0:
            raise ValueError('needle must not be empty')
        if not isinstance(align, int):
            raise TypeError(f'align must be int, got {type(align).__name__}')
        if align < 1:
            raise ValueError(f'align must be >= 1, got {align}')
        _check_bool_or_none(executable, 'executable')
        needle = bytes(needle)
        out = []
        for base_addr, data in self._all_chunks(executable):
            start = 0
            while (idx := data.find(needle, start)) != -1:
                addr = base_addr + idx
                if addr % align == 0:
                    out.append(addr)
                start = idx + 1
        out.sort()
        return out

    def find_string(self, text: str, *, wide: bool) -> list[int]:
        if not isinstance(text, str):
            raise TypeError(f'text must be str, got {type(text).__name__}')
        if text == '':
            raise ValueError('text must not be empty')
        if wide:
            needle, align = text.encode('utf-16-le') + b'\0\0', 2
        else:
            needle, align = text.encode('utf-8') + b'\0', 1
        return self.find_bytes(needle, align=align, executable=None)

    def lea_refs(self, targets: Iterable[int]) -> dict[int, list[int]]:
        items = list(targets)
        for t in items:
            if not isinstance(t, int):
                raise TypeError(f'targets must be ints, got {type(t).__name__}')
        wanted = set(items)
        if not wanted:
            return {}
        result = {t: [] for t in wanted}
        for base_addr, data in self._all_chunks(True):
            for m in _LEA_CANDIDATE.finditer(data):
                i = m.start()
                if i + 7 > len(data):  # the 7-byte instruction must not cross the chunk end
                    continue
                disp = int.from_bytes(data[i + 3:i + 7], 'little', signed=True)
                target = base_addr + i + 7 + disp
                if target in result:
                    result[target].append(base_addr + i)
        for sites in result.values():
            sites.sort()
        return result

    def string_refs(self, text: str, *, wide: bool) -> list[int]:
        if not isinstance(text, str):
            raise TypeError(f'text must be str, got {type(text).__name__}')
        if text == '':
            raise ValueError('text must not be empty')
        key = (text, bool(wide))
        if key not in self._string_ref_cache:
            self.prefetch_string_refs([key])
        return list(self._string_ref_cache[key])

    def prefetch_string_refs(self, items: Iterable[tuple[str, bool]]) -> None:
        to_fetch: dict[tuple[str, bool], tuple[str, bool]] = {}
        for item in items:
            if not isinstance(item, tuple) or len(item) != 2:
                raise TypeError(f'invalid prefetch_string_refs item {item!r}')
            text, wide = item
            if not isinstance(text, str) or not isinstance(wide, bool):
                raise TypeError(f'invalid prefetch_string_refs item {item!r}')
            if text == '':
                raise ValueError('text must not be empty')
            key = (text, wide)
            if key not in self._string_ref_cache:
                to_fetch[key] = (text, wide)
        if not to_fetch:
            return
        per_key_addrs = {}
        addr_union = set()
        for key, (text, wide) in to_fetch.items():
            addrs = self.find_string(text, wide=wide)
            per_key_addrs[key] = addrs
            addr_union.update(addrs)
        refs = self.lea_refs(addr_union)
        for key, addrs in per_key_addrs.items():
            self._string_ref_cache[key] = sorted({site for a in addrs for site in refs.get(a, [])})

    def aligned_values(self, value: int, *, size: int = 8, align: int = 8, executable: bool | None = False) -> list[int]:
        if not isinstance(value, int):
            raise TypeError(f'value must be int, got {type(value).__name__}')
        if not isinstance(size, int):
            raise TypeError(f'size must be int, got {type(size).__name__}')
        if size not in (1, 2, 4, 8):
            raise ValueError(f'size must be one of 1, 2, 4, 8, got {size}')
        if not (0 <= value < 2 ** (8 * size)):
            raise ValueError(f'value {value:#x} does not fit in {size} bytes')
        return self.find_bytes(value.to_bytes(size, 'little'), align=align, executable=executable)

    def rip_target(self, address: int, disp_offset: int, length: int) -> int:
        if not isinstance(address, int) or not isinstance(disp_offset, int) or not isinstance(length, int):
            raise TypeError('address, disp_offset and length must be int')
        return address + length + self.source.i32(address + disp_offset)
