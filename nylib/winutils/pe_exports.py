"""PE export-table reader for an image loaded in any process (`ExportTable`), plus `read_exports` for this process."""
import bisect
import ctypes
import dataclasses
import functools
import typing
from .. import winapi


@dataclasses.dataclass(frozen=True)
class Export:
    """One export-table entry; a forwarded export has `address` 0 and `forwarder` set to its 'DLL.Func' text."""
    name: str  # '' for ordinal-only exports
    ordinal: int
    rva: int
    address: int
    forwarder: str


class ExportTable:
    """Export directory of the PE32/PE32+ image at `base`, read through `process` (a nylib `Process`).

    Raises KeyError when the image has no export directory."""

    def __init__(self, process, base: int):
        self.process, self.base = process, base
        nt = process.read(p_nt := base + process.read(base, winapi.IMAGE_DOS_HEADER).e_lfanew, winapi.IMAGE_NT_HEADERS64)
        if nt.OptionalHeader.Magic != 0x20B: nt = process.read(p_nt, winapi.IMAGE_NT_HEADERS32)  # PE32
        self.directory = nt.OptionalHeader.DataDirectory[0]  # IMAGE_DIRECTORY_ENTRY_EXPORT
        if not self.directory.VirtualAddress: raise KeyError(f'module {base:#x} has no export directory')
        self.header = process.read(base + self.directory.VirtualAddress, winapi.IMAGE_EXPORT_DIRECTORY)
        self.image_end = base + nt.OptionalHeader.SizeOfImage

    @functools.cached_property
    def functions(self):
        return self.process.read(self.base + self.header.AddressOfFunctions, ctypes.c_uint32 * self.header.NumberOfFunctions)

    @functools.cached_property
    def names(self):
        return self.process.read(self.base + self.header.AddressOfNames, ctypes.c_uint32 * self.header.NumberOfNames)

    @functools.cached_property
    def name_ordinals(self):
        return self.process.read(self.base + self.header.AddressOfNameOrdinals, ctypes.c_uint16 * self.header.NumberOfNames)

    @functools.cached_property
    def data(self) -> bytes:
        """Raw export directory, where names and forwarder strings normally live."""
        return self.process.read(self.base + self.directory.VirtualAddress, self.directory.Size)

    def bytes_at(self, rva: int, size: int) -> bytes:
        if 0 <= (off := rva - self.directory.VirtualAddress) and off + size <= len(self.data): return self.data[off:off + size]
        return self.process.read(self.base + rva, size)

    def string_at(self, rva: int) -> str:
        """Return the NUL-terminated string at `rva`."""
        if 0 <= (off := rva - self.directory.VirtualAddress) < len(self.data) and (end := self.data.find(b'\0', off)) >= 0:
            return self.data[off:end].decode('utf-8', 'replace')
        return self.process.read_bytes_zero_trim(self.base + rva).decode('utf-8', 'replace')

    @property
    def name(self) -> str:
        return self.string_at(self.header.Name)

    def find(self, name: str) -> int:
        """Return the function index exported as `name`, or -1."""
        target = name.encode('utf-8') + b'\0'
        name_at = lambda rva: self.bytes_at(rva, min(len(target), self.image_end - self.base - rva))
        i = bisect.bisect_left(self.names, target, key=name_at)  # export names are sorted, same binary search as the loader
        return self.name_ordinals[i] if i < len(self.names) and name_at(self.names[i]) == target else -1

    def target(self, idx: int) -> int | str | None:
        """Return the address of function `idx`, its forwarder string, or None for an empty or out-of-range slot."""
        if not 0 <= idx < self.header.NumberOfFunctions or not (rva := self.functions[idx]): return None
        return self.string_at(rva) if self.directory.VirtualAddress <= rva < self.directory.VirtualAddress + self.directory.Size else self.base + rva

    def __iter__(self) -> typing.Iterator[Export]:
        """Yield one entry per exported name in name-table order, then the unnamed non-empty slots by ordinal."""
        named = set()
        for name_rva, idx in zip(self.names, self.name_ordinals):
            if idx < self.header.NumberOfFunctions:
                named.add(idx)
                yield self._export(self.string_at(name_rva), idx)
        for idx in range(self.header.NumberOfFunctions):
            if idx not in named and self.functions[idx]: yield self._export('', idx)

    def _export(self, name: str, idx: int) -> Export:
        target = self.target(idx)
        return Export(name, self.header.Base + idx, self.functions[idx], target if isinstance(target, int) else 0, target if isinstance(target, str) else '')


def read_exports(base: int) -> list[Export]:
    """Return every export of the image loaded at `base` in this process; [] on any failure, never raises."""
    try:
        return list(ExportTable(_self_process(), base))
    except Exception:
        return []


@functools.cache
def _self_process():
    from ..process import Process  # nylib.process imports this module
    return Process(winapi.GetCurrentProcessId(), winapi.GetCurrentProcess())  # ReadProcessMemory path: a bad address raises instead of faulting


__all__ = ['Export', 'ExportTable', 'read_exports']
