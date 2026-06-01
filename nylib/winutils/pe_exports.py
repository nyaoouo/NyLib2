"""In-memory PE export-table walker.

Reads the export table from a loaded module in memory using
`ctypes.string_at` + `struct.unpack_from` — the same pattern as
`pe_unmap.py`. No external dependencies beyond ctypes/struct.

Usage::

    from nylib.winutils.pe_exports import read_exports

    base = ... # module base address (e.g. from LDR data)
    for exp in read_exports(base):
        print(exp.ordinal, exp.name, hex(exp.address), exp.forwarder)
"""
from __future__ import annotations

import ctypes
import dataclasses
import struct

# PE constants
_IMAGE_DOS_SIGNATURE = 0x5A4D       # 'MZ'
_IMAGE_NT_SIGNATURE = 0x00004550    # 'PE\0\0'
_IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20B

# Safety caps
_MAX_NAME_LEN = 256
_MAX_FORWARDER_LEN = 256
_MAX_EXPORTS = 65536  # sanity cap — no real DLL exports more than this


@dataclasses.dataclass(frozen=True)
class Export:
    """A single entry from an in-memory PE export table.

    Attributes:
        name:      Symbol name; empty string for ordinal-only entries.
        ordinal:   1-based ordinal (Base-adjusted).
        rva:       Function RVA within the module image.
        address:   Absolute address = module_base + rva.
                   0 if rva == 0.
        forwarder: Non-empty when this export is a forwarder string
                   (e.g. ``"NTDLL.NtQueryInformationProcess"``). When
                   set, ``address`` is 0 (the RVA points to the string,
                   not executable code).
    """
    name: str
    ordinal: int
    rva: int
    address: int
    forwarder: str


def _safe_read(addr: int, n: int) -> bytes | None:
    """Read `n` bytes from `addr` via ctypes. Returns None on any failure."""
    if addr <= 0 or n <= 0:
        return None
    try:
        return ctypes.string_at(addr, n)
    except Exception:
        return None


def _read_cstring(addr: int, max_len: int = _MAX_NAME_LEN) -> str:
    """Read a NUL-terminated ASCII/latin-1 string from `addr`."""
    data = _safe_read(addr, max_len)
    if data is None:
        return ""
    nul = data.find(b"\x00")
    if nul >= 0:
        data = data[:nul]
    try:
        return data.decode("ascii")
    except Exception:
        return data.decode("latin-1", errors="replace")


def read_exports(base: int) -> list[Export]:
    """Walk the PE export table at `base` and return all exports.

    `base` must be the base address of a loaded 64-bit PE image.
    Returns an empty list on any failure (bad magic, no export table,
    unmapped memory, etc.). Never raises.
    """
    try:
        return _read_exports_impl(base)
    except Exception:
        return []


def _read_exports_impl(base: int) -> list[Export]:
    # --- DOS header ---
    dos = _safe_read(base, 0x40)
    if dos is None or len(dos) < 0x40:
        return []
    if struct.unpack_from("<H", dos, 0)[0] != _IMAGE_DOS_SIGNATURE:
        return []
    e_lfanew = struct.unpack_from("<I", dos, 0x3C)[0]
    if e_lfanew <= 0:
        return []

    # --- NT headers (read enough for the full optional header) ---
    # PE sig(4) + FileHeader(20) + OptionalHeader64(240) = 0x108 bytes
    nt = _safe_read(base + e_lfanew, 0x108)
    if nt is None or len(nt) < 0x108:
        return []
    if struct.unpack_from("<I", nt, 0)[0] != _IMAGE_NT_SIGNATURE:
        return []

    # OptionalHeader starts at offset 0x18 within NT headers
    opt_offset = 0x18
    opt_magic = struct.unpack_from("<H", nt, opt_offset)[0]
    if opt_magic != _IMAGE_NT_OPTIONAL_HDR64_MAGIC:
        return []

    # DataDirectory[0] = Export Table; located at OptionalHeader+0x70
    # (IMAGE_OPTIONAL_HEADER64: 0x70 = offsetof DataDirectory[0])
    dd_offset = opt_offset + 0x70
    export_va, export_size = struct.unpack_from("<II", nt, dd_offset)
    if export_va == 0 or export_size == 0:
        return []

    export_range_start = export_va
    export_range_end = export_va + export_size

    # --- IMAGE_EXPORT_DIRECTORY (40 bytes) ---
    expdir = _safe_read(base + export_va, 40)
    if expdir is None or len(expdir) < 40:
        return []

    # +0x10 = Base (ordinal base)
    # +0x14 = NumberOfFunctions
    # +0x18 = NumberOfNames
    # +0x1C = AddressOfFunctions (RVA)
    # +0x20 = AddressOfNames (RVA)
    # +0x24 = AddressOfNameOrdinals (RVA)
    ordinal_base = struct.unpack_from("<I", expdir, 0x10)[0]
    num_functions = struct.unpack_from("<I", expdir, 0x14)[0]
    num_names = struct.unpack_from("<I", expdir, 0x18)[0]
    addr_of_functions = struct.unpack_from("<I", expdir, 0x1C)[0]
    addr_of_names = struct.unpack_from("<I", expdir, 0x20)[0]
    addr_of_name_ordinals = struct.unpack_from("<I", expdir, 0x24)[0]

    # Sanity caps
    if num_functions == 0 or num_functions > _MAX_EXPORTS:
        return []
    num_names = min(num_names, num_functions, _MAX_EXPORTS)

    # --- Read the three tables ---
    func_table_bytes = _safe_read(base + addr_of_functions,
                                   num_functions * 4)
    if func_table_bytes is None:
        return []
    func_table = list(
        struct.unpack_from(f"<{num_functions}I", func_table_bytes))

    name_table: list[int] = []
    ordinal_table: list[int] = []
    if num_names > 0:
        name_bytes = _safe_read(base + addr_of_names, num_names * 4)
        ord_bytes = _safe_read(base + addr_of_name_ordinals, num_names * 2)
        if name_bytes and ord_bytes:
            name_table = list(
                struct.unpack_from(f"<{num_names}I", name_bytes))
            ordinal_table = list(
                struct.unpack_from(f"<{num_names}H", ord_bytes))

    # --- Build a set of 0-based ordinal indices that have a name ---
    named_indices: set[int] = set(ordinal_table[:len(name_table)])

    results: list[Export] = []

    # Named exports
    for i in range(len(name_table)):
        name_rva = name_table[i]
        idx = ordinal_table[i]          # 0-based index into AddressOfFunctions
        one_based_ordinal = ordinal_base + idx

        if idx >= num_functions:
            continue  # corrupt table entry

        name = _read_cstring(base + name_rva)
        func_rva = func_table[idx]

        # Check for forwarder: function RVA falls within export directory
        if export_range_start <= func_rva < export_range_end:
            forwarder = _read_cstring(base + func_rva, _MAX_FORWARDER_LEN)
            results.append(Export(
                name=name,
                ordinal=one_based_ordinal,
                rva=func_rva,
                address=0,
                forwarder=forwarder,
            ))
        else:
            address = (base + func_rva) if func_rva != 0 else 0
            results.append(Export(
                name=name,
                ordinal=one_based_ordinal,
                rva=func_rva,
                address=address,
                forwarder="",
            ))

    # Ordinal-only exports (no name)
    for idx in range(num_functions):
        if idx in named_indices:
            continue  # already handled above
        func_rva = func_table[idx]
        if func_rva == 0:
            continue  # empty slot
        one_based_ordinal = ordinal_base + idx

        if export_range_start <= func_rva < export_range_end:
            forwarder = _read_cstring(base + func_rva, _MAX_FORWARDER_LEN)
            results.append(Export(
                name="",
                ordinal=one_based_ordinal,
                rva=func_rva,
                address=0,
                forwarder=forwarder,
            ))
        else:
            address = base + func_rva
            results.append(Export(
                name="",
                ordinal=one_based_ordinal,
                rva=func_rva,
                address=address,
                forwarder="",
            ))

    return results


__all__ = ["Export", "read_exports"]
