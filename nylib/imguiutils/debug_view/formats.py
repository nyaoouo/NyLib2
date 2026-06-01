"""Address / memory-cell formatters and the AddressFormat / MemFormat enums.

Pure Python; no ImGui or capstone dependency so this module can be
imported and tested without the native pyimgui pyd present.
"""
from __future__ import annotations

import dataclasses
import enum
import re
import typing


class AddressFormat(enum.Enum):
    HEX = "hex"                       # 0x0000000000001234
    MODULE_OFFSET = "module+offset"   # mymodule.dll+0x1234 (fallback to HEX)


class MemCellSize(enum.IntEnum):
    U8 = 1
    U16 = 2
    U32 = 4
    U64 = 8


Radix = typing.Literal["hex", "dec"]


@dataclasses.dataclass(frozen=True)
class MemFormat:
    cell: MemCellSize = MemCellSize.U8
    radix: Radix = "hex"   # v0: cells are always unsigned

    def cell_text_width(self) -> int:
        """Character count for one cell label (hex digits, fixed)."""
        return self.cell * 2 if self.radix == "hex" else len(str((1 << (self.cell * 8)) - 1))


def format_address(addr: int, fmt: AddressFormat,
                    proc: typing.Any = None,
                    *, resolver: typing.Any = None) -> str:
    """Format `addr` per `fmt`. When `resolver` is provided (a
    ModuleResolver), module + export lookups go through its O(log N)
    cached snapshot instead of a fresh LDR walk per call.

    MODULE_OFFSET tries the richer `module:export+0xOFF` form first;
    when the address isn't covered by any export (or the offset cap
    fires) it falls back to plain `module+0xOFF`; when no module
    contains the address at all it falls back to raw hex."""
    if fmt is AddressFormat.MODULE_OFFSET:
        if resolver is not None:
            try:
                ex = resolver.lookup_export(int(addr))
            except Exception:
                ex = None
            if ex is not None:
                mod, sym, off = ex
                if off == 0:
                    return f"{mod}:{sym}"
                return f"{mod}:{sym}+0x{int(off):X}"
        name, off = _try_lookup_module(addr, proc, resolver)
        if name is None:
            return _hex_addr(addr)
        return f"{name}+0x{off:X}"
    return _hex_addr(addr)


def _try_lookup_module(addr: int, proc, resolver) -> tuple[str | None, int]:
    """Best-effort module lookup. Prefers the resolver when given; falls
    back to a fresh enum_ldr_data walk. Always returns (name|None, off)
    so callers can branch on whether a module was found."""
    if resolver is not None:
        try:
            result = resolver.lookup(int(addr))
        except Exception:
            result = None
        if result is not None:
            return result[0], int(result[1])
        return None, int(addr)
    try:
        return _lookup_module(addr, proc)
    except Exception:
        return None, int(addr)


def _hex_addr(addr: int) -> str:
    """Hex render for display. Uses natural width (no leading-zero pad).

    Common Win64 user-space addresses (`0x7FF74EA01D10`) and module bases
    (`0x140001000`) render compactly without the dead `0x0000` prefix.
    The clipboard "Copy address (hex)" path keeps the fully padded
    16-digit form for unambiguous round-tripping."""
    return f"0x{addr & 0xFFFFFFFFFFFFFFFF:X}"


def _lookup_module(addr: int, proc) -> tuple[str | None, int]:
    """Return (module_name, offset_within_module) or (None, addr).

    Performs a fresh LDR walk on `proc` (defaults to Process.current).
    Callers that need this for every render frame should cache externally.
    """
    if proc is None:
        from nylib.process import Process
        proc = Process.current
    addr = int(addr)
    for entry in proc.enum_ldr_data():
        base = int(entry.DllBase or 0)
        size = int(entry.SizeOfImage or 0)
        if base <= addr < base + size:
            try:
                name = entry.BaseDllName.remote_value(proc)
            except Exception:
                name = None
            return name, addr - base
    return None, addr


def format_cell(value: int, fmt: MemFormat) -> str:
    """Render a single hex/dec cell. Value is treated as unsigned."""
    mask = (1 << (fmt.cell * 8)) - 1
    value &= mask
    if fmt.radix == "hex":
        return f"{value:0{fmt.cell * 2}X}"
    return f"{value}"


def snap_pow2_in(candidates: set[int], raw: int) -> int:
    """Return the largest element of `candidates` that is <= raw.
    If `raw` is below the smallest candidate, return the smallest.
    If `raw` is above the largest candidate, return the largest."""
    if not candidates:
        raise ValueError("candidates must be non-empty")
    ordered = sorted(candidates)
    if raw <= ordered[0]:
        return ordered[0]
    pick = ordered[0]
    for c in ordered:
        if c <= raw:
            pick = c
        else:
            break
    return pick


_HEX_CHARS = set("0123456789abcdefABCDEF")
_OP_SPLIT_RE = re.compile(r"\s*([+\-])\s*")


def _is_hex_literal(token: str) -> bool:
    """True if `token` is a hex literal (with or without 0x prefix)."""
    if not token:
        return False
    if token[:2].lower() == "0x":
        rest = token[2:]
        return bool(rest) and all(c in _HEX_CHARS for c in rest)
    return all(c in _HEX_CHARS for c in token)


def _resolve_module_base(name: str, proc: typing.Any,
                          resolver: typing.Any = None) -> int | None:
    """Return the DllBase of the loaded module matching `name` (case
    insensitive), or None when no such module is loaded. Prefers
    `resolver` when given; falls back to a fresh enum_ldr_data walk."""
    if resolver is not None:
        try:
            return resolver.base_of(name)
        except Exception:
            return None
    if proc is None:
        from nylib.process import Process
        proc = Process.current
    target = name.lower()
    for entry in proc.enum_ldr_data():
        try:
            ent_name = entry.BaseDllName.remote_value(proc)
        except Exception:
            continue
        if ent_name.lower() == target:
            return int(entry.DllBase or 0)
    return None


def _parse_term(token: str, proc: typing.Any,
                 resolver: typing.Any = None) -> int | None:
    """Parse one term: a hex literal, `module:export`, or a plain
    module name."""
    if not token:
        return None
    if _is_hex_literal(token):
        try:
            return int(token, 16)
        except ValueError:
            return None
    # module:export form -> exported function address.
    if ":" in token:
        mod, _, sym = token.partition(":")
        mod = mod.strip()
        sym = sym.strip()
        if not mod or not sym:
            return None
        return _resolve_export(mod, sym, proc, resolver)
    # Otherwise: bare module name -> base.
    return _resolve_module_base(token, proc, resolver)


def _resolve_export(mod_name: str, sym_name: str,
                     proc: typing.Any,
                     resolver: typing.Any = None) -> int | None:
    """Resolve `module:export` to an absolute address. Prefers the
    resolver's cached export table; falls back to a live LDR + PE
    export walk for the resolver-less code path (slow but functional
    for one-off goto-box parses)."""
    if resolver is not None:
        try:
            return resolver.export_addr(mod_name, sym_name)
        except Exception:
            return None
    base = _resolve_module_base(mod_name, proc, None)
    if base is None:
        return None
    try:
        from nylib.winutils.pe_exports import read_exports
    except Exception:
        return None
    target = sym_name.lower()
    for e in read_exports(base):
        name = getattr(e, "name", "") or ""
        if name and name.lower() == target:
            rva = int(getattr(e, "rva", 0) or 0)
            if rva > 0:
                return base + rva
    return None


def parse_address(text: str, proc: typing.Any = None,
                   *, resolver: typing.Any = None) -> int | None:
    """Parse `text` as an address expression.

    Supported forms:
        0x1234                          - hex literal (with prefix)
        1234                            - plain numbers are always hex
        kernel32.dll                    - module name -> DllBase
        kernel32.dll + 0x1234           - module + offset (spaces OK)
        kernel32.dll+0x1234             - module + offset (no spaces)
        kernel32.dll + 0x1234 - 0x100   - chained + / - across terms
        0x140000000 + 0x100 - 0x4       - chained + / - on hex terms

    Each term is independently a hex literal or a loaded-module name;
    the result of all + / - operations is masked to 64 bits so subtractive
    underflow wraps as ordinary pointer arithmetic. Returns None when a
    term fails to parse or a referenced module is not loaded.
    """
    if not text:
        return None
    s = text.strip()
    if not s:
        return None
    # Split on + / -, keeping the operators interleaved with the terms.
    # Leading operator is rejected (no implicit zero) so a typo like
    # "+0x100" doesn't silently parse.
    parts = _OP_SPLIT_RE.split(s)
    if not parts or not parts[0].strip():
        return None
    result = _parse_term(parts[0].strip(), proc, resolver)
    if result is None:
        return None
    i = 1
    while i + 1 < len(parts):
        op = parts[i]
        operand = parts[i + 1].strip()
        val = _parse_term(operand, proc, resolver)
        if val is None:
            return None
        if op == "+":
            result += val
        else:
            result -= val
        i += 2
    if i != len(parts):
        # Trailing op with no operand, e.g. "0x100 +".
        return None
    return result & 0xFFFFFFFFFFFFFFFF


__all__ = [
    "AddressFormat",
    "MemCellSize",
    "MemFormat",
    "format_address",
    "format_cell",
    "snap_pow2_in",
    "parse_address",
]
