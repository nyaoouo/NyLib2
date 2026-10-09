"""CodeView record encoding: numeric leaves, type/symbol records, base types."""
import struct

LF_MODIFIER, LF_POINTER, LF_PROCEDURE = 0x1001, 0x1002, 0x1008
LF_ARGLIST, LF_FIELDLIST, LF_BITFIELD, LF_INDEX = 0x1201, 0x1203, 0x1205, 0x1404
LF_BCLASS, LF_ENUMERATE, LF_ARRAY = 0x1400, 0x1502, 0x1503
LF_CLASS, LF_STRUCTURE, LF_UNION, LF_ENUM, LF_MEMBER = 0x1504, 0x1505, 0x1506, 0x1507, 0x150D
LF_INTERFACE = 0x1519
LF_UDT_SRC_LINE, LF_UDT_MOD_SRC_LINE = 0x1606, 0x1607

S_END, S_OBJNAME, S_CONSTANT, S_UDT = 0x0006, 0x1101, 0x1107, 0x1108
S_LDATA32, S_GDATA32, S_PUB32, S_LPROC32, S_GPROC32 = 0x110C, 0x110D, 0x110E, 0x110F, 0x1110
S_PROCREF, S_LPROCREF, S_COMPILE3 = 0x1125, 0x1127, 0x113C

# UDT property-field flags (LF_CLASS/LF_STRUCTURE/LF_UNION/LF_ENUM/LF_INTERFACE)
CO_FWDREF, CO_SCOPED, CO_HASUNIQUENAME = 0x80, 0x100, 0x200

# numeric-leaf tag -> trailing byte count (tag itself is 2 bytes, not counted)
NUMERIC_TAG_LEN = {0x8000: 1, 0x8001: 2, 0x8002: 2, 0x8003: 4, 0x8004: 4, 0x8009: 8, 0x800A: 8}

_MAX_RECORD_LEN = 0xFF00


def numeric_len(record: bytes, off: int) -> int:
    """Byte length of the numeric leaf at ``off`` (tag incl. when tagged)."""
    v = struct.unpack_from('<H', record, off)[0]
    return 2 if v < 0x8000 else 2 + NUMERIC_TAG_LEN[v]


def _align4(n: int) -> int:
    return (n + 3) & ~3


def cstr(s: str) -> bytes:
    """Encode a NUL-terminated UTF-8 string, as used by every CodeView name field."""
    return s.encode('utf-8') + b'\0'


def numeric(v: int) -> bytes:
    """Encode a CodeView numeric leaf (inline u16 or a tagged LF_* value).

    ``ValueError`` outside ``-2**63..2**64-1``.
    """
    if v >= 0:
        if v > 0xFFFFFFFFFFFFFFFF:
            raise ValueError(f'numeric leaf out of range: {v:#x}')
        if v < 0x8000:
            return struct.pack('<H', v)
        if v <= 0xFFFF:
            return struct.pack('<HH', 0x8002, v)  # LF_USHORT
        if v <= 0xFFFFFFFF:
            return struct.pack('<HI', 0x8004, v)  # LF_ULONG
        return struct.pack('<HQ', 0x800A, v)  # LF_UQUADWORD
    if v < -0x8000000000000000:
        raise ValueError(f'numeric leaf out of range: {v:#x}')
    if v >= -0x80:
        return struct.pack('<Hb', 0x8000, v)  # LF_CHAR
    if v >= -0x8000:
        return struct.pack('<Hh', 0x8001, v)  # LF_SHORT
    if v >= -0x80000000:
        return struct.pack('<Hi', 0x8003, v)  # LF_LONG
    return struct.pack('<Hq', 0x8009, v)  # LF_QUADWORD


def lf_pad(b: bytes, prefix_len: int = 0) -> bytes:
    """Pad ``b`` to a 4-byte multiple with descending LF_PAD bytes (0xF3 0xF2 0xF1)."""
    pad = (-(len(b) + prefix_len)) % 4
    return b + bytes(0xF0 + pad - i for i in range(pad))


def _check_record_len(body: bytes) -> None:
    if len(body) > _MAX_RECORD_LEN:
        raise ValueError(f'record length {len(body):#x} exceeds {_MAX_RECORD_LEN:#x}')


def type_record(leaf: int, payload: bytes) -> bytes:
    """Encode a top-level TPI/IPI record: u16 length, leaf, payload, LF_PAD."""
    body = lf_pad(struct.pack('<H', leaf) + payload, prefix_len=2)
    _check_record_len(body)
    return struct.pack('<H', len(body)) + body


def symbol_record(kind: int, payload: bytes) -> bytes:
    """Encode a symbol record: u16 length, kind, payload, zero padding to 4 bytes."""
    body = struct.pack('<H', kind) + payload
    body += b'\0' * (_align4(len(body) + 2) - 2 - len(body))
    _check_record_len(body)
    return struct.pack('<H', len(body)) + body


def fl_member(name: str, ti: int, offset: int, access: int = 3) -> bytes:
    """LF_MEMBER field-list sub-record."""
    return lf_pad(struct.pack('<HHI', LF_MEMBER, access, ti) + numeric(offset) + cstr(name))


def fl_bclass(ti: int, offset: int, access: int = 3) -> bytes:
    """LF_BCLASS field-list sub-record (non-virtual base class)."""
    return lf_pad(struct.pack('<HHI', LF_BCLASS, access, ti) + numeric(offset))


def fl_enumerate(name: str, value: int, access: int = 3) -> bytes:
    """LF_ENUMERATE field-list sub-record."""
    return lf_pad(struct.pack('<HH', LF_ENUMERATE, access) + numeric(value) + cstr(name))


# name -> (simple_ti, size, dia_bt, dia_size, enum_range | None)
BASE_TYPES = {
    'void': (0x0003, 0, 1, 0, None),
    'HRESULT': (0x0008, 4, 31, 4, None),
    'signed char': (0x0010, 1, 6, 1, (-2 ** 7, 2 ** 7 - 1)),
    'unsigned char': (0x0020, 1, 7, 1, (0, 2 ** 8 - 1)),
    'char': (0x0070, 1, 2, 1, (-2 ** 7, 2 ** 7 - 1)),
    'wchar_t': (0x0071, 2, 3, 2, (0, 2 ** 16 - 1)),
    'char16_t': (0x007A, 2, 32, 2, (0, 2 ** 16 - 1)),
    'char32_t': (0x007B, 4, 33, 4, (0, 2 ** 32 - 1)),
    'char8_t': (0x007C, 1, 34, 1, (0, 2 ** 8 - 1)),
    'short': (0x0011, 2, 6, 2, (-2 ** 15, 2 ** 15 - 1)),
    'unsigned short': (0x0021, 2, 7, 2, (0, 2 ** 16 - 1)),
    'long': (0x0012, 4, 13, 4, (-2 ** 31, 2 ** 31 - 1)),
    'unsigned long': (0x0022, 4, 14, 4, (0, 2 ** 32 - 1)),
    'int': (0x0074, 4, 6, 4, (-2 ** 31, 2 ** 31 - 1)),
    'unsigned int': (0x0075, 4, 7, 4, (0, 2 ** 32 - 1)),
    '__int64': (0x0013, 8, 6, 8, (-2 ** 63, 2 ** 63 - 1)),
    'unsigned __int64': (0x0023, 8, 7, 8, (0, 2 ** 64 - 1)),
    'float': (0x0040, 4, 8, 4, None),
    'double': (0x0041, 8, 8, 8, None),
    'long double': (0x0042, 10, 8, 10, None),
    'bool': (0x0030, 1, 10, 1, (0, 2 ** 8 - 1)),
    '<bt6:16>': (0x0078, 16, 6, 16, None),
    '<bt7:16>': (0x0079, 16, 7, 16, None),
    '<bt8:2>': (0x0046, 2, 8, 2, None),
    '<bt8:16>': (0x0043, 16, 8, 16, None),
    '<bt10:2>': (0x0031, 2, 10, 2, (0, 2 ** 16 - 1)),
    '<bt10:4>': (0x0032, 4, 10, 4, (0, 2 ** 32 - 1)),
    '<bt10:8>': (0x0033, 8, 10, 8, (0, 2 ** 64 - 1)),
}

# (dia_bt, dia_size) -> name; total over BASE_TYPES, one name per DIA-observable pair.
BASE_TYPES_BY_DIA = {(bt, size): name for name, (_ti, _sz, bt, size, _rng) in BASE_TYPES.items()}

# integral but not enum-capable (128-bit; enum_range is None for these too, see "Base types")
_INTEGRAL_NOT_ENUM_CAPABLE = frozenset(('<bt6:16>', '<bt7:16>'))


def enum_range(name: str) -> tuple[int, int] | None:
    """Storage range ``(lo, hi)`` of an enum-capable base type name, else ``None``."""
    if not isinstance(name, str):
        return None
    entry = BASE_TYPES.get(name)
    return entry[4] if entry is not None else None


def is_integral(name: str) -> bool:
    """True for every integral base type name, incl. the non-enum-capable 128-bit ones."""
    if not isinstance(name, str):
        return False
    return enum_range(name) is not None or name in _INTEGRAL_NOT_ENUM_CAPABLE
