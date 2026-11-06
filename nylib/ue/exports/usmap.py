"""Dumper-7 usmap writer: literal port of MappingGenerator.cpp @ ea0dab3, streamed over one pass
of `snapshot.types()`.

Compression 0 only; record order is the snapshot's path order, not Dumper-7's launch order.
"""
import contextvars
import logging
import os
import re
import struct

from ..flags import EPropertyFlags
from ..model import PropType
from ..names import make_name_valid, strip_path, valid_file_name

logger = logging.getLogger('nylib.ue.exports.usmap')
export_warnings: contextvars.ContextVar[list | None] = contextvars.ContextVar('usmap_export_warnings', default=None)  # dump()'s warning list

_MAGIC = 0x30C4
_VERSION = 4  # ExplicitEnumValues
_EDITOR_ONLY = int(EPropertyFlags.EditorOnly)
_ILLEGAL_MEMBER_NAMES = frozenset({
    'IN', 'OUT', 'TRUE', 'FALSE', 'DELETE', 'PF_MAX', 'SW_MAX', 'MM_MAX', 'SIZE_MAX', 'RELATIVE',
    'TRANSPARENT', 'NO_ERROR', 'EVENT_MAX', 'IGNORE', 'short', 'long', 'int', 'signed', 'unsigned',
})
_TYPE_CODES = {
    'ByteProperty': 0, 'BoolProperty': 1, 'IntProperty': 2, 'FloatProperty': 3,
    'ObjectProperty': 4, 'ClassProperty': 4, 'NameProperty': 5, 'DelegateProperty': 6,
    'DoubleProperty': 7, 'ArrayProperty': 8, 'StructProperty': 9, 'StrProperty': 10,
    'TextProperty': 11, 'InterfaceProperty': 12,
    'MulticastInlineDelegateProperty': 13, 'MulticastSparseDelegateProperty': 13,
    'WeakObjectProperty': 14, 'LazyObjectProperty': 15,
    'SoftObjectProperty': 17, 'SoftClassProperty': 17,
    'UInt64Property': 18, 'UInt32Property': 19, 'UInt16Property': 20,
    'Int64Property': 21, 'Int16Property': 22, 'Int8Property': 23,
    'MapProperty': 24, 'SetProperty': 25, 'EnumProperty': 26, 'FieldPathProperty': 27,
    'OptionalProperty': 28,
}
_UNKNOWN_CODE = 0xFF
_LAST_SEGMENT_RE = re.compile(r'[^.:]*$')


def _check_out_dir(out_dir):
    if not isinstance(out_dir, (str, os.PathLike)):
        raise TypeError(f'out_dir must be str or os.PathLike, got {type(out_dir).__name__}')


def _referenced_name(path: str) -> str:
    """A referenced type's name: `strip_path` of `path`'s last segment after its last '.' or ':' (GetName())."""
    return strip_path(_LAST_SEGMENT_RE.search(path).group())


def _property_bit(p) -> int:
    bit = p.type.bit
    return bit if bit is not None else 0xFF


def _enum_member_name(raw: str, first_c_by_name: dict) -> str:
    """EnumManager @ ea0dab3: strip a `Namespace::` prefix, then suffix a repeated/illegal name."""
    n = make_name_valid(raw[raw.rfind(':') + 1:])
    first_c = first_c_by_name.get(n)
    base = 0 if first_c is None else 1 + first_c
    c = base + (1 if n in _ILLEGAL_MEMBER_NAMES else 0)
    if n not in first_c_by_name:
        first_c_by_name[n] = c
    return n if c == 0 else f'{n}_{c - 1}'


class _Writer:
    """Holds the name table (deduplicated, first-use order) and the missing-reference count/sample."""

    def __init__(self):
        self.names: dict[str, int] = {}
        self.name_buf = bytearray()
        self.missing_count = 0
        self.missing_sample = None

    def name_index(self, name: str, record_path: str) -> int:
        idx = self.names.get(name)
        if idx is not None:
            return idx
        nb = name.encode('utf-8')
        if len(nb) > 0xFFFF:
            raise ValueError(f'name too long ({len(nb)} bytes) for record {record_path!r}: {name!r}')
        idx = len(self.names)
        self.names[name] = idx
        self.name_buf += struct.pack('<H', len(nb)) + nb
        return idx

    def note_missing(self, record_path: str, prop_name: str) -> None:
        self.missing_count += 1
        if self.missing_sample is None:
            self.missing_sample = f'{record_path}.{prop_name}'


def _encode_type(pt: PropType | None, w: _Writer, record_path: str, prop_name: str) -> bytes:
    if pt is None:
        return bytes((_UNKNOWN_CODE,))
    if pt.kind == 'ByteProperty' and pt.enum is not None:
        idx = w.name_index(_referenced_name(pt.enum), record_path)
        return bytes((26, 0)) + struct.pack('<i', idx)
    code = _TYPE_CODES.get(pt.kind)
    if code is None:
        return bytes((_UNKNOWN_CODE,))
    if pt.kind == 'ArrayProperty':
        return bytes((code,)) + _encode_type(pt.inner, w, record_path, prop_name)
    if pt.kind == 'SetProperty':
        return bytes((code,)) + _encode_type(pt.element, w, record_path, prop_name)
    if pt.kind == 'OptionalProperty':
        return bytes((code,)) + _encode_type(pt.value, w, record_path, prop_name)
    if pt.kind == 'MapProperty':
        return (bytes((code,)) + _encode_type(pt.key, w, record_path, prop_name)
                + _encode_type(pt.value, w, record_path, prop_name))
    if pt.kind == 'StructProperty':
        if pt.struct is None:
            w.note_missing(record_path, prop_name)
            idx = w.name_index('None', record_path)
        else:
            idx = w.name_index(_referenced_name(pt.struct), record_path)
        return bytes((code,)) + struct.pack('<i', idx)
    if pt.kind == 'EnumProperty':
        underlying = _encode_type(pt.underlying, w, record_path, prop_name)
        if pt.enum is None:
            w.note_missing(record_path, prop_name)
            idx = w.name_index('None', record_path)
        else:
            idx = w.name_index(_referenced_name(pt.enum), record_path)
        return bytes((code,)) + underlying + struct.pack('<i', idx)
    return bytes((code,))


def _encode_enum(rec, w: _Writer) -> bytes:
    name_idx = w.name_index(strip_path(rec.name), rec.path)
    if len(rec.values) > 0xFFFF:
        raise ValueError(f'enum {rec.path!r} has more than 0xFFFF members')
    buf = bytearray(struct.pack('<iH', name_idx, len(rec.values) & 0xFFFF))
    first_c_by_name: dict = {}
    for raw, value in rec.values:
        if not (-(2 ** 63) <= value < 2 ** 64):
            raise ValueError(f'enum {rec.path!r} member {raw!r} value {value} is out of range')
        member_idx = w.name_index(_enum_member_name(raw, first_c_by_name), rec.path)
        buf += struct.pack('<Qi', value & 0xFFFFFFFFFFFFFFFF, member_idx)
    return bytes(buf)


def _encode_struct(rec, w: _Writer) -> bytes:
    name_idx = w.name_index(strip_path(rec.name), rec.path)
    super_idx = -1 if rec.super is None else w.name_index(_referenced_name(rec.super), rec.path)
    kept = sorted((p for p in rec.properties if not (p.flags & _EDITOR_ONLY)),
                  key=lambda p: (p.offset, _property_bit(p)))
    if len(kept) > 0xFFFF:
        raise ValueError(f'struct {rec.path!r} has more than 0xFFFF serializable properties')
    prop_buf = bytearray()
    index = 0
    for p in kept:
        pname_idx = w.name_index(p.name, rec.path)
        prop_buf += struct.pack('<HBi', index & 0xFFFF, p.array_dim & 0xFF, pname_idx)
        prop_buf += _encode_type(p.type, w, rec.path, p.name)
        index += p.array_dim
    buf = bytearray(struct.pack('<iiHH', name_idx, super_idx, index & 0xFFFF, len(kept) & 0xFFFF))
    buf += prop_buf
    return bytes(buf)


def write(snapshot, out_dir) -> str:
    """Write `<out_dir>/Mappings/<file stem>.usmap`: Dumper-7's name table, enums, structs and classes."""
    _check_out_dir(out_dir)
    w = _Writer()
    enum_buf = bytearray()
    struct_buf = bytearray()
    enum_count = 0
    struct_count = 0
    for rec in snapshot.types():
        if rec.kind == 'function':
            continue
        if rec.kind == 'enum':
            enum_buf += _encode_enum(rec, w)
            enum_count += 1
        else:
            struct_buf += _encode_struct(rec, w)
            struct_count += 1
    if w.missing_count:
        text = f"{w.missing_count} propert{'y' if w.missing_count == 1 else 'ies'} referenced a missing enum or struct (first: {w.missing_sample})"
        logger.warning('%s', text)
        if (sink := export_warnings.get()) is not None:
            sink.append(f'usmap: {text}')

    payload_len = 12 + len(w.name_buf) + len(enum_buf) + len(struct_buf)
    header = struct.pack('<HBiBII', _MAGIC, _VERSION, 0, 0, payload_len, payload_len)
    stem = valid_file_name(snapshot.stem) if snapshot.stem else 'unknown'
    path = os.path.join(os.fspath(out_dir), 'Mappings', f'{stem}.usmap')
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'wb') as f:
        f.write(header)
        f.write(struct.pack('<I', len(w.names)))
        f.write(w.name_buf)
        f.write(struct.pack('<I', enum_count))
        f.write(enum_buf)
        f.write(struct.pack('<I', struct_count))
        f.write(struct_buf)
    return os.path.abspath(path)
