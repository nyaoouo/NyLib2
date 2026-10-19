"""Parse Unreal Engine `.usmap` property mapping files (CUE4Parse semantics).

Versions 0-4 (EUsmapVersion.Initial..ExplicitEnumValues), compression methods None/Oodle/ZStandard;
Brotli is recognised and rejected. Every count, name length and declared decompressed size is checked
against what remains before anything is built from it.
"""
import hashlib
import importlib
import os
import struct

from nylib.utils import oodle
from nylib.utils.oodle import OodleError
from ..errors import InvalidMappingError
from ._hashes import _ascii_lower

_MAGIC = 0x30C4
_PACKAGE_VERSIONING = 1  # EUsmapVersion: adds the bHasVersioning byte and, if set, package/custom versions
_LONG_FNAME = 2  # name lengths become u16
_LARGE_ENUMS = 3  # enum member counts become u16
_EXPLICIT_ENUM_VALUES = 4  # EUsmapVersion.Latest; enum members carry an explicit u64 value
_LATEST_VERSION = _EXPLICIT_ENUM_VALUES

_METHOD_NONE, _METHOD_OODLE, _METHOD_BROTLI, _METHOD_ZSTD = 0, 1, 2, 3

_STRUCT_TYPE, _ENUM_TYPE, _MAP_TYPE = 9, 26, 24
_NESTED_TYPES = frozenset({8, 25, 28})  # ArrayProperty, SetProperty, OptionalProperty
_KNOWN_TYPES = frozenset(range(29)) | {0xFF}  # classic EPropertyType (0-28) plus the Unknown sentinel

_MAX_PAYLOAD = 64 << 20  # the decompressed payload cap
_MAX_FILE = 2 * _MAX_PAYLOAD + (64 << 10)
_MAX_TYPE_DEPTH = 32


class PropertyType:
    """One node of a property's type tree; `code` is the raw EPropertyType byte."""
    __slots__ = ('code', 'inner', 'value', 'struct_name', 'enum_name')

    def __init__(self, code, *, inner=None, value=None, struct_name=None, enum_name=None):
        self.code = code
        self.inner = inner
        self.value = value
        self.struct_name = struct_name
        self.enum_name = enum_name

    def __eq__(self, other):
        if not isinstance(other, PropertyType):
            return NotImplemented
        return ((self.code, self.inner, self.value, self.struct_name, self.enum_name) ==
                (other.code, other.inner, other.value, other.struct_name, other.enum_name))

    def __repr__(self):
        return f'PropertyType({self.code!r}, inner={self.inner!r}, value={self.value!r}, struct_name={self.struct_name!r}, enum_name={self.enum_name!r})'


class _Property:
    __slots__ = ('index', 'array_dim', 'name', 'type')

    def __init__(self, index, array_dim, name, type_):
        self.index = index
        self.array_dim = array_dim
        self.name = name
        self.type = type_


class StructRecord:
    """A parsed struct: its own property slots (serialized entries, not pre-expanded) and its super's name."""
    __slots__ = ('name', 'super', 'property_count', 'properties')

    def __init__(self, name, super_, property_count, properties):
        self.name = name
        self.super = super_
        self.property_count = property_count
        self.properties = properties  # tuple[_Property, ...]


class EnumRecord:
    __slots__ = ('name', 'members')

    def __init__(self, name, members):
        self.name = name
        self.members = members  # tuple[(value, member_name), ...]


class Mappings:
    """A parsed `.usmap` schema: struct and enum records, keyed per D1's duplicate rules."""

    def __init__(self, structs: dict, enums: dict, usmap_name: str):
        self._structs = structs  # dict[ascii_lower(name) -> StructRecord]; last-wins
        self._enums = enums  # dict[name -> EnumRecord]; first-wins
        self._usmap = usmap_name

    def record(self, name: str) -> 'StructRecord | None':
        return self._structs.get(_ascii_lower(name))

    def enum(self, name: str) -> 'EnumRecord | None':
        return self._enums.get(name)

    def lookup(self, struct_name: str, index: int):
        """(owner, name, type) for property `index` of `struct_name`, walking the super chain like CUE4Parse's
        Struct.TryGetValue (array dims expand); None when no such property exists anywhere in the chain.

        A struct named in the chain (including `struct_name` itself) with no record raises InvalidMappingError
        (reason 'no record'); `_zen.py` is expected to re-raise with the package context the 3.8 template needs.
        """
        seen = set()
        name = struct_name
        offset = index
        while True:
            key = _ascii_lower(name)
            if key in seen:
                raise InvalidMappingError(f'{self._usmap}: the super chain of {struct_name!r} cycles back to {name!r}',
                                           usmap=self._usmap, class_name=name, reason='super chain cycle')
            seen.add(key)
            rec = self._structs.get(key)
            if rec is None:
                raise InvalidMappingError(f'{self._usmap} has no record for {name!r}', usmap=self._usmap,
                                           class_name=name, property_index=offset, reason='no record')
            for p in rec.properties:
                if p.index <= offset < p.index + p.array_dim:
                    return rec.name, p.name, p.type
            if offset < rec.property_count or rec.super is None:
                return None
            offset -= rec.property_count
            name = rec.super


def parse(path) -> Mappings:
    """Read and validate a `.usmap` at `path`: versions 0-4, methods None/Oodle/ZStandard.

    `path` is assumed already validated and absolute (the caller applies the path rule).
    """
    return read(path)[0]


def read(path) -> tuple:
    """(Mappings, sha256 of the file's bytes) of the `.usmap` at `path`, from one bounded read; see parse()."""
    path = os.fspath(path)
    basename = os.path.basename(path)
    try:
        with open(path, 'rb') as f:
            size = os.fstat(f.fileno()).st_size
            if size > _MAX_FILE:
                raise _malformed(basename, f'file size {size} exceeds the {_MAX_FILE}-byte limit')
            raw = f.read(size)
    except FileNotFoundError as e:
        raise InvalidMappingError(f'mapping file {basename} not found', usmap=basename, reason='not found', path=path,
                                  errno=e.errno, winerror=getattr(e, 'winerror', None)) from None
    except OSError as e:
        raise InvalidMappingError(f'mapping file {basename} cannot be read', usmap=basename, reason='unreadable', path=path,
                                  errno=e.errno, winerror=getattr(e, 'winerror', None)) from None
    return _parse_bytes(raw, basename), hashlib.sha256(raw).digest()


def _malformed(basename: str, reason: str) -> InvalidMappingError:
    return InvalidMappingError(f'{basename} is not a valid .usmap: {reason}', usmap=basename, reason=reason)


def _parse_bytes(raw: bytes, basename: str) -> Mappings:
    n = len(raw)
    if n < 3:
        raise _malformed(basename, 'truncated header')
    magic, version = struct.unpack_from('<HB', raw, 0)
    if magic != _MAGIC:
        raise _malformed(basename, f'bad magic {magic:#x}')
    if version > _LATEST_VERSION:
        raise _malformed(basename, f'unsupported version {version}')

    pos = 3
    if version >= _PACKAGE_VERSIONING:
        if pos + 4 > n:
            raise _malformed(basename, 'truncated header')
        (has_versioning,) = struct.unpack_from('<i', raw, pos)
        pos += 4
        if has_versioning not in (0, 1):
            raise _malformed(basename, f'bad bool value {has_versioning}')
        if has_versioning:
            if pos + 12 > n:
                raise _malformed(basename, 'truncated header')
            pos += 8  # FPackageFileVersion (two int32); not needed to read the schema
            (cv_count,) = struct.unpack_from('<I', raw, pos)
            pos += 4
            if pos + 20 * cv_count + 4 > n:
                raise _malformed(basename, 'truncated header')
            pos += 20 * cv_count + 4  # FCustomVersion[] (16-byte guid + int32 version), then NetCL (uint32)

    if pos + 9 > n:
        raise _malformed(basename, 'truncated header')
    method, compressed_size, decompressed_size = struct.unpack_from('<BII', raw, pos)
    pos += 9
    if method == _METHOD_BROTLI:
        raise InvalidMappingError(f'{basename} is Brotli-compressed, which this nylib version does not read',
                                   usmap=basename, reason='Brotli')
    if method not in (_METHOD_NONE, _METHOD_OODLE, _METHOD_ZSTD):
        raise _malformed(basename, f'unknown compression method {method}')
    if decompressed_size > _MAX_PAYLOAD:
        raise _malformed(basename, f'decompressed size {decompressed_size} exceeds the {_MAX_PAYLOAD}-byte limit')
    if pos + compressed_size > n:
        raise _malformed(basename, 'truncated body')
    if pos + compressed_size < n:
        raise _malformed(basename, f'{n - pos - compressed_size} trailing bytes')
    body = raw[pos:pos + compressed_size]

    if method == _METHOD_NONE:
        if compressed_size != decompressed_size:
            raise _malformed(basename, 'stored (uncompressed) size does not match the declared decompressed size')
        payload = body
    elif method == _METHOD_OODLE:
        try:
            d = oodle.dll('core')
            getattr(d, 'OodleLZ_Decompress')
        except (OodleError, AttributeError) as e:
            raise InvalidMappingError(f'{basename} is Oodle-compressed, and Oodle is unavailable: {e}',
                                       usmap=basename, reason='Oodle unavailable') from e
        try:
            payload = oodle.decompress(body, decompressed_size)
        except OodleError as e:
            raise _malformed(basename, f'Oodle decompression failed: {e}') from e
    else:
        try:
            zstd = importlib.import_module('compression.zstd')
        except ImportError:
            raise InvalidMappingError(f'{basename} is ZStandard-compressed, which needs Python 3.14 (compression.zstd)',
                                       usmap=basename, reason='needs Python 3.14') from None
        dec = zstd.ZstdDecompressor()
        try:  # bounded by the declared size, so a small file cannot expand without limit
            payload = dec.decompress(body, max_length=decompressed_size)
            more = b'' if dec.eof else dec.decompress(b'', max_length=1)
        except (zstd.ZstdError, MemoryError) as e:
            raise _malformed(basename, f'ZStandard decompression failed: {e}') from e
        if more:
            raise _malformed(basename, f'ZStandard decompressed to more than {decompressed_size} bytes, expected {decompressed_size}')
        if len(payload) != decompressed_size or not dec.eof:
            raise _malformed(basename, f'ZStandard decompressed to {len(payload)} bytes, expected {decompressed_size}')
        if dec.unused_data:
            raise _malformed(basename, f'ZStandard data continues after the declared {decompressed_size} bytes')

    try:
        structs, enums = _parse_payload(payload, version)
    except (ValueError, IndexError, struct.error, UnicodeDecodeError, RecursionError, MemoryError) as e:
        raise _malformed(basename, str(e)) from None
    return Mappings(structs, enums, basename)


def _parse_payload(payload, version: int):
    n = len(payload)
    pos = 0

    def take(size):
        nonlocal pos
        if pos + size > n:
            raise ValueError(f'truncated payload at offset {pos}')
        chunk = payload[pos:pos + size]
        pos += size
        return chunk

    def u8():
        return take(1)[0]

    def u16():
        return struct.unpack('<H', take(2))[0]

    def u32():
        return struct.unpack('<I', take(4))[0]

    def u64():
        return struct.unpack('<Q', take(8))[0]

    def i32():
        return struct.unpack('<i', take(4))[0]

    def name_index(*, allow_neg1=False):
        start = pos
        idx = i32()
        if allow_neg1 and idx == -1:
            return None
        if not (0 <= idx < len(names)):
            raise ValueError(f'name index {idx} out of range at offset {start}')
        return idx

    def read_type(depth):
        if depth > _MAX_TYPE_DEPTH:
            raise ValueError('type nesting too deep')
        start = pos
        code = u8()
        if code not in _KNOWN_TYPES:
            raise ValueError(f'bad type code {code} at offset {start}')
        if code == _STRUCT_TYPE:
            idx = name_index(allow_neg1=True)
            return PropertyType(code, struct_name=None if idx is None else names[idx])
        if code == _ENUM_TYPE:
            inner = read_type(depth + 1)
            idx = name_index(allow_neg1=True)
            return PropertyType(code, inner=inner, enum_name=None if idx is None else names[idx])
        if code in _NESTED_TYPES:
            return PropertyType(code, inner=read_type(depth + 1))
        if code == _MAP_TYPE:
            inner = read_type(depth + 1)
            value = read_type(depth + 1)
            return PropertyType(code, inner=inner, value=value)
        return PropertyType(code)

    name_count = u32()
    if name_count > n - pos:
        raise ValueError(f'name count {name_count} exceeds the payload')
    names = []
    for _ in range(name_count):
        length = u16() if version >= _LONG_FNAME else u8()
        names.append(take(length).decode('utf-8', 'surrogateescape'))

    enum_count = u32()
    if enum_count > n - pos:
        raise ValueError(f'enum count {enum_count} exceeds the payload')
    enums = {}
    for _ in range(enum_count):
        ename = names[name_index()]
        member_count = u16() if version >= _LARGE_ENUMS else u8()
        if member_count > n - pos:
            raise ValueError(f'enum member count {member_count} exceeds the payload')
        members = []
        for j in range(member_count):
            value = u64() if version >= _EXPLICIT_ENUM_VALUES else j
            members.append((value, names[name_index()]))
        enums.setdefault(ename, EnumRecord(ename, tuple(members)))  # first-wins

    struct_count = u32()
    if struct_count > n - pos:
        raise ValueError(f'struct count {struct_count} exceeds the payload')
    structs = {}
    for _ in range(struct_count):
        sname = names[name_index()]
        super_idx = name_index(allow_neg1=True)
        super_name = None if super_idx is None else names[super_idx]
        property_count = u16()
        serializable_count = u16()
        if serializable_count > n - pos:
            raise ValueError(f'property count {serializable_count} exceeds the payload')
        props = []
        for _ in range(serializable_count):
            p_index = u16()
            array_dim = u8()
            pname = names[name_index()]
            props.append(_Property(p_index, array_dim, pname, read_type(0)))
        structs[_ascii_lower(sname)] = StructRecord(sname, super_name, property_count, tuple(props))  # last-wins

    if pos != n:
        raise ValueError(f'{n - pos} trailing bytes in the mapping payload')
    return structs, enums
