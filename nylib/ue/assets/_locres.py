"""Parse UE localization resources and metadata into immutable records."""
import hashlib
import struct
import zlib
from dataclasses import dataclass
from types import MappingProxyType

from ..errors import CorruptAssetError, UnsupportedAssetError

_LOCRES_MAGIC = struct.pack('<4I', 0x7574140E, 0xFC034A67, 0x9D90154A, 0x1B7F37C3)
_LOCMETA_MAGIC = struct.pack('<4I', 0xA14CEE4F, 0x83554868, 0xBD464C6C, 0x7C50DA70)
_I32, _U32, _I64 = struct.Struct('<i'), struct.Struct('<I'), struct.Struct('<q')


@dataclass(frozen=True, slots=True)
class LocresEntry:
    namespace: str
    key: str
    string: str
    source_hash: int


@dataclass(frozen=True, slots=True)
class Locmeta:
    version: int
    native_culture: str
    native_locres: str
    cultures: tuple[str, ...]
    ugc: bool


class Locres:
    __slots__ = ('version', 'sha256', 'namespaces', 'entries', '_index', '_hash')

    def __new__(cls, *args, **kwargs):
        raise TypeError('Locres cannot be constructed directly: call parse_locres()')

    def __setattr__(self, name, value):
        raise AttributeError('Locres is immutable')

    def __delattr__(self, name):
        raise AttributeError('Locres is immutable')

    def __len__(self) -> int:
        return len(self.entries)

    def __repr__(self):
        return (f'Locres(version={self.version}, entries={len(self.entries)}, '
                f'namespaces={len(self.namespaces)}, sha256={self.sha256[:8] + "..."!r})')

    def __eq__(self, other):
        if not isinstance(other, Locres):
            return NotImplemented
        return (self.version, self.namespaces, self.entries) == (other.version, other.namespaces, other.entries)

    def __hash__(self):
        return self._hash

    def __reduce__(self):
        return _make_locres, (self.version, self.sha256, self.namespaces, self.entries)

    def get(self, namespace: str, key: str, default=None):
        _check_lookup(namespace, key)
        entry = self._index.get((namespace, key))
        return default if entry is None else entry.string

    def entry(self, namespace: str, key: str) -> LocresEntry:
        _check_lookup(namespace, key)
        try:
            return self._index[(namespace, key)]
        except KeyError:
            raise KeyError('no entry with that namespace and key') from None

    @staticmethod
    def source_hash(text: str) -> int:
        if not isinstance(text, str):
            raise TypeError('text must be a str')
        units = text.split('\0', 1)[0].encode('utf-16-le', 'surrogatepass')
        n = len(units) // 2
        return zlib.crc32(struct.pack(f'<{n}I', *struct.unpack(f'<{n}H', units))) if n else 0


def _check_lookup(namespace, key):
    if not isinstance(namespace, str) or not isinstance(key, str):
        raise TypeError('namespace and key must be str')


def _make_locres(version, sha256, namespaces, entries):
    result = object.__new__(Locres)
    for name, value in (('version', version), ('sha256', sha256), ('namespaces', namespaces), ('entries', entries),
                        ('_index', MappingProxyType({(e.namespace, e.key): e for e in entries})),
                        ('_hash', hash((version, namespaces, entries)))):
        object.__setattr__(result, name, value)
    return result


class _Reader:
    __slots__ = ('data', 'pos', 'end', 'file', 'kind', 'src')

    def __init__(self, data, kind, file):
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise TypeError('data must be bytes, bytearray or memoryview')
        if file is not None and not isinstance(file, str):
            raise TypeError('file must be a str or None')
        self.data = data.tobytes() if isinstance(data, memoryview) else bytes(data)
        self.pos, self.end = 0, len(self.data)
        self.file, self.kind = file, kind
        self.src = 'the data' if file is None else repr(file)

    def fail(self, detail):
        raise CorruptAssetError(f'{self.src} is not a valid .{self.kind}: {detail}', detail=detail, file=self.file)

    def unsupported(self, version):
        raise UnsupportedAssetError(
            f'{self.src} is a .{self.kind} of version {version}, which this nylib version does not read',
            feature=f'{self.kind} version {version}', file=self.file)

    def need(self, n):
        p = self.pos
        if n > self.end - p:
            self.fail(f'truncated at {p:#x}')
        self.pos += n
        return p

    def i32(self):
        return _I32.unpack_from(self.data, self.need(4))[0]

    def u32(self):
        return _U32.unpack_from(self.data, self.need(4))[0]

    def count(self, unit, what, *, unsigned=False):
        p = self.pos
        n = self.u32() if unsigned else self.i32()
        if n < 0 or n * unit > self.end - self.pos:
            self.fail(f'{what} {n} at {p:#x}')
        return n

    def fstring(self):
        p = self.pos
        n = self.i32()
        if not n:
            return ''
        size = n if n > 0 else -2 * n
        if size > self.end - self.pos:
            self.fail(f'bad string at {p:#x}')
        q = self.need(size)
        raw = self.data[q:q + size]
        if n > 0:
            if raw[-1] != 0:
                self.fail(f'bad string at {p:#x}')
            return raw[:-1].decode('latin-1')
        if raw[-2:] != b'\0\0':
            self.fail(f'bad string at {p:#x}')
        return raw[:-2].decode('utf-16-le', 'surrogatepass')


def parse_locres(data: 'bytes | bytearray | memoryview', *, file: str | None = None) -> Locres:
    """Read a version 3 localization resource."""
    r = _Reader(data, 'locres', file)
    b = r.data
    if b[:16] != _LOCRES_MAGIC:
        raise UnsupportedAssetError(
            f'{r.src} has no .locres magic: a legacy (version 0) .locres, which this nylib version does not read',
            feature='locres version 0', file=file)
    r.pos = 16
    version = b[r.need(1)]
    if version != 3:
        r.unsupported(version)
    p = r.need(8)
    strings_at = _I64.unpack_from(b, p)[0]
    if not r.pos + 4 <= strings_at <= len(b) - 4:
        r.fail(f'string array offset {strings_at:#x} at {p:#x}')
    declared = r.u32()
    r.pos = strings_at
    n = r.count(8, 'string count')
    strings = []
    for _ in range(n):
        strings.append(r.fstring())
        r.need(4)
    if r.pos != len(b):
        r.fail(f'the string array ends at {r.pos:#x}, not at the end ({len(b):#x})')
    r.pos, r.end = 29, strings_at
    nns = r.count(12, 'namespace count', unsigned=True)
    namespaces, entries, seen = [], [], set()
    for _ in range(nns):
        r.need(4)
        ns = r.fstring()
        namespaces.append(ns)
        nk = r.count(16, 'key count', unsigned=True)
        for _ in range(nk):
            r.need(4)
            kp = r.pos
            key = r.fstring()
            src = r.u32()
            ip = r.pos
            si = r.i32()
            if not 0 <= si < n:
                r.fail(f'string index {si} outside the {n} strings at {ip:#x}')
            if (ns, key) in seen:
                r.fail(f'repeated namespace and key at {kp:#x}')
            seen.add((ns, key))
            entries.append(LocresEntry(ns, key, strings[si], src))
    if r.pos != strings_at:
        r.fail(f'the entry table ends at {r.pos:#x}, not at the string array ({strings_at:#x})')
    if declared != len(entries):
        r.fail(f'{declared} entries declared, {len(entries)} read')
    return _make_locres(3, hashlib.sha256(b).hexdigest(), tuple(namespaces), tuple(entries))


def parse_locmeta(data: 'bytes | bytearray | memoryview', *, file: str | None = None) -> Locmeta:
    """Read version 2 localization metadata."""
    r = _Reader(data, 'locmeta', file)
    if r.data[:16] != _LOCMETA_MAGIC:
        r.fail('no .locmeta magic')
    r.pos = 16
    version = r.data[r.need(1)]
    if version != 2:
        r.unsupported(version)
    native_culture, native_locres = r.fstring(), r.fstring()
    n = r.count(4, 'culture count')
    cultures = tuple(r.fstring() for _ in range(n))
    p = r.pos
    ugc = r.u32()
    if ugc > 1:
        r.fail(f'bool value {ugc} at {p:#x}')
    if r.pos != r.end:
        r.fail(f'{r.end - r.pos} bytes after the end at {r.pos:#x}')
    return Locmeta(2, native_culture, native_locres, cultures, ugc == 1)
