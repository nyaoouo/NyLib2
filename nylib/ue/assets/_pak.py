"""Legacy .pak indexes and ranged loose-file reads."""
import hashlib
import logging
import os
import re
import struct
import time
from dataclasses import dataclass

from nylib.utils import oodle
from nylib.utils.oodle import OodleError
from ..errors import CorruptAssetError, InvalidKeyError, UnsupportedContainerError
from ._iostore import _MAX_BLOCK_SIZE, _changed_file, _container_error, _guid_str
from ._winfile import SharedFile

_BAD = re.compile('[\x00-\x1f\x7f-\x9f\u2028\u2029\ud800-\udfff]')
_LOWER = str.maketrans('ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz')
_PIECE = 64 << 10
_UNRECORDED = object()
_PATH_ERROR = ("path must be a relative path such as 'Wardogs/Content/Localization/Game/en/Game.locres', "
               "without a backslash, a leading /, an empty segment, '.' or '..'")


@dataclass(frozen=True, slots=True)
class FileInfo:
    path: str
    container: str
    size: int
    stored_size: int
    compression: str
    encrypted: bool


def lower(s):
    return s.translate(_LOWER)


def check_path(path, *, record=False):
    if record and isinstance(path, FileInfo):
        path = path.path
        if not isinstance(path, str):
            raise ValueError(_PATH_ERROR)
    if not isinstance(path, str):
        raise TypeError('path must be a str' + (' or FileInfo' if record else ''))
    if not path or '\\' in path or path.startswith('/') or any(s in ('', '.', '..') for s in path.split('/')):
        raise ValueError(_PATH_ERROR)
    return path


class _Bad(Exception):
    pass


class _Reader:
    def __init__(self, data):
        self.data, self.pos = data, 0

    def take(self, n):
        if n < 0 or n > len(self.data) - self.pos:
            raise _Bad(f'truncated at {self.pos:#x}')
        p = self.pos
        self.pos += n
        return self.data[p:self.pos]

    def number(self, fmt):
        return struct.unpack('<' + fmt, self.take(struct.calcsize('<' + fmt)))[0]

    def count(self, minimum=1):
        n = self.number('i')
        if n < 0 or n > (len(self.data) - self.pos) // minimum:
            raise _Bad('invalid count')
        return n

    def flag(self):
        n = self.number('I')
        if n > 1:
            raise _Bad('invalid bool value')
        return bool(n)

    def fstring(self):
        n = self.number('i')
        if not n:
            return ''
        raw = self.take(n if n > 0 else -2 * n)
        end = 1 if n > 0 else 2
        if raw[-end:] != bytes(end):
            raise _Bad('string has no terminator')
        return raw[:-end].decode('latin-1' if n > 0 else 'utf-16-le', 'surrogatepass')

    def name(self, version):
        if version == 11:
            return self.fstring()
        raw = self.take(self.number('i'))
        if raw.endswith(b'\0'):
            raw = raw[:-1]
        try:
            return raw.decode('utf-8')
        except UnicodeDecodeError:
            return None

    def end(self):
        if len(self.data) - self.pos > 15:
            raise _Bad('more than 15 bytes after the index')


def align16(n):
    return (n + 15) & ~15


def read_footer(path):
    with SharedFile(path) as f:
        return _read_footer(f)


def _read_footer(f):
    size = f.identity().size
    for length in (221, 222, 225, 262):
        if size < length:
            continue
        b = f.pread(size - length, length)
        if len(b) != length:
            return None
        if struct.unpack_from('<I', b, 17)[0] != 0x5A6F12E1:
            continue
        methods = tuple(b[61 + 32 * i:93 + 32 * i].split(b'\0', 1)[0].decode('ascii', 'replace') for i in range(5)) if length == 221 else ()
        foot = dict(size=size, length=length, version=struct.unpack_from('<i', b, 21)[0], encrypted=bool(b[16]),
                    guid=_guid_str(b[:16]), methods=methods)
        if length == 221:
            foot.update(offset=struct.unpack_from('<q', b, 25)[0], index_size=struct.unpack_from('<q', b, 33)[0], hash=b[41:61])
        return foot
    return None


def _method(methods, k):
    names = ('None',) + tuple(m for m in methods if m)
    return names[k] if k < len(names) else f'#{k}'


def _encoded(data, loc, methods):
    r = _Reader(data)
    if loc >= len(data):
        raise _Bad('encoded entry location outside the index')
    r.pos = loc
    bits = r.number('I')
    bs = r.number('I') if bits & 63 == 63 else (bits & 63) << 11
    method = bits >> 23 & 63
    off = r.number('I' if bits & (1 << 31) else 'q')
    usize = r.number('I' if bits & (1 << 30) else 'q')
    size = r.number('I' if bits & (1 << 29) else 'q') if method else usize
    encrypted = bool(bits & (1 << 22))
    n = bits >> 6 & 0xFFFF
    sizes = [size] if n == 1 and not encrypted else [r.number('I') for _ in range(n)]
    header = 53 + (4 + 16 * n if method else 0)
    starts, p = [], off + header
    for s in sizes:
        starts.append(p)
        p += align16(s) if encrypted else s
    return dict(offset=off, size=size, usize=usize, method=_method(methods, method), method_index=method, encrypted=encrypted,
                block_size=usize if n == 1 else bs, blocks=tuple(zip(starts, sizes)), header=header, deleted=False)


def _serialized(r, methods):
    off, size, usize = r.number('q'), r.number('q'), r.number('q')
    method = r.number('I')
    r.take(20)
    blocks = [(r.number('q'), r.number('q')) for _ in range(r.count(16))] if method else []
    flags, bs = r.number('B'), r.number('I')
    return dict(offset=off, size=size, usize=usize, method=_method(methods, method), method_index=method, encrypted=bool(flags & 1),
                deleted=bool(flags & 2), block_size=bs, blocks=tuple((off + s, e - s) for s, e in blocks),
                header=53 + (4 + 16 * len(blocks) if method else 0))


def _read(f, offset, n, counters):
    t = time.perf_counter()
    b = f.pread(offset, n)
    counters.seconds_io += time.perf_counter() - t
    counters.blocks_read += 1
    counters.bytes_read += len(b)
    if len(b) != n:
        raise _Bad('read past the file end')
    return b


def _decrypt(aes, data, counters):
    t = time.perf_counter()
    b = aes.decrypt(data)
    counters.seconds_aes += time.perf_counter() - t
    return b


def _blob(f, offset, size, foot, aes, counters):
    n = align16(size) if aes else size
    if offset < 0 or size < 0 or offset + n > foot['size']:
        raise _Bad('index range outside the file')
    b = _read(f, offset, n, counters)
    return _decrypt(aes, b, counters)[:size] if aes else b


def _corrupt(pak, detail, path=None):
    src = f'{pak}: ' + (f'{path!r}: ' if path is not None else '')
    return CorruptAssetError(src + detail, container=pak, file=path, detail=detail)


def read_index(path, aes_for, check, counters, identity=_UNRECORDED):
    pak = os.path.basename(path)
    entry_path = None
    try:
        check()
        with SharedFile(path) as f:
            if identity is not _UNRECORDED and f.identity() != identity:
                raise _changed_file(pak, pak)
            foot = _read_footer(f)
            if foot is None:
                raise _Bad('not a recognised .pak file')
            v = foot['version']
            if foot['length'] != 221 or v not in (11, 12):
                raise UnsupportedContainerError(f'{pak} is a .pak of version {v}, which this nylib version does not read',
                                                container=pak, feature=f'pak version {v}')
            aes = aes_for(foot['guid'], pak) if foot['encrypted'] else None
            prim = _blob(f, foot['offset'], foot['index_size'], foot, aes, counters)
            r = _Reader(prim)
            try:
                mount = r.fstring()
                if not 1 <= len(mount) <= 1024 or _BAD.search(mount):
                    raise _Bad('invalid mount point')
            except _Bad:
                if aes:
                    guid = foot['guid']
                    raise InvalidKeyError(f'AES key (guid {guid}) does not decrypt {pak}: its index does not start with a valid mount point',
                                          key_guid=guid, container=pak) from None
                raise
            if hashlib.sha1(prim).digest() != foot['hash']:
                raise _Bad('the index does not match its SHA-1 hash')
            if r.number('i') < 0:
                raise _Bad('invalid entry count')
            r.number('Q')
            if r.flag():
                r.take(36)
            if not r.flag():
                raise UnsupportedContainerError(f'{pak} has no full directory index, which this nylib version needs to list its files',
                                                container=pak, feature='pak without a full directory index')
            doff, dsize, dhash = r.number('q'), r.number('q'), r.take(20)
            encoded = r.take(r.number('i'))
            serialized = [_serialized(r, foot['methods']) for _ in range(r.count(53))]
            r.end()
            check()
            d = _blob(f, doff, dsize, foot, aes, counters)
            if hashlib.sha1(d).digest() != dhash:
                raise _Bad('the directory index does not match its SHA-1 hash')
            dr, files, skipped = _Reader(d), [], 0
            decoded, validated = {}, set()
            for _ in range(dr.count(8)):
                directory = dr.fstring()
                for _ in range(dr.count(8)):
                    name, loc = dr.name(v), dr.number('i')
                    if loc == -0x80000000 or name is None:
                        skipped += 1
                        continue
                    if loc < 0 and -loc > len(serialized):
                        raise _Bad('serialized entry location outside the index')
                    if loc not in decoded:
                        decoded[loc] = _encoded(encoded, loc, foot['methods']) if loc >= 0 else serialized[-loc - 1]
                    e = decoded[loc]
                    if e['deleted']:
                        skipped += 1
                        continue
                    p = re.sub('/+', '/', mount.removeprefix('../../../') + directory + name).lstrip('/')
                    try:
                        check_path(p)
                    except ValueError:
                        skipped += 1
                        continue
                    if len(p) > 1024 or _BAD.search(p):
                        skipped += 1
                        continue
                    entry_path = p
                    if loc not in validated:
                        if min(e['offset'], e['size'], e['usize']) < 0:
                            raise _Bad('negative entry size or offset')
                        if not e['method_index']:
                            ranges = [(e['offset'] + e['header'], e['usize'])]
                            if e['size'] != e['usize']:
                                raise _Bad('stored entry size mismatch')
                        else:
                            ranges = e['blocks']
                            bs = e['block_size']
                            if not 0 <= bs <= _MAX_BLOCK_SIZE or (bs == 0 and (e['usize'] or e['size'] or ranges)):
                                raise _Bad('invalid compression block count or size')
                            if bs and len(ranges) != (e['usize'] + bs - 1) // bs:
                                raise _Bad('invalid compression block count or size')
                            if any(size > _MAX_BLOCK_SIZE for _, size in ranges):
                                raise _Bad('invalid compression block count or size')
                        for start, size in ranges:
                            if start < 0 or size < 0 or start + (align16(size) if e['encrypted'] else size) > foot['size']:
                                raise _Bad('entry block range outside the file')
                        validated.add(loc)
                    info = FileInfo(p, pak, e['usize'], e['size'], e['method'], e['encrypted'])
                    files.append((info, path, foot['guid'], e))
                    entry_path = None
            dr.end()
        logging.getLogger('nylib.ue.assets').debug('container %s: %d loose files, %d skipped entries', pak, len(files), skipped)
        return files
    except OSError as e:
        raise _corrupt(pak, 'the .pak file cannot be read') from e
    except _Bad as e:
        raise _corrupt(pak, str(e), entry_path) from None


def read_range(entry, offset, n, aes, check, counters, identity=_UNRECORDED):
    info, path, guid, e = entry
    if not n:
        return b''
    bs = e['block_size'] if e['method_index'] else _PIECE
    first, last = offset // bs, (offset + n - 1) // bs
    check.k, check.n = 0, last - first + 1
    out = bytearray(n)
    try:
        with SharedFile(path) as f:
            if identity is not _UNRECORDED and f.identity() != identity:
                raise _changed_file(info.container, os.path.basename(path), info.path)
            for b in range(first, last + 1):
                check()
                lo, hi = max(offset, b * bs), min(offset + n, (b + 1) * bs)
                if not e['method_index']:
                    start, end = (lo & ~15, align16(hi)) if aes else (lo, hi)
                    data = _read(f, e['offset'] + e['header'] + start, end - start, counters)
                    if aes:
                        data = _decrypt(aes, data, counters)
                    data = data[lo - start:hi - start]
                else:
                    start, size = e['blocks'][b]
                    raw = _read(f, start, align16(size) if aes else size, counters)
                    if aes:
                        raw = _decrypt(aes, raw, counters)[:size]
                    usize = min(bs, info.size - b * bs)
                    t = time.perf_counter()
                    try:
                        data = bytes(oodle.decompress(raw, usize))
                    except OodleError:
                        raise _Bad('Oodle block decompression failed') from None
                    counters.seconds_oodle += time.perf_counter() - t
                    if len(data) != usize:
                        raise _Bad('decompressed block size mismatch')
                    counters.blocks_decompressed += 1
                    counters.bytes_decompressed += usize
                    data = data[lo - b * bs:hi - b * bs]
                out[lo - offset:hi - offset] = data
                check.k += 1
    except OSError as exc:
        error = _container_error(exc, info.container, os.path.basename(path))
        error.file = info.path
        raise error from None
    except _Bad as exc:
        raise _corrupt(info.container, str(exc), info.path) from None
    return bytes(out)
