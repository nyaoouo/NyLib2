"""IoStore (.utoc/.ucas) containers: TOC model, chunk lookup, block reads, directory index, key check, .pak footer.

Only TOC version 8 (the UE 5.7 profile) is read. A chunk is identified by all 12 raw FIoChunkId bytes.
"""
import hashlib
import os
import stat
import struct
import threading
import time
from typing import NamedTuple

from nylib.utils import oodle
from nylib.utils.oodle import OodleError
from ..errors import CorruptAssetError, InstallationClosedError, InvalidKeyError, UnsupportedContainerError
from ._bcrypt import Aes256Ecb
from ._hashes import chunk_hash
from ._keys import AesKey
from ._records import _Counters

_TOC_MAGIC = b'-==--==--==--==-'
_TOC_HEADER_LEN = 144
_SUPPORTED_VERSION = 8
_FLAG_ENCRYPTED = 2
_FLAG_SIGNED = 4
_FLAG_INDEXED = 8
_FLAG_ON_DEMAND = 16
_MIN_BLOCK_SIZE = 4096
_MAX_BLOCK_SIZE = 1 << 24
_CHECK_EVERY = 4096
_INVALID = 0xFFFFFFFF

CHUNK_TYPE_NAMES = {
    0: 'Invalid', 1: 'ExportBundleData', 2: 'BulkData', 3: 'OptionalBulkData', 4: 'MemoryMappedBulkData',
    5: 'ScriptObjects', 6: 'ContainerHeader', 7: 'ExternalFile', 8: 'ShaderCodeLibrary', 9: 'ShaderCode',
    10: 'PackageStoreEntry', 11: 'DerivedData', 12: 'EditorDerivedData', 13: 'PackageResource',
}


def chunk_type_name(chunk_type: int) -> str:
    return CHUNK_TYPE_NAMES.get(chunk_type, str(chunk_type))


def _align16(n: int) -> int:
    return (n + 15) & ~15


def chunk_key(chunk_id: int, index: int, chunk_type: int, extra: int = 0) -> bytes:
    """The 12-byte FIoChunkId: u64 id, NETWORK_ORDER16 index, byte 10 = extra, type; a value outside its field raises ValueError."""
    for argname, value, width in (
            ('chunk_id', chunk_id, 1 << 64), ('index', index, 1 << 16),
            ('chunk_type', chunk_type, 1 << 8), ('extra', extra, 1 << 8)):
        if not 0 <= value < width:
            raise ValueError(f'{argname} out of range: {value!r}')
    swapped = ((index & 0xFF) << 8) | (index >> 8)
    return struct.pack('<QHBB', chunk_id, swapped, extra, chunk_type)


def _guid_str(raw16: bytes) -> str:
    a, b, c, d = struct.unpack_from('<4I', raw16)
    return f'{a:08X}{b:08X}{c:08X}{d:08X}'


def _container_error(e: OSError, container: str, basename: str) -> CorruptAssetError:
    """A container-file OSError: 'not found' for a missing file, 'cannot be read' for any other OSError."""
    detail = 'not found' if isinstance(e, FileNotFoundError) else 'cannot be read'
    return CorruptAssetError(f'container file {basename} {detail}', container=container, detail=detail,
                              errno=e.errno, winerror=e.winerror)


def _corrupt(container: str, detail: str, chunk: tuple[int, int] | None = None, block: int | None = None) -> CorruptAssetError:
    """A CorruptAssetError reading '{container}[ chunk {id:016x} ({type})][ block {b}]: {detail}'; chunk is (id, type)."""
    loc = container
    if chunk is not None:
        loc += f' chunk {chunk[0]:016x} ({chunk_type_name(chunk[1])})'
    if block is not None:
        loc += f' block {block}'
    return CorruptAssetError(f'{loc}: {detail}', container=container, detail=detail)


def _pread(f, offset: int, size: int, container: str, basename: str) -> bytes:
    try:
        f.seek(offset)
        return f.read(size)
    except OSError as e:
        raise _container_error(e, container, basename) from None


def _digest(name: str, header: bytes, ids: bytes, offlens: bytes, blocks: bytes, methods: bytes, metas: bytes,
            dir_index: bytes, ucas_size: int) -> bytes:
    """The per-container identity input: sha256 of the length-prefixed name and sections, then the .ucas size."""
    def f(b: bytes) -> bytes:
        return len(b).to_bytes(8, 'little') + b

    h = hashlib.sha256()
    h.update(f(name.encode('utf-8', 'surrogatepass')))
    h.update(f(header))
    h.update(f(ids))
    h.update(f(offlens))
    h.update(f(blocks))
    h.update(f(methods))
    h.update(f(metas))
    h.update(f(dir_index))
    h.update(ucas_size.to_bytes(8, 'little'))
    return h.digest()


class Toc:
    """A parsed .utoc; per-entry fields decode on demand from the retained raw sections."""
    __slots__ = ('path', 'version', 'flags', 'entry_count', 'block_count', 'method_count', 'block_size',
                 'dir_index_size', 'partition_count', 'container_id', 'key_guid', '_methods',
                 '_chunk_ids_raw', '_offlen_raw', '_seeds_raw', 'seeds_count', '_no_hash_raw', 'no_hash_count',
                 '_raw_blocks', 'dir_index_raw', 'ucas_size', 'digest', '_no_hash_map')

    def __init__(self, path, version, flags, entry_count, block_count, method_count, block_size, dir_index_size,
                 partition_count, container_id, key_guid, methods, chunk_ids_raw, offlen_raw, seeds_raw,
                 seeds_count, no_hash_raw, no_hash_count, raw_blocks, dir_index_raw, ucas_size, digest):
        self.path = path
        self.version = version
        self.flags = flags
        self.entry_count = entry_count
        self.block_count = block_count
        self.method_count = method_count
        self.block_size = block_size
        self.dir_index_size = dir_index_size
        self.partition_count = partition_count
        self.container_id = container_id
        self.key_guid = key_guid
        self._methods = methods  # tuple, index 0 is 'None' (stored)
        self._chunk_ids_raw = chunk_ids_raw  # bytes, 12 * entry_count
        self._offlen_raw = offlen_raw  # bytes, 10 * entry_count (5-byte offset + 5-byte length, big-endian)
        self._seeds_raw = seeds_raw  # bytes, 4 * seeds_count; a zero count means no perfect hash (linear scan)
        self.seeds_count = seeds_count
        self._no_hash_raw = no_hash_raw  # bytes, 4 * no_hash_count: entry indices without a perfect-hash slot
        self.no_hash_count = no_hash_count
        self._raw_blocks = raw_blocks  # bytes, 12 * block_count
        self.dir_index_raw = dir_index_raw  # bytes or None; still encrypted when the container is
        self.ucas_size = ucas_size
        self.digest = digest
        self._no_hash_map = None

    @property
    def basename(self) -> str:
        return os.path.basename(self.path)

    @property
    def encrypted(self) -> bool:
        return bool(self.flags & _FLAG_ENCRYPTED)

    @property
    def indexed(self) -> bool:
        return bool(self.flags & _FLAG_INDEXED)

    def declared_methods(self) -> tuple[str, ...]:
        return self._methods[1:]

    def used_methods(self) -> tuple[str, ...]:
        """The names at least one block uses, stored blocks excluded, in declared order."""
        used = set(self._raw_blocks[11::12])
        return tuple(name for i, name in enumerate(self._methods) if i and i in used)

    def block(self, i: int) -> tuple[int, int, int, int]:
        """(offset, compressed size, uncompressed size, method index) of block `i`."""
        if not 0 <= i < self.block_count:
            raise IndexError(i)
        lo, hi = struct.unpack_from('<QI', self._raw_blocks, 12 * i)
        return lo & ((1 << 40) - 1), (lo >> 40) & 0xFFFFFF, hi & 0xFFFFFF, hi >> 24

    def method_name(self, index: int) -> str:
        return self._methods[index]

    def chunk_key_at(self, i: int) -> bytes:
        """The raw 12-byte FIoChunkId of entry `i`."""
        if not 0 <= i < self.entry_count:
            raise IndexError(i)
        return self._chunk_ids_raw[12 * i:12 * i + 12]

    def chunk_fields(self, i: int) -> tuple[int, int, int, int]:
        """(chunk_id, index, extra, chunk_type) of entry `i`, index un-swapped from NETWORK_ORDER16."""
        cid, swapped, extra, ctype = struct.unpack('<QHBB', self.chunk_key_at(i))
        index = ((swapped & 0xFF) << 8) | (swapped >> 8)
        return cid, index, extra, ctype

    def chunk_range(self, i: int) -> tuple[int, int]:
        """(offset, length) of entry `i`, in the logical block-table space; raises on the 'block layout' row."""
        if not 0 <= i < self.entry_count:
            raise IndexError(i)
        off = int.from_bytes(self._offlen_raw[10 * i:10 * i + 5], 'big')
        length = int.from_bytes(self._offlen_raw[10 * i + 5:10 * i + 10], 'big')
        limit = self.block_count * self.block_size
        if off + length > limit:
            cid, _index, _extra, ctype = self.chunk_fields(i)
            raise _corrupt(self.basename, f'the chunk ends at {off + length:#x}, past the block table end {limit:#x}', (cid, ctype))
        return off, length

    def _seed_at(self, i: int) -> int:
        (v,) = struct.unpack_from('<i', self._seeds_raw, 4 * i)
        return v

    def _no_hash_at(self, i: int) -> int:
        (v,) = struct.unpack_from('<i', self._no_hash_raw, 4 * i)
        return v

    def find_raw(self, key: bytes) -> int | None:
        """The TOC entry index whose raw 12-byte FIoChunkId is `key`, or None."""
        if len(key) != 12:
            raise ValueError(f'chunk key must be 12 bytes, got {len(key)}')
        n = self.entry_count
        if n == 0:
            return None
        if self.seeds_count == 0:
            return self._find_linear(key)
        seed = self._seed_at(chunk_hash(key, 0) % self.seeds_count)
        if seed == 0:
            return None
        if seed < 0:
            slot = -seed - 1
            if slot >= n:
                return self._find_no_hash(key)
        else:
            slot = chunk_hash(key, seed) % n
        return slot if self.chunk_key_at(slot) == key else None

    def find(self, chunk_id: int, index: int, chunk_type: int) -> int | None:
        """find_raw of (chunk_id, index, chunk_type) with byte 10 = 0, the default cooked index."""
        return self.find_raw(chunk_key(chunk_id, index, chunk_type))

    def _find_no_hash(self, key: bytes) -> int | None:
        if self._no_hash_map is None:
            self._no_hash_map = {
                self.chunk_key_at(idx): idx
                for idx in (self._no_hash_at(j) for j in range(self.no_hash_count))}
        return self._no_hash_map.get(key)

    def _find_linear(self, key: bytes) -> int | None:
        raw = self._chunk_ids_raw
        pos = raw.find(key)
        while pos >= 0:
            if pos % 12 == 0:
                return pos // 12
            pos = raw.find(key, pos + 1)
        return None

    @classmethod
    def read(cls, path: str, counters: _Counters | None = None) -> 'Toc':
        """Parse and validate a .utoc in the 'TOC validation' row order, and stat the sibling .ucas."""
        name = os.path.basename(path)
        t0 = time.perf_counter()
        try:
            f = open(path, 'rb')
        except OSError as e:
            raise _container_error(e, name, name) from None
        with f:
            try:
                n = os.fstat(f.fileno()).st_size
            except OSError as e:
                raise _container_error(e, name, name) from None
            head = _pread(f, 0, _TOC_HEADER_LEN, name, name)
            got = len(head)
            if len(head) < _TOC_HEADER_LEN or head[:16] != _TOC_MAGIC:
                raise _corrupt(name, 'not a valid .utoc (bad magic or truncated header)')
            (version, _r0, _r1, header_size, entry_count, block_count, block_entry_size, method_count, method_len,
             block_size, dir_index_size, partition_count, container_id) = struct.unpack_from('<BBHIIIIIIIIIQ', head, 16)
            if version != _SUPPORTED_VERSION:
                ctr = ' (AES-CTR)' if version == 10 else ''
                raise UnsupportedContainerError(
                    f'{name} uses TOC version {version}{ctr}; this nylib version reads TOC version 8 (the UE 5.7 profile)',
                    feature=f'TOC version {version}', container=name)
            if header_size != _TOC_HEADER_LEN:
                raise _corrupt(name, f'the header size is {header_size}, expected {_TOC_HEADER_LEN}')
            key_guid = _guid_str(head[64:80])
            flags, _enc_method, _r4, seeds_count, _partition_size, no_hash_count = struct.unpack_from('<BBHIQI', head, 80)
            if partition_count != 1:
                raise UnsupportedContainerError(f'{name} has {partition_count} partitions; this nylib version reads 1',
                                                 feature='multiple partitions', container=name)
            if flags & _FLAG_ON_DEMAND:
                raise UnsupportedContainerError(f'{name} is an on-demand container, which this nylib version does not read',
                                                 feature='OnDemand container', container=name)
            if block_entry_size != 12:
                raise _corrupt(name, f'the compressed block entry size is {block_entry_size}, expected 12')
            if not _MIN_BLOCK_SIZE <= block_size <= _MAX_BLOCK_SIZE or block_size & (block_size - 1):
                raise _corrupt(name, f'the compression block size {block_size} is not a power of two from '
                                     f'{_MIN_BLOCK_SIZE} to {_MAX_BLOCK_SIZE}')
            if method_count > 255:
                raise _corrupt(name, f'the compression method count {method_count} is above 255')
            if method_count and method_len == 0:
                raise _corrupt(name, f'{method_count} compression methods are declared with a name length of 0')

            ids_size = 12 * entry_count
            offlen_size = 10 * entry_count
            seeds_size = 4 * seeds_count
            no_hash_size = 4 * no_hash_count
            blocks_size = 12 * block_count
            methods_size = method_count * method_len
            pos = _TOC_HEADER_LEN + ids_size + offlen_size + seeds_size + no_hash_size + blocks_size + methods_size
            sig_size = 0
            if flags & _FLAG_SIGNED:
                raw_hash_size = _pread(f, pos, 4, name, name)
                got += len(raw_hash_size)
                if len(raw_hash_size) < 4:
                    raise _corrupt(name, f'the Signed hash size at {pos} lies past the file end {n}')
                (hash_size,) = struct.unpack('<i', raw_hash_size)
                if hash_size < 0:
                    raise _corrupt(name, f'the Signed hash size {hash_size} is negative')
                sig_size = 4 + 2 * hash_size + 20 * block_count
            dir_size = dir_index_size if flags & _FLAG_INDEXED else 0
            metas_size = 24 * entry_count  # FIoStoreTocEntryMeta: 20-byte hash, 1 flags byte, 3 padding
            pos += sig_size + dir_size + metas_size
            if pos != n:
                raise _corrupt(name, f'the TOC sections end at {pos}, not at the file size {n}')
            data = _pread(f, _TOC_HEADER_LEN, n - _TOC_HEADER_LEN, name, name)
            got += len(data)
            if len(data) != n - _TOC_HEADER_LEN:
                raise _corrupt(name, f'the file ends at {_TOC_HEADER_LEN + len(data)}, not at its size {n}')
        if counters is not None:
            counters.bytes_read += got
            counters.seconds_io += time.perf_counter() - t0

        p = 0
        chunk_ids_raw = data[p:p + ids_size]
        p += ids_size
        offlen_raw = data[p:p + offlen_size]
        p += offlen_size
        seeds_raw = data[p:p + seeds_size]
        p += seeds_size
        no_hash_raw = data[p:p + no_hash_size]
        p += no_hash_size
        raw_blocks = data[p:p + blocks_size]
        p += blocks_size
        method_name_bytes = data[p:p + methods_size]
        p += methods_size + sig_size
        dir_index_raw = data[p:p + dir_size] if dir_size else None
        p += dir_size
        metas_raw = data[p:p + metas_size]
        del data

        for j in range(no_hash_count):
            (idx,) = struct.unpack_from('<i', no_hash_raw, 4 * j)
            if not 0 <= idx < entry_count:
                raise _corrupt(name, f'overflow-list entry {idx} is out of range for {entry_count} entries')

        methods = ['None']
        for i in range(method_count):
            raw_name = method_name_bytes[i * method_len:(i + 1) * method_len].rstrip(b'\0')
            if not all(0x20 <= b <= 0x7E for b in raw_name):
                raise _corrupt(name, f'compression method name {i} is not printable ASCII')
            methods.append(raw_name.decode('ascii'))
        methods = tuple(methods)

        used = set(raw_blocks[11::12])
        if used and (top := max(used)) > method_count:
            raise _corrupt(name, f'a compression block uses method index {top}, above the method count {method_count}')
        for i in sorted(used):
            if i and methods[i] != 'Oodle':
                raise UnsupportedContainerError(f"{name} uses compression method '{methods[i]}', which this nylib version does not read",
                                                 feature=f"compression method '{methods[i]}'", container=name)

        if flags & _FLAG_ENCRYPTED and flags & _FLAG_INDEXED and dir_index_size % 16 != 0:
            raise _corrupt(name, f'the encrypted directory index size {dir_index_size} is not a multiple of 16')

        ucas_path = path[:-5] + '.ucas'
        ucas_name = os.path.basename(ucas_path)
        try:
            ust = os.stat(ucas_path)
        except OSError as e:
            raise _container_error(e, name, ucas_name) from None
        if not stat.S_ISREG(ust.st_mode):
            raise CorruptAssetError(f'container file {ucas_name} cannot be read', container=name, detail='cannot be read') from None
        ucas_size = ust.st_size

        digest = _digest(name, head, chunk_ids_raw, offlen_raw, raw_blocks, method_name_bytes, metas_raw,
                          dir_index_raw or b'', ucas_size)
        return cls(path, version, flags, entry_count, block_count, method_count, block_size, dir_index_size,
                    partition_count, container_id, key_guid, methods, chunk_ids_raw, offlen_raw, seeds_raw,
                    seeds_count, no_hash_raw, no_hash_count, raw_blocks, dir_index_raw, ucas_size, digest)


def check_key(toc: Toc, key: AesKey) -> None:
    """Raise unless the directory index decrypts to a NUL-terminated mount point starting with '../../../'."""
    if not toc.indexed or toc.dir_index_size == 0:
        raise UnsupportedContainerError(
            f'{toc.basename} is encrypted but has no directory index to check the key against',
            feature='encrypted container without a directory index', container=toc.basename)
    if not _mount_point_decrypts(toc.dir_index_raw, key):
        raise InvalidKeyError(
            f'AES key (guid {key.guid}) does not decrypt {toc.basename}: its directory index does not start with a valid mount point',
            key_guid=key.guid, container=toc.basename)


def _mount_point_decrypts(dir_index_raw: bytes, key: AesKey) -> bool:
    if dir_index_raw is None or len(dir_index_raw) < 16:
        return False
    aes = Aes256Ecb(key)
    try:
        head = aes.decrypt(dir_index_raw[:16])
        (length,) = struct.unpack_from('<i', head, 0)
        if length == 0 or abs(length) > 128:
            return False
        n = length if length > 0 else -2 * length
        total = _align16(4 + n)
        if total > len(dir_index_raw):
            return False
        body = aes.decrypt(dir_index_raw[:total])
        if length > 0:
            if body[4 + n - 1] != 0:
                return False
            text = body[4:4 + n - 1].decode('utf-8', 'surrogateescape')
        else:
            if body[4 + n - 2:4 + n] != b'\0\0':
                return False
            text = body[4:4 + n - 2].decode('utf-16-le', 'surrogatepass')
    finally:
        aes.close()
    return text.startswith('../../../')


class DirIndex(NamedTuple):
    mount: str
    dirs: tuple[tuple[int, int, int, int], ...]
    files: tuple[tuple[int, int, int], ...]
    strings: tuple[str, ...]


def read_directory_index(data: bytes, container: str) -> DirIndex:
    """Parse a decrypted FIoDirectoryIndexResource; raises CorruptAssetError on any structural problem."""
    n = len(data)
    pos = 0

    def need(size):
        nonlocal pos
        if pos + size > n:
            raise _corrupt(container, 'the directory index is truncated')

    def i32():
        nonlocal pos
        need(4)
        (v,) = struct.unpack_from('<i', data, pos)
        pos += 4
        return v

    def fstring():
        nonlocal pos
        length = i32()
        if length == 0:
            return ''
        if length > 0:
            need(length)
            raw = data[pos:pos + length]
            pos += length
            if not raw.endswith(b'\0'):
                raise _corrupt(container, 'a directory index string is not NUL-terminated')
            return raw[:-1].decode('utf-8', 'surrogateescape')
        size = -2 * length
        need(size)
        raw = data[pos:pos + size]
        pos += size
        if not raw.endswith(b'\0\0'):
            raise _corrupt(container, 'a directory index string is not NUL-terminated')
        return raw[:-2].decode('utf-16-le', 'surrogatepass')

    try:
        mount = fstring()
        nd = i32()
        if nd < 0:
            raise _corrupt(container, f'the directory index has a negative directory count {nd}')
        need(16 * nd)
        flat = struct.unpack_from(f'<{4 * nd}I', data, pos) if nd else ()
        dirs = tuple(flat[i:i + 4] for i in range(0, 4 * nd, 4))
        pos += 16 * nd
        nf = i32()
        if nf < 0:
            raise _corrupt(container, f'the directory index has a negative file count {nf}')
        need(12 * nf)
        flat = struct.unpack_from(f'<{3 * nf}I', data, pos) if nf else ()
        files = tuple(flat[i:i + 3] for i in range(0, 3 * nf, 3))
        pos += 12 * nf
        ns = i32()
        if ns < 0:
            raise _corrupt(container, f'the directory index has a negative string count {ns}')
        strings = tuple(fstring() for _ in range(ns))
    except struct.error:
        raise _corrupt(container, 'the directory index is malformed') from None
    return DirIndex(mount, dirs, files, strings)


def iter_directory_index(index: DirIndex, container: str, entry_count: int, *, max_len: int | None = None,
                         checkpoint=None):
    """Yield (path, toc_index) by walking the directory tree, like CUE4Parse IoStoreReader.ReadIndex.

    `entry_count` bounds `toc_index`. With `max_len`, a longer path (less a leading '../../../') yields (None, None), and
    so does a directory that long, which is not walked; `checkpoint()` runs every 4,096 entries visited.
    """
    dirs, files, strings = index.dirs, index.files, index.strings
    nd, nf, ns = len(dirs), len(files), len(strings)
    seen_dirs = bytearray(nd)
    seen_files = bytearray(nf)
    visits = 0
    bound = None if max_len is None else max_len + (9 if index.mount.startswith('../../../') else 0)

    def name(i):
        if not 0 <= i < ns:
            raise _corrupt(container, f'directory index string index {i} is out of range for {ns} strings')
        return strings[i]

    def tick():
        nonlocal visits
        visits += 1
        if checkpoint is not None and visits % _CHECK_EVERY == 0:
            checkpoint()

    def materialize(chain):
        parts = []
        while chain is not None:
            seg, chain, _length = chain
            parts.append(seg)
        parts.reverse()
        return ''.join(parts)

    if bound is not None and len(index.mount) > bound:
        yield None, None
        return
    stack = [(0, (index.mount, None, len(index.mount)))]
    while stack:
        tick()
        d, chain = stack.pop()
        if not 0 <= d < nd:
            raise _corrupt(container, f'directory index directory {d} is out of range for {nd} directories')
        if seen_dirs[d]:
            raise _corrupt(container, 'the directory index tree is cyclic')
        seen_dirs[d] = 1
        name_idx, first_child, next_sib, first_file = dirs[d]
        if next_sib != _INVALID:
            stack.append((next_sib, chain))
        child_chain = chain
        if name_idx != _INVALID:
            seg = name(name_idx)
            if seg:  # an empty directory name adds no path segment
                _, _, length = chain
                length += len(seg) + 1
                if bound is not None and length > bound:
                    yield None, None
                    continue
                child_chain = (seg + '/', chain, length)
        if first_child != _INVALID:
            stack.append((first_child, child_chain))
        f = first_file
        prefix = materialize(child_chain) if f != _INVALID else ''
        _, _, prefix_len = child_chain
        while f != _INVALID:
            tick()
            if not 0 <= f < nf:
                raise _corrupt(container, f'directory index file {f} is out of range for {nf} files')
            if seen_files[f]:
                raise _corrupt(container, 'the directory index file list is cyclic')
            seen_files[f] = 1
            name_idx, nxt, toc_index = files[f]
            if not 0 <= toc_index < entry_count:
                raise _corrupt(container, f'directory index file {f} points at TOC entry {toc_index}, outside the {entry_count} entries')
            leaf = name(name_idx)
            if bound is not None and prefix_len + len(leaf) > bound:
                yield None, None
            else:
                yield prefix + leaf, toc_index
            f = nxt


class Container:
    """Reads chunk ranges from one .utoc + .ucas pair; the .ucas opens on the first read and never after close()."""

    def __init__(self, toc: Toc, aes: Aes256Ecb | None = None):
        self.toc = toc
        self._aes = aes
        self._lock = threading.Lock()
        self._f = None
        self._size = None
        self._closed = False

    def _ensure_open(self):
        if self._f is not None:
            return
        with self._lock:
            if self._f is not None:
                return
            if self._closed:
                raise InstallationClosedError('the installation is closed')
            ucas_path = self.toc.path[:-5] + '.ucas'
            ucas_name = os.path.basename(ucas_path)
            try:
                f = open(ucas_path, 'rb')
            except OSError as e:
                raise _container_error(e, self.toc.basename, ucas_name) from None
            try:
                size = os.fstat(f.fileno()).st_size
            except OSError as e:
                f.close()
                raise _container_error(e, self.toc.basename, ucas_name) from None
            self._size = size  # set before _f is published: readers test _f without the lock
            self._f = f

    def close(self) -> None:
        with self._lock:
            self._closed = True
            if self._f is not None:
                self._f.close()
                self._f = None

    def _read_block(self, i: int, chunk: tuple[int, int], expected_usize: int, counters: _Counters | None) -> bytes:
        c = self.toc.basename
        off, csize, usize, method_idx = self.toc.block(i)
        if usize != expected_usize:
            raise _corrupt(c, f'uncompressed size {usize} does not match the expected {expected_usize}', chunk, i)
        method = self.toc.method_name(method_idx)
        if method == 'None' and csize < usize:
            raise _corrupt(c, f'a stored block has compressed size {csize} below its uncompressed size {usize}', chunk, i)
        raw_len = _align16(csize)
        self._ensure_open()
        if off + raw_len > self._size:
            raise _corrupt(c, f'the .ucas file ends at {self._size} but the block ends at {off + raw_len}', chunk, i)
        buf = bytearray(raw_len)
        t0 = time.perf_counter()
        ucas_name = os.path.basename(self.toc.path[:-5] + '.ucas')
        with self._lock:
            if self._closed:
                raise InstallationClosedError('the installation is closed')
            try:
                self._f.seek(off)
                got = self._f.readinto(buf)
            except OSError as e:
                raise _container_error(e, self.toc.basename, ucas_name) from None
        if counters is not None:
            counters.bytes_read += got
            counters.blocks_read += 1
            counters.seconds_io += time.perf_counter() - t0
        if got < raw_len:
            # off + got is only the real end when off itself is within the file; re-stat for a truncation past off.
            try:
                actual_size = os.fstat(self._f.fileno()).st_size
            except OSError as e:
                raise _container_error(e, self.toc.basename, ucas_name) from None
            raise _corrupt(c, f'the .ucas file ends at {actual_size} but the block ends at {off + raw_len}', chunk, i)
        data = bytes(buf)
        if self.toc.encrypted:
            t0 = time.perf_counter()
            data = self._aes.decrypt(data)
            if counters is not None:
                counters.seconds_aes += time.perf_counter() - t0
        if method == 'None':
            return data[:usize]
        t0 = time.perf_counter()
        try:
            out = oodle.decompress(data[:csize], usize)
        except OodleError as e:
            raise _corrupt(c, str(e), chunk, i) from e
        if counters is not None:
            counters.blocks_decompressed += 1
            counters.bytes_decompressed += len(out)
            counters.seconds_oodle += time.perf_counter() - t0
        return bytes(out)

    def read_range(self, toc_index: int, offset: int, length: int, *, memo: dict | None = None,
                   cache: dict | None = None, counters: _Counters | None = None, checkpoint=None) -> bytes:
        """Bytes [offset, offset+length) of chunk `toc_index`; touches only the blocks that intersect.

        `memo` and `cache` are plain mappings keyed by (self, block_index): `memo` is this operation's own
        (checked first, never evicted), `cache` is the caller's shared block cache (checked, and filled, second).
        """
        chunk_id, _index, _extra, chunk_type = self.toc.chunk_fields(toc_index)
        c_off, c_len = self.toc.chunk_range(toc_index)
        if offset < 0 or length < 0 or offset + length > c_len:
            raise ValueError(f'range {offset}+{length} outside chunk of {c_len} bytes')
        if length == 0:
            return b''
        bs = self.toc.block_size
        chunk_end = c_off + c_len
        start = c_off + offset
        end = start + length
        pieces = []
        for b in range(start // bs, (end - 1) // bs + 1):
            if checkpoint is not None:
                checkpoint()
            key = (self, b)
            expected_usize = min(bs, chunk_end - b * bs)
            data = memo.get(key) if memo is not None else None
            if data is None and cache is not None:
                data = cache.get(key)
                if data is not None and counters is not None:
                    counters.cache_hits += 1
            if data is not None and len(data) != expected_usize:
                # a block shared with another chunk whose end differs must still match this chunk's own size.
                raise _corrupt(self.toc.basename, f'uncompressed size {len(data)} does not match the expected {expected_usize}',
                                (chunk_id, chunk_type), b)
            if data is None:
                data = self._read_block(b, (chunk_id, chunk_type), expected_usize, counters)
                if cache is not None:
                    cache[key] = data
            if memo is not None:
                memo[key] = data
            pieces.append(data[max(start - b * bs, 0):min(end - b * bs, bs, len(data))])
        return b''.join(pieces)


class PakFooter(NamedTuple):
    version: int
    encrypted: bool
    key_guid: str
    compression: tuple[str, ...]


_PAK_MAGIC = 0x5A6F12E1
_PAK_FOOTER_LEN = 221  # FPakInfo (post-4.23): guid16 + enc1 + magic4 + ver4 + off8 + size8 + hash20 + 5*32 methods


def read_pak_footer(path: str) -> PakFooter | None:
    """The trailing FPakInfo of a legacy .pak; None when the footer does not parse."""
    name = os.path.basename(path)
    try:
        with open(path, 'rb') as f:
            size = os.fstat(f.fileno()).st_size
            if size < _PAK_FOOTER_LEN:
                return None
            f.seek(size - _PAK_FOOTER_LEN)
            foot = f.read(_PAK_FOOTER_LEN)
    except OSError as e:
        raise _container_error(e, name, name) from None
    key_guid = foot[:16]
    encrypted = foot[16] != 0
    magic, version = struct.unpack_from('<Ii', foot, 17)
    if magic != _PAK_MAGIC:
        return None
    methods = tuple(
        method_name for i in range(5)
        if (method_name := foot[61 + 32 * i:61 + 32 * (i + 1)].rstrip(b'\0').decode('ascii', 'replace')))
    return PakFooter(version=version, encrypted=encrypted, key_guid=_guid_str(key_guid), compression=methods)
