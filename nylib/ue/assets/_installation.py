"""open_installation, Installation and Texture: the read-only nylib.ue.assets facade over one game's IoStore containers."""
import fnmatch
import hashlib
import logging
import operator
import os
import re
import string
import struct
import threading
import time
import warnings
from collections import OrderedDict
from collections.abc import Callable
from typing import Literal

from nylib.utils import oodle
from nylib.utils.oodle import OodleError
from ..errors import (
    AmbiguousNameError, AssetError, BuildMismatchError, CorruptAssetError, InstallationClosedError, InvalidKeyError,
    MissingAssetError, ReadCancelledError, RegionOutOfBoundsError, UnsupportedAssetError, UnsupportedContainerError,
)
from . import _iostore, _pe, _texture, _usmap
from ._bcrypt import Aes256Ecb
from ._hashes import package_id
from ._iostore import Container, Toc, check_key, iter_directory_index, read_directory_index
from ._keys import AesKey, _check_path
from ._records import BuildInfo, ContainerInfo, PackageInfo, ReadStats, Region, _Counters
from ._zen import MAX_PACKAGE_CHUNK, Reader, ScriptObjects, ZenHeader, _SUMMARY_SIZE, _load_name_batch, _local_name, \
    check_package_chunk_size

_log = logging.getLogger('nylib.ue.assets')

_ENGINES = ('5.7',)
_DEFAULT_CACHE_BYTES = 4 << 20
_IDENTITY_TAG = b'nylib.ue.assets identity'
_DECODE_RULES_VERSION = 1  # raise whenever any decoded output can change
_EXPORT_BUNDLE_DATA, _BULK_DATA, _SCRIPT_OBJECTS = _texture.EXPORT_BUNDLE_DATA, _texture.BULK_DATA, 5
_NAMES_START = _SUMMARY_SIZE + 8  # the summary, then the two VERSE_CELLS offsets
_MISSING_POLICIES = ('raise', 'transparent', 'fallback')
_LOWER = str.maketrans(string.ascii_uppercase, string.ascii_lowercase)
_PAK_REASON = 'legacy .pak is not read by this nylib version'
_CLOSED = 'the installation is closed'
_AES_KEY_STR = ('aes_key takes an AesKey, bytes or a list of AesKey; for a hex string or a key file use '
                'AesKey.from_hex() or AesKey.from_file()')
_NAME_FORMS = 'a package name, an object path, or an Engine/Content or <project>/Content asset path'
_MAX_PATH = 1024  # UE's name length limit; longer directory-index paths are not listed
_BAD_PATH_CHAR = re.compile('[\x00-\x1f\x7f-\x9f\u2028\u2029\ud800-\udfff]')  # a lone surrogate is an undecodable index byte
_GLOBAL = 'global.utoc'


def _lower(s: str) -> str:
    return s.translate(_LOWER)


def _int_arg(value, name: str) -> int:
    if isinstance(value, bool):
        raise TypeError(f'{name} must be an int, not bool')
    try:
        return operator.index(value)
    except TypeError:
        raise TypeError(f'{name} must be an int, got {type(value).__name__}') from None


def _keys_arg(aes_key) -> dict:
    """The keys of `aes_key` by GUID."""
    if aes_key is None:
        keys = []
    elif isinstance(aes_key, AesKey):
        keys = [aes_key]
    elif isinstance(aes_key, str):
        raise TypeError(_AES_KEY_STR)
    elif isinstance(aes_key, (bytes, bytearray, memoryview)):
        keys = [AesKey(aes_key)]
    elif isinstance(aes_key, (list, tuple)):
        if not all(isinstance(k, AesKey) for k in aes_key):
            raise TypeError('every item of an aes_key list or tuple must be an AesKey')
        keys = aes_key
    else:
        raise TypeError(f'aes_key takes an AesKey, bytes or a list of AesKey, got {type(aes_key).__name__}')
    by_guid = {}
    for k in keys:
        if k.guid in by_guid:
            raise ValueError(f'two aes_key entries have guid {k.guid}')
        by_guid[k.guid] = k
    return by_guid


def _annotate(e: AssetError, package, container) -> None:
    """Fill in `package` and `container` where the raising module could not know them."""
    if e.package is None:
        e.package = package
    if e.container is None:
        e.container = container


def _script_error(e: CorruptAssetError, container: str) -> CorruptAssetError:
    """`e` from the global ScriptObjects chunk, re-located at that chunk."""
    return CorruptAssetError(f'{container} chunk {0:016x} (ScriptObjects): {e.detail}', container=container, detail=e.detail)


def _asset_package(path: str, project: str | None) -> str | None:
    """The package of an asset path 'Engine/Content/...' or '<project>/Content/...' ending in .uasset or .umap, else None."""
    if not _lower(path).endswith(('.uasset', '.umap')):
        return None
    segs = path.split('/')
    if len(segs) < 3 or _lower(segs[1]) != 'content':
        return None
    rest = '/'.join(segs[2:])
    rest = rest[:rest.rindex('.')]
    root = _lower(segs[0])
    if root == 'engine':
        return '/Engine/' + rest
    if project is not None and root == _lower(project):
        return '/Game/' + rest
    return None


def _plugin_dir(path: str, project: str | None) -> tuple | None:
    """(directory key, dk, rest without extension) for a path under '<root>/Plugins/<d1>/.../<dk>/Content/...', else None.

    `root` must be 'Engine' or `project` (ASCII-case-insensitive); the directory key is the directory's
    path up to and including Content, ASCII-lower-cased.
    """
    if not _lower(path).endswith(('.uasset', '.umap')):
        return None
    segs = path.split('/')
    if len(segs) < 4 or _lower(segs[1]) != 'plugins':
        return None
    root = _lower(segs[0])
    if root != 'engine' and (project is None or root != _lower(project)):
        return None
    for i in range(3, len(segs)):
        if _lower(segs[i]) == 'content':
            rest = '/'.join(segs[i + 1:])
            rest = rest[:rest.rindex('.')]
            if not rest:
                return None
            return _lower('/'.join(segs[:i + 1])), segs[i - 1], rest
    return None


def _find_exe(paks: str) -> str | None:
    """The unique *-Win64-Shipping.exe in paks/../../Binaries/Win64, else None."""
    bindir = os.path.join(os.path.dirname(os.path.dirname(paks)), 'Binaries', 'Win64')
    try:
        with os.scandir(bindir) as it:
            found = [e.path for e in it if _lower(e.name).endswith('-win64-shipping.exe') and e.is_file()]
    except OSError:
        return None
    return found[0] if len(found) == 1 else None


def _read_build(paks: str, exe: str | None, build: int | None, usmap_name: str) -> BuildInfo | None:
    """The exe's BuildInfo, checked against `build` when it is an int; exe problems raise only then."""
    path = exe if exe is not None else _find_exe(paks)
    if path is None:
        if build is None:
            return None
        raise BuildMismatchError(f'no unique *-Win64-Shipping.exe found for build {build:#010x}: pass exe=',
                                 expected=build, usmap=usmap_name)
    name = os.path.basename(path)
    try:
        stamp, version = _pe.read_build(path)
    except (OSError, ValueError) as e:
        if build is None:
            return None
        errno, winerror = (e.errno, e.winerror) if isinstance(e, OSError) else (None, None)
        raise BuildMismatchError(f'{name} is not a readable PE image: cannot check build {build:#010x}', expected=build,
                                 exe=name, path=path, usmap=usmap_name, errno=errno, winerror=winerror) from None
    if build is not None and stamp != build:
        raise BuildMismatchError(f'{name} is build {stamp:#010x}, expected {build:#010x}: create and verify a .usmap for this build',
                                 expected=build, found=stamp, exe=name, path=path, usmap=usmap_name)
    return BuildInfo(exe=name, stamp=stamp, version=version, path=path)


def _scan(paks: str) -> tuple:
    """(.utoc paths, .pak paths) at the top level of `paks`, each sorted by (ASCII-lower(file), file)."""
    try:
        with os.scandir(paks) as it:
            found = [(e.name, e.path) for e in it if _lower(e.name).endswith(('.utoc', '.pak')) and e.is_file()]
    except OSError as e:
        raise MissingAssetError(f'paks directory {os.path.basename(paks)} cannot be read', path=paks,
                                errno=e.errno, winerror=e.winerror) from None
    found.sort(key=lambda f: (_lower(f[0]), f[0]))
    utocs = [p for n, p in found if _lower(n).endswith('.utoc')]
    paks_ = [p for n, p in found if _lower(n).endswith('.pak')]
    return utocs, paks_


def _check_oodle(container: str) -> None:
    try:
        getattr(oodle.dll('core'), 'OodleLZ_Decompress')
    except OodleError as e:
        raise UnsupportedContainerError(f'{container} needs Oodle, which is unavailable: {e}', feature='Oodle',
                                        container=container) from e
    except AttributeError as e:
        raise UnsupportedContainerError(f'{container} needs Oodle, which is unavailable: the core DLL does not export '
                                        'OodleLZ_Decompress', feature='Oodle', container=container) from e


def _pak_row(path: str) -> ContainerInfo:
    name = os.path.basename(path)
    try:
        foot = _iostore.read_pak_footer(path)
    except CorruptAssetError:
        return ContainerInfo(file=name, kind='pak', mounted=False, version=0, compression=(), encrypted=False, chunks=None,
                             reason='the .pak file cannot be read')
    if foot is None:
        return ContainerInfo(file=name, kind='pak', mounted=False, version=0, compression=(), encrypted=False, chunks=None,
                             reason='not a recognised .pak file')
    return ContainerInfo(file=name, kind='pak', mounted=False, version=foot.version, compression=foot.compression,
                         encrypted=foot.encrypted, chunks=None, reason=_PAK_REASON)


def _identity(engine: str, usmap_sha256: bytes, tocs) -> str:
    def f(b: bytes) -> bytes:
        return len(b).to_bytes(8, 'little') + b

    h = hashlib.sha256(f(_IDENTITY_TAG) + _DECODE_RULES_VERSION.to_bytes(4, 'little') + f(engine.encode('ascii'))
                       + usmap_sha256 + len(tocs).to_bytes(4, 'little'))
    for toc in tocs:
        h.update(toc.digest)
    return h.hexdigest()[:16]


def open_installation(paks_dir: str | os.PathLike, *, engine: str, usmap: str | os.PathLike, build: int | None,
                      aes_key: 'AesKey | bytes | bytearray | Sequence[AesKey] | None' = None,
                      exe: str | os.PathLike | None = None,
                      cache_bytes: int | None = None) -> 'Installation':
    """Open the IoStore containers of an installed UE 5.7 game, read-only.

    Checks the build (when `build` is an int) before any container is read; a failure releases everything opened.
    """
    paks = _check_path(paks_dir, 'paks_dir')
    if not isinstance(engine, str):
        raise TypeError(f'engine must be a str, got {type(engine).__name__}')
    if engine not in _ENGINES:
        raise ValueError(f'engine must be one of {_ENGINES}')
    usmap_path = _check_path(usmap, 'usmap')
    if build is not None:
        build = _int_arg(build, 'build')
        if not 0 <= build <= 0xFFFFFFFF:
            raise ValueError('build must be in 0..0xFFFFFFFF')
    keys = _keys_arg(aes_key)
    exe_path = None if exe is None else _check_path(exe, 'exe')
    if cache_bytes is None:
        cache_bytes = _DEFAULT_CACHE_BYTES
    else:
        cache_bytes = _int_arg(cache_bytes, 'cache_bytes')
        if cache_bytes < 0:
            raise ValueError('cache_bytes must be >= 0')

    t0 = time.perf_counter()
    paks_name = os.path.basename(paks)
    if not os.path.isdir(paks):
        raise MissingAssetError(f'paks directory {paks_name!r} not found', path=paks)
    usmap_name = os.path.basename(usmap_path)
    build_info = _read_build(paks, exe_path, build, usmap_name)
    mappings, usmap_sha256 = _usmap.read(usmap_path)
    utocs, pak_paths = _scan(paks)
    if not utocs:
        raise MissingAssetError(f'no IoStore container (.utoc) in paks directory {paks_name!r}', path=paks)

    counters = _Counters()
    mounted = []
    decryptors = {}
    try:
        for path in utocs:
            toc = Toc.read(path, counters)
            aes = None
            if toc.encrypted:
                key = keys.get(toc.key_guid)
                if key is None:
                    raise InvalidKeyError(f'{toc.basename} is encrypted with key guid {toc.key_guid}; no aes_key has that guid',
                                          key_guid=toc.key_guid, container=toc.basename)
                t = time.perf_counter()
                check_key(toc, key)
                if (aes := decryptors.get(key.guid)) is None:
                    aes = decryptors[key.guid] = Aes256Ecb(key)
                counters.seconds_aes += time.perf_counter() - t
            mounted.append((toc, aes))
            _log.debug('container %s: version %d, flags %#x, %d chunks', toc.basename, toc.version, toc.flags, toc.entry_count)
        if (first := next((toc for toc, _aes in mounted if toc.used_methods()), None)) is not None:
            _check_oodle(first.basename)
        rows = [ContainerInfo(file=toc.basename, kind='iostore', mounted=True, version=toc.version,
                              compression=toc.used_methods(), encrypted=toc.encrypted, chunks=toc.entry_count, reason=None)
                for toc, _aes in mounted]
        rows += [_pak_row(p) for p in pak_paths]
        rows.sort(key=lambda r: (_lower(r.file), r.file))
        identity = _identity(engine, usmap_sha256, [toc for toc, _aes in mounted])
    except BaseException:
        for aes in decryptors.values():
            aes.close()
        raise

    parent = os.path.dirname(paks)
    project = os.path.basename(os.path.dirname(parent)) if _lower(os.path.basename(parent)) == 'content' else None
    counters.seconds = time.perf_counter() - t0
    inst = object.__new__(Installation)
    inst._init(engine=engine, build=build_info, checked=build is not None, identity=identity, containers=tuple(rows),
               usmap_name=usmap_name, mappings=mappings, mounted=mounted, decryptors=tuple(decryptors.values()),
               cache_bytes=cache_bytes, project=project, pak_count=len(pak_paths), totals=counters)
    _log.debug('opened %s: engine %s, %d iostore mounted, %d pak not mounted, usmap %s, identity %s', paks_name, engine,
               len(mounted), len(pak_paths), usmap_name, identity)
    return inst


class _BlockCache:
    """The shared decompressed-block cache: LRU, bounded by the summed bytes of its blocks."""

    def __init__(self, cap: int):
        self._cap = cap
        self._lock = threading.Lock()
        self._blocks = OrderedDict()
        self._size = 0

    def get(self, key):
        with self._lock:
            data = self._blocks.get(key)
            if data is not None:
                self._blocks.move_to_end(key)
            return data

    def __setitem__(self, key, data) -> None:
        n = len(data)
        if n > self._cap:
            return
        with self._lock:
            if (old := self._blocks.pop(key, None)) is not None:
                self._size -= len(old)
            self._blocks[key] = data
            self._size += n
            while self._size > self._cap:
                _key, dropped = self._blocks.popitem(last=False)
                self._size -= len(dropped)

    def clear(self) -> None:
        with self._lock:
            self._blocks.clear()
            self._size = 0


class _Op:
    """One operation: registered with the close state on entry; its counters join the totals once, on exit."""
    __slots__ = ('_inst', 'counters', '_record', '_t0', '_done')

    def __init__(self, inst: 'Installation', record: bool, reads: int):
        self._inst = inst
        self._record = record
        self.counters = _Counters()
        self.counters.reads = reads
        self._done = False

    def __enter__(self) -> '_Op':
        self._inst._enter()
        self._t0 = time.perf_counter()
        return self

    def finish(self) -> None:
        self.counters.seconds = time.perf_counter() - self._t0
        self._done = True

    def __exit__(self, *exc) -> None:
        if not self._done:
            self.finish()
        self._inst._exit(self.counters if self._record else None)


class Installation:
    """One game installation's mounted IoStore containers; made only by open_installation, closed by close() or `with`.

    Every method is thread-safe; close() waits for reads on other threads and never for the caller's own read.
    """

    def __new__(cls, *args, **kwargs):
        raise TypeError('Installation cannot be constructed directly: call open_installation()')

    def _init(self, *, engine, build, checked, identity, containers, usmap_name, mappings, mounted, decryptors,
              cache_bytes, project, pak_count, totals):
        self._engine = engine
        self._build = build
        self._checked = checked
        self._identity = identity
        self._containers = containers
        self._usmap_name = usmap_name
        self._mappings = mappings
        self._mounted = tuple((toc, Container(toc, aes), aes) for toc, aes in mounted)
        self._mounted_count = len(mounted)
        self._decryptors = decryptors
        self._cache = _BlockCache(cache_bytes) if cache_bytes else None
        self._project = project
        self._pak_count = pak_count
        self._totals = totals
        self._state = threading.Condition(threading.Lock())  # guards the close state below and the totals
        self._closed = False
        self._active = {}  # thread ident -> operations in flight on that thread
        self._active_total = 0
        self._releasing = False
        self._released = False
        self._script_lock = threading.Lock()
        self._script = None  # (ScriptObjects, Texture2D global index or None)
        self._listing_lock = threading.Lock()
        self._listing = None  # [(package name, mounted index, TOC index)], sorted

    engine = property(lambda self: self._engine)
    build = property(lambda self: self._build)
    identity = property(lambda self: self._identity)
    containers = property(lambda self: self._containers)
    closed = property(lambda self: self._closed)

    def __repr__(self) -> str:
        if self._build is None:
            build = 'unknown'
        else:
            build = f"{self._build.stamp:#010x} ({'checked' if self._checked else 'unchecked'})"
        closed = ' closed' if self._closed else ''
        return (f'<Installation engine={self._engine} build={build} iostore={self._mounted_count} mounted, '
                f'pak={self._pak_count} not mounted, usmap={self._usmap_name}{closed}>')

    def __enter__(self) -> 'Installation':
        if self._closed:
            raise InstallationClosedError(_CLOSED)
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def __reduce_ex__(self, protocol):
        raise TypeError('Installation cannot be pickled: call open_installation in the other process')

    def __getstate__(self):
        raise TypeError('Installation cannot be pickled: call open_installation in the other process')

    def __del__(self):
        if getattr(self, '_state', None) is None or self._closed:
            return
        try:
            warnings.warn('unclosed nylib.ue.assets Installation', ResourceWarning, source=self)
        finally:
            self.close()

    # ---- close state -------------------------------------------------------------------------------------------

    def _op(self, *, record: bool = True, reads: int = 0) -> _Op:
        return _Op(self, record, reads)

    def _enter(self) -> None:
        me = threading.get_ident()
        with self._state:
            if self._closed:
                raise InstallationClosedError(_CLOSED)
            self._active[me] = self._active.get(me, 0) + 1
            self._active_total += 1

    def _exit(self, counters: _Counters | None) -> None:
        me = threading.get_ident()
        release = False
        with self._state:
            if counters is not None:
                self._totals.add(counters)
            if n := self._active[me] - 1:
                self._active[me] = n
            else:
                del self._active[me]
            self._active_total -= 1
            if not self._active_total:
                if self._closed and not self._releasing:
                    self._releasing = release = True
                self._state.notify_all()
        if release:
            self._release()

    def _check_open(self) -> None:
        if self._closed:
            raise InstallationClosedError(_CLOSED)

    def close(self) -> None:
        """Close the installation; idempotent. Returns once every handle is released, unless called inside a read."""
        me = threading.get_ident()
        with self._state:
            self._closed = True
            if self._active.get(me):
                return
            while not self._released:
                if not self._active_total and not self._releasing:
                    self._releasing = True
                    break
                self._state.wait()
            else:
                return
        self._release()

    def _release(self) -> None:
        try:
            for _toc, container, _aes in self._mounted:
                container.close()
            for aes in self._decryptors:
                aes.close()
            if self._cache is not None:
                self._cache.clear()
        finally:
            self._mounted = ()
            self._decryptors = ()
            self._script = self._listing = self._mappings = None
            with self._state:
                self._released = True
                self._state.notify_all()

    # ---- names and lookup --------------------------------------------------------------------------------------

    def _parse_name(self, name) -> tuple:
        """(package name, export name or None) of a package name, object path or asset path."""
        if not isinstance(name, str):
            raise TypeError(f'name must be a str, got {type(name).__name__}')
        if not name or '\\' in name or ':' in name or '//' in name or name.endswith('/'):
            raise ValueError(f'name must be {_NAME_FORMS}, without a backslash, colon, empty segment or trailing /')
        if name.startswith('/'):
            if _lower(name).endswith(('.uasset', '.umap')):
                return name[:name.rindex('.')], None
            last = name.rsplit('/', 1)[1]
            if '.' not in last:
                return name, None
            dot = len(name) - len(last) + last.index('.')
            export = name[dot + 1:]
            if not export or '.' in export:
                raise ValueError('the export part of an object path must be non-empty and contain no "."')
            return name[:dot], export
        if (pkg := _asset_package(name, self._project)) is not None:
            return pkg, None
        raise ValueError(f'name must be {_NAME_FORMS}; an asset-file path under a plugin root is not accepted, use the '
                         'package name list_packages() returns')

    def _locate(self, pkg: str) -> tuple:
        """(toc, container) and the TOC index of `pkg`'s ExportBundleData chunk in its one mounted container."""
        pid = package_id(pkg)
        hits = [(toc, container, idx) for toc, container, _aes in self._mounted
                if (idx := toc.find(pid, 0, _EXPORT_BUNDLE_DATA)) is not None]
        if not hits:
            raise MissingAssetError(f'package {pkg!r} is not in the {self._mounted_count} mounted IoStore containers '
                                    f'({self._pak_count} .pak files are not mounted)', package=pkg)
        if len(hits) > 1:
            names = ', '.join(toc.basename for toc, _c, _i in hits)
            raise UnsupportedContainerError(f'package {pkg!r} is in {len(hits)} containers ({names}): patch containers are '
                                            'not supported by this nylib version', feature='patch containers', package=pkg)
        return hits[0]

    @staticmethod
    def _bulk_size(toc: Toc, cid: int) -> int:
        return 0 if (i := toc.find(cid, 0, _BULK_DATA)) is None else toc.chunk_range(i)[1]

    def _recorded_name(self, toc: Toc, container: Container, idx: int, cid: int, size: int, counters) -> str:
        """The package name recorded in the zen summary, from the first block(s) of the header chunk."""
        c = toc.basename
        memo = {}

        def read(n: int) -> bytes:
            return container.read_range(idx, 0, n, memo=memo, cache=self._cache, counters=counters, checkpoint=self._check_open)

        def corrupt(detail: str) -> CorruptAssetError:
            return CorruptAssetError(f'{c} chunk {cid:016x} (ExportBundleData): {detail}', container=c, detail=detail)

        head = read(min(size, _NAMES_START))
        if len(head) < _NAMES_START:
            raise corrupt(f'the package summary needs {_NAMES_START} bytes, the chunk has {len(head)}')
        has_versioning, header_size, n0, n1 = struct.unpack_from('<IIII', head)
        if has_versioning:
            raise UnsupportedAssetError('a versioned zen package is not supported by this nylib version',
                                        feature='versioned zen package')
        if not _NAMES_START <= header_size <= size:
            raise corrupt(f'the header size {header_size} is outside the {size}-byte chunk')
        if header_size > MAX_PACKAGE_CHUNK:
            raise corrupt(f'the package header of {header_size} bytes exceeds the {MAX_PACKAGE_CHUNK}-byte limit')
        try:
            return _local_name(n0, n1, _load_name_batch(Reader(read(header_size), _NAMES_START)))
        except ValueError as e:
            raise corrupt(str(e)) from None

    # ---- public methods ----------------------------------------------------------------------------------------

    def has_package(self, name: str) -> bool:
        """True iff the package is in a mounted container; reads no container data."""
        pkg, _export = self._parse_name(name)
        with self._op(record=False):
            pid = package_id(pkg)
            return any(toc.find(pid, 0, _EXPORT_BUNDLE_DATA) is not None for toc, _c, _a in self._mounted)

    def package(self, name: str) -> PackageInfo:
        """The package's PackageInfo, its name as the package records it."""
        pkg, _export = self._parse_name(name)
        with self._op() as op:
            c = None
            try:
                toc, container, idx = self._locate(pkg)
                c = toc.basename
                cid = toc.chunk_fields(idx)[0]
                size = toc.chunk_range(idx)[1]
                recorded = self._recorded_name(toc, container, idx, cid, size, op.counters)
                return PackageInfo(name=recorded, container=c, size=size, bulk_size=self._bulk_size(toc, cid), package_id=cid)
            except AssetError as e:
                _annotate(e, pkg, c)
                raise

    def list_packages(self, prefix: str = '/', *, match: str | None = None) -> list[PackageInfo]:
        """Packages whose name starts with `prefix` and fnmatches `match`, both ASCII-case-insensitive; a new sorted list."""
        if not isinstance(prefix, str):
            raise TypeError(f'prefix must be a str, got {type(prefix).__name__}')
        if match is not None and not isinstance(match, str):
            raise TypeError(f'match must be a str or None, got {type(match).__name__}')
        with self._op() as op:
            with self._listing_lock:
                if self._listing is None:
                    self._listing = self._build_listing(op.counters)
                listing = self._listing
            low_prefix = _lower(prefix)
            low_match = None if match is None else _lower(match)
            out = []
            for name, mi, idx in listing:
                low = _lower(name)
                if not low.startswith(low_prefix) or (low_match is not None and not fnmatch.fnmatchcase(low, low_match)):
                    continue
                toc = self._mounted[mi][0]
                try:
                    cid = toc.chunk_fields(idx)[0]
                    out.append(PackageInfo(name=name, container=toc.basename, size=toc.chunk_range(idx)[1],
                                           bulk_size=self._bulk_size(toc, cid), package_id=cid))
                except AssetError as e:
                    _annotate(e, name, toc.basename)
                    raise
            return out

    def _build_listing(self, counters) -> list:
        entries = []
        dropped = skipped = learning_reads = failed_learning = 0
        learned = {}  # plugin directory key -> learned mount, once a learning read (success or not) has run
        for mi, (toc, container, aes) in enumerate(self._mounted):
            self._check_open()
            if not toc.indexed or not toc.dir_index_size:
                continue
            raw = toc.dir_index_raw
            if toc.encrypted:
                t = time.perf_counter()
                raw = aes.decrypt(raw)
                counters.seconds_aes += time.perf_counter() - t
            index = read_directory_index(raw, toc.basename)
            del raw
            seen = bytearray(toc.entry_count)
            for path, idx in iter_directory_index(index, toc.basename, toc.entry_count, max_len=_MAX_PATH,
                                                  checkpoint=self._check_open):
                if path is None or _BAD_PATH_CHAR.search(path):
                    skipped += 1
                    continue
                cid, chunk_index, extra, chunk_type = toc.chunk_fields(idx)
                if chunk_index or extra or chunk_type != _EXPORT_BUNDLE_DATA:
                    continue
                if path.startswith('../../../'):
                    path = path[9:]
                if _lower(path).endswith(('.o.uasset', '.o.umap')):
                    continue
                if (pkg := _asset_package(path, self._project)) is not None:
                    if seen[idx]:  # the first entry to reach the hash claims its TOC entry; later ones are not hashed
                        skipped += 1
                        continue
                    seen[idx] = 1
                    if package_id(pkg) != cid:
                        dropped += 1
                        continue
                    entries.append((pkg, mi, idx))
                    continue
                if (plugin := _plugin_dir(path, self._project)) is None:
                    continue
                key, dk, rest = plugin
                if seen[idx]:
                    skipped += 1
                    continue
                seen[idx] = 1
                dk_name = f'/{dk}/{rest}'
                if package_id(dk_name) == cid:  # the entry matches its folder name
                    entries.append((dk_name, mi, idx))
                    continue
                if key not in learned:  # this directory's one learning read, from its first miss
                    learning_reads += 1
                    try:
                        size = toc.chunk_range(idx)[1]
                        recorded = self._recorded_name(toc, container, idx, cid, size, counters)
                    except (CorruptAssetError, UnsupportedAssetError) as err:
                        if isinstance(err, CorruptAssetError) and (err.errno is not None or err.winerror is not None):
                            raise  # a container-file I/O error: never cache a transient failure into the listing
                        failed_learning += 1
                        learned[key] = None
                    else:
                        mount, _sep, remainder = recorded.lstrip('/').partition('/')
                        learned[key] = mount if (_lower(remainder) == _lower(rest)
                                                 and package_id(f'/{mount}/{rest}') == cid) else None
                mount = learned.get(key)
                if mount is not None and package_id(mount_name := f'/{mount}/{rest}') == cid:  # the learned mount matches
                    entries.append((mount_name, mi, idx))
                    continue
                dropped += 1
        entries.sort(key=lambda e: (_lower(e[0]), e[0], self._mounted[e[1]][0].basename))
        _log.debug('list_packages: %d packages listed, %d entries dropped (name hash differs from chunk id), %d entries skipped '
                   '(path over %d characters, a control character or undecodable byte, or a repeat TOC entry), %d plugin-root '
                   'learning reads (%d failed)', len(entries), dropped, skipped, _MAX_PATH, learning_reads, failed_learning)
        return entries

    def _read_header(self, toc: Toc, container: Container, idx: int, counters) -> ZenHeader:
        cid = toc.chunk_fields(idx)[0]
        length = toc.chunk_range(idx)[1]
        check_package_chunk_size(length, toc.basename, cid)
        data = container.read_range(idx, 0, length, cache=self._cache, counters=counters, checkpoint=self._check_open)
        try:
            return ZenHeader(data)
        except CorruptAssetError as e:
            if e.package is not None:
                raise
            # before the package name is parsed, ZenHeader has no location to put in the message; add package()'s.
            raise CorruptAssetError(f'{toc.basename} chunk {cid:016x} (ExportBundleData): {e.detail}',
                                    container=toc.basename, detail=e.detail) from None

    def _script_objects(self, counters) -> tuple:
        """(ScriptObjects, the Texture2D global index or None, its container), loaded once from global.utoc."""
        with self._script_lock:
            if self._script is None:
                self._script = self._load_script_objects(counters)
            return self._script

    def _load_script_objects(self, counters) -> tuple:
        found = next(((toc, container) for toc, container, _aes in self._mounted if _lower(toc.basename) == _GLOBAL), None)
        idx = None if found is None else found[0].find(0, 0, _SCRIPT_OBJECTS)
        if idx is None:
            raise UnsupportedContainerError('no mounted container holds the global ScriptObjects chunk, which texture() needs',
                                            feature='global ScriptObjects', container=_GLOBAL if found is None else found[0].basename)
        toc, container = found
        try:
            length = toc.chunk_range(idx)[1]
            if length > MAX_PACKAGE_CHUNK:
                detail = f'ScriptObjects chunk of {length} bytes exceeds the {MAX_PACKAGE_CHUNK}-byte limit'
                raise CorruptAssetError(f'{toc.basename} chunk {0:016x} (ScriptObjects): {detail}', detail=detail)
            data = container.read_range(idx, 0, length, counters=counters, checkpoint=self._check_open)
            try:
                script = ScriptObjects(data)
                texture2d = script.index_of('/Script/Engine.Texture2D')
            except CorruptAssetError as e:
                raise _script_error(e, toc.basename) from None
        except AssetError as e:
            _annotate(e, None, toc.basename)
            raise
        _log.debug('ScriptObjects loaded: %d entries, %d bytes', script._count, length)
        return script, texture2d, toc.basename

    @staticmethod
    def _select_export(header: ZenHeader, script: tuple, pkg: str, export) -> int:
        """The index of the export to read; `script` is what _script_objects() returns."""
        table, texture2d, script_container = script

        def class_name(index):
            try:
                return table.class_name(index)
            except CorruptAssetError as e:
                raise _script_error(e, script_container) from None
            except AssetError as e:
                _annotate(e, None, script_container)
                raise
        exports = header.exports
        if export is not None:
            want = _lower(export)
            i = next((i for i, e in enumerate(exports) if _lower(e.name) == want), None)
            if i is None:
                raise MissingAssetError(f'package {pkg!r} has no export {export!r}', package=pkg, export=export)
            e = exports[i]
            if e.cls != texture2d:
                cls = class_name(e.cls)
                what = f'a {cls}' if cls is not None else 'of a class from another package'
                raise UnsupportedAssetError(f'export {export!r} of package {pkg!r} is {what}, not a Texture2D',
                                            feature='class', exports=((e.name, cls),))
            return i
        found = [i for i, e in enumerate(exports) if e.cls == texture2d]
        if len(found) == 1:
            return found[0]
        if not found:
            pairs = tuple((e.name, class_name(e.cls)) for e in exports)
            text = ', '.join(f"{n} ({c if c is not None else 'a class from another package'})" for n, c in pairs[:8])
            raise UnsupportedAssetError(f"package {pkg!r} has no Texture2D export (exports: {text}{', ...' if len(pairs) > 8 else ''})",
                                        feature='class', exports=pairs)
        names = tuple(exports[i].name for i in found)
        text = ', '.join(names[:8]) + (', ...' if len(names) > 8 else '')
        raise AmbiguousNameError(f'package {pkg!r} has {len(names)} Texture2D exports ({text}): name one as {pkg}.<export>',
                                 package=pkg, exports=names)

    def texture(self, name: str) -> 'Texture':
        """A new Texture for the package's Texture2D export (the named one, or its only one)."""
        pkg, export = self._parse_name(name)
        with self._op() as op:
            c = None
            try:
                toc, container, idx = self._locate(pkg)
                c = toc.basename
                header = self._read_header(toc, container, idx, op.counters)
                pkg = header.name
                ei = self._select_export(header, self._script_objects(op.counters), pkg, export)
                cid = toc.chunk_fields(idx)[0]
                bulk = toc.find(cid, 0, _BULK_DATA)
                bulk_length = 0 if bulk is None else toc.chunk_range(bulk)[1]
                info, layout, unreadable = _texture.parse_texture2d(header, ei, self._mappings, bulk_length)
            except AssetError as e:
                _annotate(e, pkg, c)
                raise
            mi = next(i for i, m in enumerate(self._mounted) if m[1] is container)  # inside the operation: not yet released
        return Texture._new(self, info, layout, unreadable, mi, c, idx, bulk)

    def stats(self) -> ReadStats:
        """The totals since open: open itself and every operation that has ended."""
        with self._state:
            if self._closed:
                raise InstallationClosedError(_CLOSED)
            return self._totals.snapshot()


def _rect(info, mip: int, x: int, y: int, width: int, height: int, clip: bool) -> tuple:
    """The rectangle to read at `mip`, clipped when `clip`; raises RegionOutOfBoundsError."""
    pkg = info.package
    n = len(info.mips)
    if not 0 <= mip < n:
        raise RegionOutOfBoundsError(f'mip {mip} is out of range: {pkg} has {n} mips (0..{n - 1})', mip=mip,
                                     rect=(x, y, width, height), size=n)
    w_m, h_m = info.mips[mip]
    x0, y0, x1, y1 = x, y, x + width, y + height
    if clip:
        x0, y0, x1, y1 = max(x0, 0), max(y0, 0), min(x1, w_m), min(y1, h_m)
        ok = width >= 1 and height >= 1 and x0 < x1 and y0 < y1
    else:
        ok = 0 <= x and 0 <= y and width >= 1 and height >= 1 and x1 <= w_m and y1 <= h_m
    if not ok:
        raise RegionOutOfBoundsError(f'region x={x} y={y} {width}x{height} is outside mip {mip} ({w_m}x{h_m}) of {pkg}',
                                     mip=mip, rect=(x, y, width, height), size=(w_m, h_m))
    return x0, y0, x1 - x0, y1 - y0


class Texture:
    """One Texture2D export of an Installation; it keeps the installation alive and needs no closing."""

    def __new__(cls, *args, **kwargs):
        raise TypeError('Texture cannot be constructed directly: call Installation.texture()')

    @classmethod
    def _new(cls, inst: Installation, info, layout, unreadable, mi: int, container: str, header: int,
             bulk: int | None) -> 'Texture':
        self = object.__new__(cls)
        self._inst = inst
        self._info = info
        self._layout = layout
        self._unreadable = unreadable
        self._mi = mi  # an index into inst._mounted, so that after close() no Container or Toc stays reachable
        self._container = container
        self._header = header
        self._bulk = bulk
        return self

    info = property(lambda self: self._info)

    def __reduce_ex__(self, protocol):
        raise TypeError('Texture cannot be pickled: call open_installation in the other process')

    def __getstate__(self):
        raise TypeError('Texture cannot be pickled: call open_installation in the other process')

    def read_region(self, mip: int, x: int, y: int, width: int, height: int, *,
                    clip: bool = False,
                    missing: Literal['raise', 'transparent', 'fallback'] = 'raise',
                    out: bytearray | memoryview | None = None,
                    cancel: Callable[[], bool] | None = None) -> Region:
        """RGBA8 pixels of a rectangle of mip `mip`, rows top to bottom, VT borders cropped."""
        mip, x, y, width, height = (_int_arg(v, n) for v, n in ((mip, 'mip'), (x, 'x'), (y, 'y'), (width, 'width'), (height, 'height')))
        if not isinstance(clip, bool):
            raise TypeError(f'clip must be a bool, got {type(clip).__name__}')
        if not isinstance(missing, str):
            raise TypeError(f'missing must be a str, got {type(missing).__name__}')
        if missing not in _MISSING_POLICIES:
            raise ValueError(f'missing must be one of {_MISSING_POLICIES}')
        out_bytes = None
        if out is not None:
            try:
                view = memoryview(out)
            except TypeError:
                raise TypeError(f'out must be a writable bytes-like object, got {type(out).__name__}') from None
            with view:
                if view.readonly:
                    raise TypeError('out must be writable')
                if not view.c_contiguous:
                    raise ValueError('out must be C-contiguous')
                out_bytes = view.nbytes
        if cancel is not None and not callable(cancel):
            raise TypeError(f'cancel must be callable or None, got {type(cancel).__name__}')

        inst = self._inst
        info = self._info
        pkg = info.package
        with inst._op(reads=1) as op:
            counters = op.counters
            try:
                if self._unreadable is not None:
                    cls, details = self._unreadable
                    raise cls(f'{pkg}: {info.unsupported}', **details)
                rect = _rect(info, mip, x, y, width, height, clip)
                n = rect[2] * rect[3] * 4
                if out_bytes is not None and out_bytes < n:
                    raise ValueError(f'out holds {out_bytes} bytes, the region needs {n}')
                container = inst._mounted[self._mi][1]
                layout = self._layout
                if isinstance(layout, _texture.OrdinaryLayout):
                    idx = self._bulk if layout.sources[mip][0] == _texture.BULK_DATA else self._header
                    pixels, filled = _texture.assemble_rows(layout, mip, rect, out=out,
                                                            chunk_start=container.toc.chunk_range(idx)[0],
                                                            block_size=container.toc.block_size,
                                                            fetch=self._fetcher(container, counters, idx),
                                                            checkpoint=self._checkpoint(mip, cancel, 'blocks'), counters=counters)
                else:
                    pixels, filled = _texture.assemble(layout, mip, rect, missing=missing, out=out,
                                                       fetch=self._fetcher(container, counters, self._bulk),
                                                       checkpoint=self._checkpoint(mip, cancel, 'tiles'), counters=counters)
            except AssetError as e:
                _annotate(e, pkg, self._container)
                raise
            op.finish()
            stats = counters.snapshot()
        return Region(pixels=pixels, mip=mip, x=rect[0], y=rect[1], width=rect[2], height=rect[3], missing=filled, stats=stats)

    def _fetcher(self, container: Container, counters, idx: int):
        """fetch(offset, length) in chunk `idx`: drops the memo's blocks below the range's first, then reads the range."""
        inst = self._inst
        block_size = container.toc.block_size
        memo = {}

        def fetch(offset: int, length: int) -> bytes:
            first = (container.toc.chunk_range(idx)[0] + offset) // block_size
            for key in [k for k in memo if k[1] < first]:
                del memo[key]
            return container.read_range(idx, offset, length, memo=memo, cache=inst._cache, counters=counters,
                                        checkpoint=inst._check_open)
        return fetch

    def _checkpoint(self, mip: int, cancel, unit: str):
        """checkpoint(k, n) for assemble and assemble_rows: the closed check, then `cancel`; `unit` names what n counts."""
        inst = self._inst
        pkg = self._info.package

        def checkpoint(k: int, n: int) -> None:
            if inst._closed:
                raise InstallationClosedError(_CLOSED)
            if cancel is not None and cancel():
                raise ReadCancelledError(f'read of {pkg} mip {mip} cancelled after {k} of {n} {unit}')
        return checkpoint
