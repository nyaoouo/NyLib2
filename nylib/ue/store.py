"""Output-root resolution and the on-disk snapshot store: safe names, `.partial` publish (P19/P20)."""
import dataclasses
import datetime
import json
import logging
import os
import time

from . import names
from .errors import OutputRootError
from .exports import EXPORT_SPECS, run_export
from .snapshot import SCHEMA_NAME, Snapshot

logger = logging.getLogger('nylib.ue.store')

OUT_ENV = 'NYLIB_UE_OUT'
DEFAULT_DIR = 'ue_dumps'
PROFILES_DIR = 'profiles'
LOGS_DIR = '_logs'

_RESERVED_STEMS = frozenset({'CON', 'PRN', 'AUX', 'NUL'} | {f'COM{i}' for i in range(1, 10)} | {f'LPT{i}' for i in range(1, 10)})
_RENAME_RETRIES = 10  # PermissionError retries on top of the first attempt (antivirus scanners)


def resolve_out_root(out=None, *, internal: bool = False) -> str:
    """P20: `out`, else `NYLIB_UE_OUT`, else (external only) `<cwd>/ue_dumps`."""
    if out is not None and not isinstance(out, (str, os.PathLike)):
        raise TypeError(f'out must be str or os.PathLike, got {type(out).__name__}')
    if out is not None:
        s = os.fspath(out)
        if s == '':
            raise ValueError('out must not be empty')
        return os.path.abspath(s)
    env = os.environ.get(OUT_ENV)
    if env:
        return os.path.abspath(env)
    if internal:
        cwd = os.getcwd()
        raise OutputRootError(f'inside the game the current directory is {cwd}; pass out=... or set NYLIB_UE_OUT', cwd=cwd)
    return os.path.abspath(os.path.join(os.getcwd(), DEFAULT_DIR))


def safe_dir_name(name: str) -> str:
    """A filesystem-safe folder name for `name`: invalid chars, control codes, trailing dots/spaces
    and the Windows reserved stems (CON, COM1, ...) are escaped, in that order."""
    if not isinstance(name, str):
        raise TypeError(f'name must be a str, got {type(name).__name__}')
    s = names.valid_file_name(name)
    s = ''.join('_' if ord(ch) < 0x20 else ch for ch in s)
    chars = list(s)
    i = len(chars) - 1
    while i >= 0 and chars[i] in '. ':
        chars[i] = '_'
        i -= 1
    s = ''.join(chars)
    if '.' in s:
        part, rest = s.split('.', 1)
        rest = '.' + rest
    else:
        part, rest = s, ''
    if part.rstrip(' ').upper() in _RESERVED_STEMS:
        part += '_'
    return part + rest or 'unknown'


def new_snapshot_dir(out_root, game_name: str, when: datetime.datetime) -> str:
    """Reserve `<out_root>/<safe name>/<stamp>[-N]` by creating its `.partial` dir; never a stale one."""
    if not isinstance(out_root, (str, os.PathLike)):
        raise TypeError(f'out_root must be str or os.PathLike, got {type(out_root).__name__}')
    if not isinstance(game_name, str):
        raise TypeError(f'game_name must be a str, got {type(game_name).__name__}')
    if not isinstance(when, datetime.datetime):
        raise TypeError(f'when must be a datetime.datetime, got {type(when).__name__}')
    game_dir = os.path.join(os.path.abspath(os.fspath(out_root)), safe_dir_name(game_name))
    os.makedirs(game_dir, exist_ok=True)
    stamp = when.strftime('%Y%m%d-%H%M%S')
    n = 1
    while True:
        folder = os.path.join(game_dir, stamp if n == 1 else f'{stamp}-{n}')
        partial = folder + '.partial'
        if os.path.exists(folder) or os.path.exists(partial):
            n += 1
            continue
        try:
            os.mkdir(partial)
        except FileExistsError:
            n += 1
            continue
        return folder


def _rename_with_retry(src: str, dst: str) -> None:
    delay = 0.1
    for attempt in range(_RENAME_RETRIES + 1):
        try:
            os.rename(src, dst)
            return
        except PermissionError:
            if attempt == _RENAME_RETRIES:
                raise
            time.sleep(delay)
            delay = min(delay * 2, 1.6)


def publish(folder, exports) -> tuple:
    """Export `<folder>.partial`, then rename it to `folder`; nothing is renamed if an export fails."""
    if not isinstance(folder, (str, os.PathLike)):
        raise TypeError(f'folder must be str or os.PathLike, got {type(folder).__name__}')
    if not isinstance(exports, (list, tuple)):
        raise TypeError(f'exports must be a list or tuple, got {type(exports).__name__}')
    fmts = []
    for fmt in exports:
        if not isinstance(fmt, str):
            raise TypeError(f'export format must be a str, got {type(fmt).__name__}')
        if fmt not in EXPORT_SPECS:
            raise ValueError(f'unknown export format {fmt!r}')
        fmts.append(fmt)

    folder_str = os.path.abspath(os.fspath(folder))
    partial = folder_str + '.partial'
    snap = Snapshot.load(partial, _partial=True)
    try:
        written = tuple(run_export(fmt, snap, partial) for fmt in fmts)
    except Exception:
        snap.close()
        raise
    snap.close()
    _rename_with_retry(partial, folder_str)
    # Exports were written under `.partial`; translate to their post-rename path under `folder_str`.
    return tuple(os.path.join(folder_str, os.path.relpath(p, partial)) for p in written)


@dataclasses.dataclass(frozen=True)
class SnapshotRef:
    """A completed snapshot's identity, read from `meta.json` only (no snapshot data is loaded)."""
    path: str
    created: datetime.datetime | None
    exe: str | None
    pe_timestamp: int | None
    size_of_image: int | None
    game_name: str | None
    schema_version: str


def _parse_created(value):
    if not isinstance(value, str):
        return None
    try:
        dt = datetime.datetime.fromisoformat(value)
    except ValueError:
        return None
    return dt.astimezone() if dt.tzinfo is None else dt  # naive -> taken as local time


def _parse_hex_int(value):
    if not isinstance(value, str):
        return None
    try:
        return int(value, 16)
    except ValueError:
        return None


def _str_or_none(value):
    return value if isinstance(value, str) else None


def _ref_from_meta(path: str, doc: dict, version: str) -> SnapshotRef:
    target = doc.get('target')
    target = target if isinstance(target, dict) else {}
    module = target.get('module')
    module = module if isinstance(module, dict) else {}
    return SnapshotRef(
        path=path, created=_parse_created(doc.get('created')), exe=_str_or_none(target.get('exe')),
        pe_timestamp=_parse_hex_int(module.get('pe_timestamp')), size_of_image=_parse_hex_int(module.get('size')),
        game_name=_str_or_none(target.get('game_name')), schema_version=version)


def find_snapshots(out_root, *, exe=None, pe_timestamp=None, size_of_image=None) -> list:
    """Completed snapshots under `out_root` (never a `.partial` one), newest `created` first."""
    if exe is not None and not isinstance(exe, str):
        raise TypeError(f'exe must be a str or None, got {type(exe).__name__}')
    for value, label in ((pe_timestamp, 'pe_timestamp'), (size_of_image, 'size_of_image')):
        if value is not None and (not isinstance(value, int) or isinstance(value, bool)):
            raise TypeError(f'{label} must be an int or None, got {type(value).__name__}')

    root = os.fspath(out_root)
    if not os.path.isdir(root):
        return []
    refs = []
    for g in sorted(os.listdir(root)):
        gpath = os.path.join(root, g)
        if g.startswith('_') or g.casefold() == PROFILES_DIR.casefold() or not os.path.isdir(gpath):
            continue
        for s in sorted(os.listdir(gpath)):
            if s.lower().endswith('.partial'):
                continue
            spath = os.path.join(gpath, s)
            if not os.path.isdir(spath):
                continue
            meta_path = os.path.join(spath, 'meta.json')
            try:
                with open(meta_path, 'rb') as f:
                    raw = f.read()
            except OSError:
                continue
            try:
                doc = json.loads(raw.decode('utf-8'))
            except (UnicodeDecodeError, ValueError):
                logger.warning('skipping %s: not utf-8 json', meta_path)
                continue
            schema = doc.get('schema') if isinstance(doc, dict) else None
            if not isinstance(schema, dict) or schema.get('name') != SCHEMA_NAME:
                logger.debug('skipping %s: not an %s document', meta_path, SCHEMA_NAME)
                continue
            version = schema.get('version')
            if not isinstance(version, str):
                logger.debug('skipping %s: missing schema version', meta_path)
                continue
            ref = _ref_from_meta(os.path.abspath(spath), doc, version)
            if exe is not None and (ref.exe is None or ref.exe.casefold() != exe.casefold()):
                continue
            if pe_timestamp is not None and ref.pe_timestamp != pe_timestamp:
                continue
            if size_of_image is not None and ref.size_of_image != size_of_image:
                continue
            refs.append(ref)

    refs.sort(key=lambda r: r.path, reverse=True)
    refs.sort(key=lambda r: (r.created is None, -r.created.timestamp() if r.created is not None else 0.0))
    return refs
