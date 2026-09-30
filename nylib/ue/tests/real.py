"""Session discovery and per-session checks over real-target captures.

Offline test support: reads session.json, loaded captures and oracle files under
NYLIB_UE_CAPTURES. No live memory access, no process launch (the capture harness owns that).
"""
import dataclasses
import hashlib
import json
import ntpath
import os
import pathlib
import re

from ..capture import ImageSource
from ..pe import PeImage
from .oracle import GObjectsDump, parse_gobjects_dump

KNOWN_TARGETS = ('pal', 'ts', 'fb')
TARGET_APPIDS = {'pal': 2394010, 'ts': 1850510, 'fb': 3649580}  # Steam appid bound to each known target
REQUIRED_ORACLE_FILES = (
    'GObjects-Dump.txt', 'GObjects-Dump-WithProperties.txt',
    'Dumpspace/ClassesInfo.json', 'Dumpspace/EnumsInfo.json', 'Dumpspace/FunctionsInfo.json',
    'Dumpspace/OffsetsInfo.json', 'Dumpspace/StructsInfo.json',
    'CppSDK/SDK/Basic.hpp', 'CppSDK/SDK/CoreUObject_classes.hpp',
)   # plus exactly one IDAMappings/*.idmap

_CAPTURES_VAR = 'NYLIB_UE_CAPTURES'
_REQUIRED_TARGETS_VAR = 'NYLIB_UE_REQUIRED_TARGETS'
_SESSION_FILE = 'session.json'
_SCHEMA_NAME = 'nylib.ue.capture-session'
_SCHEMA_VERSION_RE = re.compile(r'1\.[0-9]+')
_HEX_RE = re.compile(r'0x[0-9A-F]+')
_SHA256_RE = re.compile(r'[0-9a-f]{64}')
_ABS_WINDOWS_PATH_RE = re.compile(r'[A-Za-z]:[\\/]')
_IDMAP_RE = re.compile(r'IDAMappings/[^/]+\.idmap')  # exactly one level deep
_STATE_VALUES = ('idle', 'title', 'menu', 'level')
_ROLE_VALUES = ('shipping', 'bootstrap', 'aux')
_DUMPER7_ROOTS = ('D:\\Dumper-7', 'C:\\Dumper-7')


def _is_int(x) -> bool:
    return isinstance(x, int) and not isinstance(x, bool)


def _is_abs_windows_path(s) -> bool:
    return isinstance(s, str) and bool(_ABS_WINDOWS_PATH_RE.match(s))


def _windows_path_under(path: str, folder: str) -> bool:
    norm_path = ntpath.normpath(path).casefold()
    norm_folder = ntpath.normpath(folder).casefold()
    return norm_path == norm_folder or norm_path.startswith(norm_folder + '\\')


def _is_posix_relpath(s: str) -> bool:
    if not isinstance(s, str) or not s or s.startswith('/') or '\\' in s or ':' in s:
        return False
    return all(p not in ('', '..') for p in s.split('/'))


def _is_path_component(s) -> bool:
    return isinstance(s, str) and bool(s) and s not in ('.', '..') and not any(c in s for c in '\\/:')


def env_path(name: str) -> str | None:
    """None when name is unset or empty; else its value, which must name an existing path."""
    if not isinstance(name, str):
        raise TypeError(f'name must be str, got {type(name).__name__}')
    value = os.environ.get(name, '')
    if not value:
        return None
    if not os.path.exists(value):
        raise FileNotFoundError(f'{name}={value!r} does not exist')
    return value


def captures_root() -> str | None:
    return env_path(_CAPTURES_VAR)


def required_targets() -> tuple[str, ...]:
    """NYLIB_UE_REQUIRED_TARGETS, comma-separated, order preserved; () when the variable is absent."""
    if _REQUIRED_TARGETS_VAR not in os.environ:
        return ()
    raw = os.environ[_REQUIRED_TARGETS_VAR]
    if not raw:
        raise ValueError(f'{_REQUIRED_TARGETS_VAR} is empty')
    items = [s.strip() for s in raw.split(',')]
    seen = set()
    for item in items:
        if not item:
            raise ValueError(f'{_REQUIRED_TARGETS_VAR} has an empty item: {raw!r}')
        if item not in KNOWN_TARGETS:
            raise ValueError(f'{_REQUIRED_TARGETS_VAR} names an unknown target {item!r}')
        if item in seen:
            raise ValueError(f'{_REQUIRED_TARGETS_VAR} repeats target {item!r}')
        seen.add(item)
    return tuple(items)


def validate_session(data: object, *, short: str) -> None:
    """Raise ValueError(f'{key path}: {problem}') at the first bad key of a complete session.json."""
    if not isinstance(short, str):
        raise TypeError(f'short must be str, got {type(short).__name__}')

    def fail(key, problem):
        raise ValueError(f'{key}: {problem}')

    if not isinstance(data, dict):
        fail('$', f'not a JSON object, got {type(data).__name__}')

    schema = data.get('schema')
    if not isinstance(schema, dict):
        fail('schema', f'not an object, got {schema!r}')
    if schema.get('name') != _SCHEMA_NAME:
        fail('schema.name', f'expected {_SCHEMA_NAME!r}, got {schema.get("name")!r}')
    version = schema.get('version')
    if not isinstance(version, str) or not _SCHEMA_VERSION_RE.fullmatch(version):
        fail('schema.version', f'must match 1.\\d+, got {version!r}')

    status = data.get('status')
    if status not in ('complete', 'incomplete'):
        fail('status', f'must be "complete" or "incomplete", got {status!r}')
    if status != 'complete':
        fail('status', f'validate_session requires a complete session, got {status!r}')

    if data.get('reason') is not None:
        fail('reason', f'must be null, got {data.get("reason")!r}')

    session_id = data.get('session_id')
    if not isinstance(session_id, str) or not session_id:
        fail('session_id', f'must be a non-empty string, got {session_id!r}')

    if not isinstance(data.get('harness_version'), str):
        fail('harness_version', f'must be a string, got {data.get("harness_version")!r}')

    state = data.get('state')
    if state not in _STATE_VALUES:
        fail('state', f'must be one of {_STATE_VALUES}, got {state!r}')

    target = data.get('target')
    if not isinstance(target, dict):
        fail('target', f'not an object, got {target!r}')

    target_short = target.get('short')
    if target_short not in KNOWN_TARGETS:
        fail('target.short', f'must be one of {KNOWN_TARGETS}, got {target_short!r}')
    if target_short != short:
        fail('target.short', f'{target_short!r} does not match the session folder {short!r}')

    if not isinstance(target.get('name'), str):
        fail('target.name', f'must be a string, got {target.get("name")!r}')

    appid = target.get('appid')
    if not _is_int(appid):
        fail('target.appid', f'must be a JSON integer, got {appid!r}')
    if appid != TARGET_APPIDS[target_short]:
        fail('target.appid', f'{appid} does not match the known Steam appid {TARGET_APPIDS[target_short]} for target {target_short!r}')

    buildid = target.get('buildid')
    if not isinstance(buildid, str) or not buildid or not (buildid.isascii() and buildid.isdigit()):
        fail('target.buildid', f'must be a non-empty string of ASCII digits, got {buildid!r}')

    install_dir, shipping_exe = target.get('install_dir'), target.get('shipping_exe')
    if not _is_abs_windows_path(install_dir):
        fail('target.install_dir', f'must be an absolute Windows path, got {install_dir!r}')
    if not _is_abs_windows_path(shipping_exe):
        fail('target.shipping_exe', f'must be an absolute Windows path, got {shipping_exe!r}')
    if not _windows_path_under(shipping_exe, install_dir):
        fail('target.shipping_exe', f'{shipping_exe!r} does not lie under install_dir {install_dir!r}')

    for key in ('pe_timestamp', 'size_of_image', 'module_base'):
        value = target.get(key)
        if not isinstance(value, str) or not _HEX_RE.fullmatch(value):
            fail(f'target.{key}', f'must be "0x" + upper-case hex, got {value!r}')

    launch = data.get('launch')
    if not isinstance(launch, dict):
        fail('launch', f'not an object, got {launch!r}')
    for key in ('steam_exe', 'command_line', 'launch_time'):
        if not isinstance(launch.get(key), str):
            fail(f'launch.{key}', f'must be a string, got {launch.get(key)!r}')
    if not _is_int(launch.get('launch_filetime')):
        fail('launch.launch_filetime', f'must be a JSON integer, got {launch.get("launch_filetime")!r}')
    recorded = launch.get('recorded_command_line')
    if recorded is not None and not isinstance(recorded, str):
        fail('launch.recorded_command_line', f'must be a string or null, got {recorded!r}')
    arguments_arrived = launch.get('arguments_arrived')
    if not (arguments_arrived is None or type(arguments_arrived) is bool):
        fail('launch.arguments_arrived', f'must be true, false or null, got {arguments_arrived!r}')

    processes = data.get('processes')
    if not isinstance(processes, list) or not processes:
        fail('processes', f'must be a non-empty list, got {processes!r}')
    shipping_count = 0
    for i, p in enumerate(processes):
        if not isinstance(p, dict):
            fail(f'processes[{i}]', f'must be an object, got {p!r}')
        if not _is_int(p.get('pid')):
            fail(f'processes[{i}].pid', f'must be a JSON integer, got {p.get("pid")!r}')
        if not _is_int(p.get('creation_filetime')):
            fail(f'processes[{i}].creation_filetime', f'must be a JSON integer, got {p.get("creation_filetime")!r}')
        if not isinstance(p.get('image_path'), str):
            fail(f'processes[{i}].image_path', f'must be a string, got {p.get("image_path")!r}')
        role = p.get('role')
        if role not in _ROLE_VALUES:
            fail(f'processes[{i}].role', f'must be one of {_ROLE_VALUES}, got {role!r}')
        shipping_count += role == 'shipping'
    if shipping_count != 1:
        fail('processes', f'must have exactly one shipping entry, found {shipping_count}')

    capture = data.get('capture')
    if not isinstance(capture, dict):
        fail('capture', f'not an object, got {capture!r}')
    if capture.get('file') != 'capture.zip':
        fail('capture.file', f'must be "capture.zip", got {capture.get("file")!r}')
    attempts = capture.get('attempts')
    if not (_is_int(attempts) and attempts in (1, 2)):
        fail('capture.attempts', f'must be 1 or 2, got {attempts!r}')
    seconds = capture.get('seconds')
    if not isinstance(seconds, (int, float)) or isinstance(seconds, bool):
        fail('capture.seconds', f'must be a JSON number, got {seconds!r}')
    for key in ('bytes', 'chunks', 'skipped_bytes', 'excluded_bytes'):
        value = capture.get(key)
        if not _is_int(value) or value < 0:
            fail(f'capture.{key}', f'must be a JSON integer >= 0, got {value!r}')
    excluded_by_reason = capture.get('excluded_by_reason')
    if not isinstance(excluded_by_reason, dict) or not all(
            isinstance(k, str) and _is_int(v) for k, v in excluded_by_reason.items()):
        fail('capture.excluded_by_reason', f'must be an object of string -> integer, got {excluded_by_reason!r}')
    if capture.get('verified') is not True:
        fail('capture.verified', f'must be true, got {capture.get("verified")!r}')
    quality = capture.get('quality')
    if not isinstance(quality, dict) or quality.get('passed') is not True:
        fail('capture.quality.passed', f'must be true, got {(quality if isinstance(quality, dict) else {}).get("passed")!r}')

    oracle = data.get('oracle')
    if not isinstance(oracle, dict):
        fail('oracle', f'not an object, got {oracle!r}')
    if not isinstance(oracle.get('stem'), str):
        fail('oracle.stem', f'must be a string, got {oracle.get("stem")!r}')
    folder = oracle.get('folder')
    if not _is_path_component(folder):
        fail('oracle.folder', f'must be a single path component, got {folder!r}')
    if not _is_int(oracle.get('longest_path')):
        fail('oracle.longest_path', f'must be a JSON integer, got {oracle.get("longest_path")!r}')
    files = oracle.get('files')
    if not isinstance(files, dict):
        fail('oracle.files', f'not an object, got {files!r}')
    idmap_count = 0
    for rel, info in files.items():
        if not _is_posix_relpath(rel):
            fail('oracle.files', f'key is not a POSIX relative path: {rel!r}')
        if (not isinstance(info, dict) or not _is_int(info.get('size'))
                or not isinstance(info.get('sha256'), str) or not _SHA256_RE.fullmatch(info.get('sha256'))):
            fail(f'oracle.files[{rel!r}]', f'must be {{size: int, sha256: 64 lower-case hex}}, got {info!r}')
        if _IDMAP_RE.fullmatch(rel):
            idmap_count += 1
    missing = [f for f in REQUIRED_ORACLE_FILES if f not in files]
    if missing:
        fail('oracle.files', f'missing required file(s): {missing}')
    if idmap_count != 1:
        fail('oracle.files', f'must contain exactly one IDAMappings/*.idmap, found {idmap_count}')

    dumper7_folders = data.get('dumper7_folders')
    if not isinstance(dumper7_folders, dict) or set(dumper7_folders) != set(_DUMPER7_ROOTS):
        fail('dumper7_folders', f'must have exactly the keys {_DUMPER7_ROOTS}, got {dumper7_folders!r}')
    for root, v in dumper7_folders.items():
        if (not isinstance(v, dict) or not isinstance(v.get('exists_before'), bool)
                or not isinstance(v.get('exists_after'), bool) or v.get('unchanged') is not True):
            fail(f'dumper7_folders[{root!r}]',
                 f'must be {{exists_before: bool, exists_after: bool, unchanged: true}}, got {v!r}')

    kill = data.get('kill')
    if kill is not None and not isinstance(kill, dict):
        fail('kill', f'must be absent, null, or an object, got {kill!r}')


@dataclasses.dataclass(frozen=True)
class Session:
    dir: str                                      # absolute session folder
    data: dict                                    # the parsed, validated session.json
    target: str                                   # data['target']['short']
    state: str                                    # data['state']
    session_id: str                               # data['session_id']


def iter_sessions() -> list[Session]:
    """Complete sessions under captures_root(), sorted by (target, folder name); [] when unset."""
    root = captures_root()
    if root is None:
        return []
    root = os.path.abspath(root)
    sessions = []
    for entry in sorted(os.listdir(root)):
        if entry.startswith('_'):
            continue
        entry_dir = os.path.join(root, entry)
        if not os.path.isdir(entry_dir):
            continue
        for folder in sorted(os.listdir(entry_dir)):
            folder_dir = os.path.join(entry_dir, folder)
            session_file = os.path.join(folder_dir, _SESSION_FILE)
            if not os.path.isfile(session_file):
                continue
            with open(session_file, 'rb') as f:
                raw = f.read()
            try:
                text = raw.decode('utf-8')
            except UnicodeDecodeError as e:
                raise ValueError(f'{session_file}: not valid UTF-8: {e}') from e
            try:
                data = json.loads(text)
            except ValueError as e:
                raise ValueError(f'{session_file}: not valid JSON: {e}') from e
            if not isinstance(data, dict):
                raise ValueError(f'{session_file}: not a JSON object')
            schema = data.get('schema')
            if not isinstance(schema, dict) or schema.get('name') != _SCHEMA_NAME:
                raise ValueError(f'{session_file}: schema.name is not {_SCHEMA_NAME!r}')
            version = schema.get('version')
            if not isinstance(version, str) or not _SCHEMA_VERSION_RE.fullmatch(version):
                raise ValueError(f'{session_file}: schema.version must match 1.\\d+, got {version!r}')
            status = data.get('status')
            if status not in ('complete', 'incomplete'):
                raise ValueError(f'{session_file}: status must be "complete" or "incomplete", got {status!r}')
            if status == 'incomplete':
                continue
            try:
                validate_session(data, short=entry)
            except ValueError as e:
                raise ValueError(f'{session_file}: {e}') from e
            sessions.append(Session(dir=folder_dir, data=data, target=data['target']['short'],
                                     state=data['state'], session_id=data['session_id']))
    sessions.sort(key=lambda s: (s.target, os.path.basename(s.dir)))
    return sessions


def same_instance(image: ImageSource, dump: GObjectsDump, *, sample: int = 1000) -> tuple[int, int]:
    """Sample dump.rows and count how many read as a live-looking vtable in image's main module."""
    if not isinstance(sample, int):
        raise TypeError(f'sample must be int, got {type(sample).__name__}')
    if sample < 1:
        raise ValueError(f'sample must be >= 1, got {sample}')
    rows = dump.rows
    if not rows:
        return 0, 0
    step = max(1, len(rows) // sample)
    main = image.main_module
    sampled = hits = 0
    for _index, address, _name in rows[::step]:
        sampled += 1
        if image.readable(address, 8) and main.base <= image.u64(address) < main.base + main.size:
            hits += 1
    return sampled, hits


def check_session(session: Session) -> None:
    """Per-session gate: the capture loads, its main module matches target, PE facts, oracle files
    and hashes, GObjects row threshold and stem, same-instance sampling. Raises naming the failed check."""
    data = session.data
    target = data['target']
    with ImageSource.load(os.path.join(session.dir, 'capture.zip'), verify=False) as image:
        mods = image.modules()
        if not mods:
            raise AssertionError('capture has no modules')
        main = mods[0]
        expected_name = os.path.basename(target['shipping_exe'])
        if main.name.casefold() != expected_name.casefold():
            raise AssertionError(f'main module name {main.name!r} != target.shipping_exe basename {expected_name!r}')
        module_base = int(target['module_base'], 16)
        size_of_image = int(target['size_of_image'], 16)
        pe_timestamp = int(target['pe_timestamp'], 16)
        if main.base != module_base:
            raise AssertionError(f'main module base {main.base:#x} != target.module_base {module_base:#x}')
        if main.size != size_of_image:
            raise AssertionError(f'main module size {main.size:#x} != target.size_of_image {size_of_image:#x}')

        pe = PeImage(image, module_base)
        if pe.timestamp != pe_timestamp:
            raise AssertionError(f'PE timestamp {pe.timestamp:#x} != target.pe_timestamp {pe_timestamp:#x}')
        if pe.size != size_of_image:
            raise AssertionError(f'PE SizeOfImage {pe.size:#x} != target.size_of_image {size_of_image:#x}')

        oracle = data['oracle']
        oracle_dir = os.path.join(session.dir, 'oracle', oracle['folder'])
        idmap_count = 0
        for rel, info in oracle['files'].items():
            path = os.path.join(oracle_dir, *rel.split('/'))
            raw = pathlib.Path(path).read_bytes()
            if len(raw) != info['size']:
                raise AssertionError(f'{rel}: size mismatch')
            if hashlib.sha256(raw).hexdigest() != info['sha256']:
                raise AssertionError(f'{rel}: sha256 mismatch')
            if _IDMAP_RE.fullmatch(rel):
                idmap_count += 1
        missing = [f for f in REQUIRED_ORACLE_FILES if f not in oracle['files']]
        if missing:
            raise AssertionError(f'oracle.files missing required file(s): {missing}')
        if idmap_count != 1:
            raise AssertionError(f'oracle.files must contain exactly one IDAMappings/*.idmap, found {idmap_count}')

        dump = parse_gobjects_dump(pathlib.Path(oracle_dir) / 'GObjects-Dump.txt')
        if len(dump.rows) < 10000:
            raise AssertionError(f'GObjects dump has {len(dump.rows)} rows, need >= 10000')
        if dump.stem != oracle['stem']:
            raise AssertionError(f'GObjects dump stem {dump.stem!r} != oracle.stem {oracle["stem"]!r}')

        sampled, hits = same_instance(image, dump)
        if sampled < 1000:
            raise AssertionError(f'same_instance sampled only {sampled} rows, need >= 1000')
        if hits < 0.99 * sampled:
            raise AssertionError(f'same_instance hits {hits}/{sampled} below the 0.99 same-instance threshold')

    for root, info in data['dumper7_folders'].items():
        if not info['unchanged']:
            raise AssertionError(f'dumper7_folders[{root!r}] changed during the session')
