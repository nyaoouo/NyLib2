"""Target detection, pin application and the dump pipeline over stages 4-6 (I3): open_target, probe, dump, list_targets."""
import dataclasses
import datetime
import hashlib
import logging
import logging.handlers
import os
import re
import time
from typing import Callable

from . import calls
from . import errors
from . import image
from . import memory
from . import pe
from . import profiles
from . import remote_calls
from . import scan
from . import store
from .exports import EXPORT_SPECS
from .exports.usmap import export_warnings
from ..winutils import process as winutils_process
from ..winutils.version import get_file_version_info

logger = logging.getLogger('nylib.ue.pipeline')

CACHE_CAP_EXTERNAL = 1 << 30  # page-cache LRU cap (bytes); 7-G confirms it from 6-G's numbers
CACHE_CAP_INTERNAL = 128 << 20
UNREADABLE_FAIL = 0.05  # share of walked objects that fails a dump
UNREADABLE_WARN = 0.001
UE_EXE_RE = re.compile(r'-(?:Win64|WinGDK)-(?:Shipping|Test|DebugGame)(?:-Cmd)?\.exe$', re.IGNORECASE)
IMAGE_EXPORT = 'image'  # (7-c) the main-module image (I6); a dump-only format
DEFAULT_DUMP_EXPORTS = ('idmap', 'gobjects', 'gobjects-props', IMAGE_EXPORT, 'usmap')  # dump's default: image before usmap

_ROOT_OBJS = {'Off': 'off', 'Settings': 'settings', 'PropertySizes': 'property_sizes', 'FNameEntry': 'names'}
_ROW_NAMES = {
    'Off.InSDK.ObjArray.GObjects': 'GObjects',
    'Off.InSDK.NameArray.GNames': 'GNames',
    'Off.InSDK.Name.AppendNameToString': 'AppendString',
    'Off.InSDK.ProcessEvent.PEIndex': 'ProcessEvent.Index',
    'Off.InSDK.ProcessEvent.PEOffset': 'ProcessEvent',
    'Off.InSDK.World.GWorld': 'GWorld',
}


@dataclasses.dataclass(frozen=True)
class TargetInfo:
    mode: str  # 'external' | 'internal' | 'capture'
    pid: int | None
    exe: str  # main module name
    exe_path: str  # main module path, '' when unknown
    exe_sha256: str | None  # lower-case hex of the file at exe_path
    module_base: int
    size_of_image: int
    pe_timestamp: int
    file_version: str | None  # version resource 'a.b.c.d'
    version_info: dict | None  # nylib.winutils.version.get_file_version_info(exe_path)


@dataclasses.dataclass
class OpenedTarget:
    source: memory.MemorySource  # cached reads (P3); .fresh is uncached
    info: TargetInfo
    process: object = None  # external: the opened handle; internal: current_process(); capture: None
    check_alive: Callable[[], bool] | None = None
    closer: Callable[[], None] | None = None

    def close(self) -> None:
        if self.closer is not None:
            closer, self.closer = self.closer, None
            closer()

    def __enter__(self) -> 'OpenedTarget':
        return self

    def __exit__(self, *exc) -> None:
        self.close()


@dataclasses.dataclass(frozen=True)
class ProbeValue:
    name: str  # display name
    key: str  # E3 provenance key
    value: int | bool | str | tuple | None
    how: str  # the provenance label
    check: str  # '-' or a sanity note
    unverified: bool


@dataclasses.dataclass(frozen=True)
class ProbeReport:
    ok: bool
    target: TargetInfo
    profile: str | None  # path of the profile used
    profile_note: str
    values: tuple  # ProbeValue, ... in e.provenance order (= bootstrap order)
    unverified: tuple  # R5.2's unverified keys; () when not ok
    steps: tuple  # completed init steps, in order, from ('objects', 'names', 'engine')
    error: errors.DetectionError | None
    explanations: tuple  # e.messages
    game_name: str
    game_name_from: str
    engine_version: str
    engine_version_from: str
    stem: str
    warnings: tuple
    seconds: float
    context: object | None  # the R5.1 EngineContext when ok


@dataclasses.dataclass(frozen=True)
class DumpResult:
    path: str  # the published snapshot folder
    target: TargetInfo
    report: ProbeReport
    counts: dict  # R6.1's six counts
    unverified: tuple
    exports: tuple  # format names, in order
    export_paths: tuple
    warnings: tuple
    seconds: float
    remote_calls: tuple = ()  # one FeatureResult per requested feature, in RUN_ORDER
    quality: dict | None = None  # the walk's export quality verdict (reflect.walk's WalkResult.quality)


@dataclasses.dataclass(frozen=True)
class TargetRow:
    pid: int
    exe: str
    engine_hint: str | None  # e.g. '++UE5+Release-5.1'
    note: str  # '' or why the process could not be inspected
    profile: str | None  # file name of the matching profile
    profile_status: str  # '-' | 'build matches' | 'build differs' | 'no rva pins' | 'ambiguous (<n> profiles)'


@dataclasses.dataclass
class _Pins:
    gobjects_rva: int | None = None
    gobjects_label: str | None = None
    gobjects_pin: object = None
    gnames_rva: int | None = None
    gnames_label: str | None = None
    offsets_pins: dict | None = None
    pe_index: int | None = None
    decrypt_fn: object = None
    hook_text: str | None = None


# --------------------------------------------------------------------------------------------
# shared argument checks
# --------------------------------------------------------------------------------------------

def _check_target(target):
    if target is None:
        return None
    if isinstance(target, bool):
        raise TypeError(f'target must be None, int or str, got {type(target).__name__}')
    if isinstance(target, int):
        return target
    if isinstance(target, str):
        if target == '':
            raise ValueError('target must not be empty')
        return target
    raise TypeError(f'target must be None, int or str, got {type(target).__name__}')


def _check_cache_bytes(cache_bytes):
    if cache_bytes is None:
        return None
    if not isinstance(cache_bytes, int) or isinstance(cache_bytes, bool):
        raise TypeError(f'cache_bytes must be an int or None, got {type(cache_bytes).__name__}')
    if cache_bytes < 0x10000:
        raise ValueError(f'cache_bytes must be >= 0x10000, got {cache_bytes:#x}')
    return cache_bytes


def _check_profile(profile):
    if profile is None:
        return None
    if isinstance(profile, profiles.Profile):
        return profile
    if isinstance(profile, (str, os.PathLike)):
        return profiles.load_profile(profile)
    raise TypeError(f'profile must be None, str, os.PathLike or Profile, got {type(profile).__name__}')


def _hex(value: int) -> str:
    return f'-0x{-value:X}' if value < 0 else f'0x{value:X}'


def _exe_stem(exe: str) -> str:
    stem = exe[:-4] if exe.lower().endswith('.exe') else exe
    return stem.split('-', 1)[0]


def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1 << 20), b''):
            h.update(chunk)
    return h.hexdigest()


def _file_pe_facts(path: str):
    """(timestamp, size_of_image) from the file's own PE header at `path`, or None if unparsable."""
    with open(path, 'rb') as f:
        mz = f.read(0x40)
        if len(mz) < 0x40 or mz[:2] != b'MZ':
            return None
        e_lfanew = int.from_bytes(mz[0x3C:0x40], 'little')
        f.seek(e_lfanew)
        head = f.read(24 + 0x3C)
        if len(head) < 24 + 0x3C or head[:4] != b'PE\0\0':
            return None
        timestamp = int.from_bytes(head[8:12], 'little')
        size_of_image = int.from_bytes(head[24 + 0x38:24 + 0x3C], 'little')
    return timestamp, size_of_image


def _iter_unique_processes():
    """(pid, exe) once per live process; iter_processes yields one mutable struct repeatedly."""
    seen = set()
    for entry in winutils_process.iter_processes():
        pid = int(entry.th32ProcessID)
        if pid in seen:
            continue
        seen.add(pid)
        yield pid, entry.szExeFile.split(b'\0')[0].decode('mbcs', 'replace')


# --------------------------------------------------------------------------------------------
# target_info / open_target
# --------------------------------------------------------------------------------------------

def target_info(source, *, mode: str, pid: int | None) -> TargetInfo:
    if not isinstance(source, memory.MemorySource):
        raise TypeError(f'source must be a MemorySource, got {type(source).__name__}')
    if mode not in ('external', 'internal', 'capture'):
        raise ValueError(f'mode must be one of external, internal, capture, got {mode!r}')
    if pid is not None and (not isinstance(pid, int) or isinstance(pid, bool)):
        raise TypeError(f'pid must be int or None, got {type(pid).__name__}')

    try:
        main = source.main_module
    except errors.UeError:
        raise errors.TargetError(pid if pid is not None else '<image>', 'no modules') from None
    try:
        image = pe.PeImage(source, main.base)
    except errors.PeFormatError as e:
        raise errors.TargetError(pid if pid is not None else main.name, f'not an x64 game: {e.reason}') from e

    exe_sha256 = file_version = version_info = None
    if main.path:
        try:
            facts = _file_pe_facts(main.path)
        except OSError:
            facts = None
        if facts is not None and facts == (image.timestamp, image.size):
            try:
                exe_sha256 = _sha256_file(main.path)
            except OSError:
                exe_sha256 = None
            try:
                version_info = get_file_version_info(main.path)
            except Exception:
                version_info = None
            file_version = version_info.get('FileVersion') if version_info else None
        elif facts is not None:
            logger.warning('the exe on disk (%s) is another build than the running module; file facts left empty', main.path)

    return TargetInfo(mode=mode, pid=pid, exe=main.name, exe_path=main.path or '', exe_sha256=exe_sha256,
                       module_base=main.base, size_of_image=image.size, pe_timestamp=image.timestamp,
                       file_version=file_version, version_info=version_info)


def _resolve_pid(name: str) -> int:
    target, alt = name.casefold(), (f'{name}.exe'.casefold() if '.' not in name else None)
    matches = [(pid, exe) for pid, exe in _iter_unique_processes() if exe.casefold() in (target, alt)]
    if not matches:
        raise errors.TargetError(name, 'no running process with that name')
    if len(matches) > 1:
        pids = ', '.join(str(pid) for pid, _ in matches)
        raise errors.AmbiguousTargetError(name, f'{len(matches)} processes are named {name!r} (pid {pids}); pass a PID instead')
    return matches[0][0]


def _open_external(pid: int, *, write: bool, remote_calls: bool, cache_bytes) -> OpenedTarget:
    process = memory.open_process(pid, write=write, remote_calls=remote_calls)
    try:
        source = memory.ProcessSource(process, max_cache_bytes=cache_bytes or CACHE_CAP_EXTERNAL)
        info = target_info(source, mode='external', pid=pid)
    except Exception:
        process.close()
        raise
    return OpenedTarget(source=source, info=info, process=process, check_alive=process.still_alive, closer=process.close)


def _open_internal(cache_bytes) -> OpenedTarget:
    process = memory.current_process()
    source = memory.ProcessSource(process, max_cache_bytes=cache_bytes or CACHE_CAP_INTERNAL)
    info = target_info(source, mode='internal', pid=process.process_id)
    return OpenedTarget(source=source, info=info, process=process, check_alive=None, closer=lambda: None)


def open_target(target=None, *, write: bool = False, remote_calls: bool = False, cache_bytes=None) -> OpenedTarget:
    target = _check_target(target)
    cache_bytes = _check_cache_bytes(cache_bytes)
    if target is None:
        return _open_internal(cache_bytes)
    pid = target if isinstance(target, int) else _resolve_pid(target)
    return _open_external(pid, write=write, remote_calls=remote_calls, cache_bytes=cache_bytes)


# --------------------------------------------------------------------------------------------
# probe_opened: pin resolution + bootstrap
# --------------------------------------------------------------------------------------------

def _rva_pin(prof, name: str, pin, info: TargetInfo, warnings: list):
    if pin.build != info.pe_timestamp or (pin.image_size is not None and pin.image_size != info.size_of_image):
        built = f'{pin.build:#x}' + (f' / {pin.image_size:#x}' if pin.image_size is not None else '')
        msg = (f'profile {profiles.display_path(prof)}: [globals] {name} is pinned for build {built}; '
               f'the target is {info.pe_timestamp:#x} / {info.size_of_image:#x}; ignored')
        warnings.append(msg)
        logger.warning(msg)
        return None
    if pin.rva >= info.size_of_image:
        raise errors.ProfileError(profiles.display_path(prof), f'[globals] {name} rva {pin.rva:#x} lies outside the image '
                                                               f'(SizeOfImage {info.size_of_image:#x})')
    return pin.rva


def _sig_pin(prof, name: str, pin, source, image):
    found = scan.Scanner(source, image).find_pattern(pin.sig, executable=True)
    if len(found) != 1:
        raise errors.ProfileError(profiles.display_path(prof), f'[globals] {name} sig matches {len(found)} sites; it must match exactly one')
    addr, stored = found[0]
    if stored:
        value = stored[0]
        if not isinstance(value, int):
            raise errors.ProfileError(profiles.display_path(prof), f'[globals] {name} sig: its first stored value is not a reference')
    else:
        value = addr
    if not (image.base <= value < image.base + image.size):
        raise errors.ProfileError(profiles.display_path(prof), f'[globals] {name} sig resolves outside the main module')
    return value - image.base


def _resolve_named_pin(prof, name: str, info: TargetInfo, source, image, warnings: list):
    pin = prof.pins.get(name)
    if pin is None:
        return None, None, None
    if pin.rva is not None:
        rva, label = _rva_pin(prof, name, pin, info, warnings), 'profile: rva'
    else:
        rva, label = _sig_pin(prof, name, pin, source, image), 'profile: sig'
    return (rva, label, pin) if rva is not None else (None, None, None)


def _resolve_pins(prof, info: TargetInfo, opened: OpenedTarget, warnings: list) -> _Pins:
    from .engine.offsets import PINNABLE_KEYS

    image = pe.PeImage(opened.source, info.module_base)
    gobjects_rva, gobjects_label, gobjects_pin = _resolve_named_pin(prof, 'gobjects', info, opened.source, image, warnings)
    gnames_rva, gnames_label, _ = _resolve_named_pin(prof, 'gnames', info, opened.source, image, warnings)

    offsets_pins = {}
    for key, value in prof.offsets.items():
        if key not in PINNABLE_KEYS:
            raise errors.ProfileError(profiles.display_path(prof), f'[offsets] unknown key {key!r}')
        offsets_pins[key] = value

    pe_pin = prof.pins.get('process_event')
    pe_index = pe_pin.index if pe_pin is not None else None

    decrypt_fn = hook_text = None
    if 'decrypt_objects' in prof.hooks:
        decrypt_fn = profiles.load_hook(prof, 'decrypt_objects')
        file_rel, func_name = prof.hooks['decrypt_objects']
        hook_text = f'{file_rel}:{func_name}'

    return _Pins(gobjects_rva, gobjects_label, gobjects_pin, gnames_rva, gnames_label, offsets_pins, pe_index, decrypt_fn, hook_text)


def _run_bootstrap(e, prof, pins: '_Pins | None', steps: list):
    """Objects/names/engine init steps (ea0dab3 ObjectArray::Init / FName::Init, R5.1); appends to `steps` as each completes
    so a step list survives a DetectionError raised partway through."""
    from .engine import context as context_mod
    from .engine.state import FChunkedFixedUObjectArrayLayout

    if pins is not None and pins.decrypt_fn is not None:
        e.objects.init_decryption(pins.decrypt_fn, pins.hook_text)

    if pins is not None and pins.gobjects_rva is not None:
        pin = pins.gobjects_pin
        layout = FChunkedFixedUObjectArrayLayout(*pin.layout) if pin.layout else FChunkedFixedUObjectArrayLayout()
        try:
            e.objects.init_chunked(pins.gobjects_rva, pin.elements_per_chunk or 0x10000, layout)
            num, maxn = e.objects.num(), e.objects.max()
        except errors.MemoryReadError as err:
            raise errors.DetectionError('ObjectArray::Init', f'the GObjects value pinned by {profiles.display_path(prof)} cannot be read: {err}',
                                        tuple(e.messages)) from err
        if not (0 < num <= maxn):
            raise errors.DetectionError('ObjectArray::Init', f'the GObjects value pinned by {profiles.display_path(prof)} does not hold an object '
                                        f'array (Num {num}, Max {maxn})', tuple(e.messages))
        e.provenance['Off.InSDK.ObjArray.GObjects'] = pins.gobjects_label
        if pin.elements_per_chunk is not None:
            e.provenance['Off.InSDK.ObjArray.ChunkSize'] = 'profile: value'
        if pin.layout is not None:
            e.provenance['Off.FUObjectArray.ChunkedFixedLayout'] = 'profile: value'
    else:
        e.objects.init()
    steps.append('objects')

    if pins is not None and pins.gnames_rva is not None:
        try:
            e.fname.init_override(pins.gnames_rva, 'GNames', True)
        except errors.DetectionError as err:
            raise errors.DetectionError('FName::Init', f'the GNames value pinned by {profiles.display_path(prof)} could not be initialised',
                                        tuple(e.messages)) from err
        e.provenance['Off.InSDK.NameArray.GNames'] = pins.gnames_label
    else:
        e.fname.init_windows()
    steps.append('names')

    offsets_pins = pins.offsets_pins if pins is not None and pins.offsets_pins else None
    pe_index = pins.pe_index if pins is not None else None
    context = context_mod.init_engine_rest(e, offsets_pins=offsets_pins, pe_index=pe_index)
    steps.append('engine')
    return context


def _resolve_provenance_value(e, key: str):
    parts = key.split('.')
    attr = _ROOT_OBJS.get(parts[0])
    if attr is None:
        return None, False
    obj = getattr(e, attr)
    try:
        for name in parts[1:]:
            obj = getattr(obj, name)
    except AttributeError:
        return None, False
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        obj = dataclasses.astuple(obj)
    return obj, True


def _row_check(key: str, e, steps: list) -> str:
    if key == 'Off.InSDK.ObjArray.GObjects' and 'objects' in steps:
        try:
            return f'{e.objects.num():,} objects'
        except Exception as err:
            return f'unreadable ({type(err).__name__})'
    if key == 'Off.InSDK.NameArray.GNames' and 'names' in steps:
        try:
            s = e.fname.comp_idx_to_string(0)
        except Exception as err:
            return f'unreadable ({type(err).__name__})'
        return 'decodes "None"' if s == 'None' else f'index 0 decodes {s!r}'
    return '-'


def probe_opened(opened: OpenedTarget, *, profile=None, out_root=None) -> ProbeReport:
    """The reusable detection core: stage 9 opens a target with its own rights and calls this."""
    if not isinstance(opened, OpenedTarget):
        raise TypeError(f'opened must be an OpenedTarget, got {type(opened).__name__}')
    if out_root is not None and not isinstance(out_root, (str, os.PathLike)):
        raise TypeError(f'out_root must be str, os.PathLike or None, got {type(out_root).__name__}')
    t0 = time.perf_counter()
    info = opened.info
    warnings = []

    prof = _check_profile(profile)
    if prof is not None:
        note = 'explicit'
        if prof.exe is not None and prof.exe.casefold() != info.exe.casefold():
            msg = f'profile {profiles.display_path(prof)} is for {prof.exe}; the target is {info.exe}'
            warnings.append(msg)
            logger.warning(msg)
    elif out_root is not None:
        matches = profiles.find_profiles(out_root, info.exe)
        if not matches:
            note = 'none'
        elif len(matches) == 1:
            prof, note = matches[0], 'exe matches'
        else:
            names = ', '.join(os.path.basename(m.path) for m in matches)
            raise errors.ProfileError(os.path.join(out_root, store.PROFILES_DIR),
                                      f'{len(matches)} profiles match {info.exe!r} ({names}); pass --profile FILE')
    else:
        note = ('profiles not searched (no output root inside the game)' if info.mode == 'internal'
                else 'profiles not searched')

    e = None
    steps, context, error = [], None, None
    try:
        pins = _resolve_pins(prof, info, opened, warnings) if prof is not None else None
        from .engine.core import Engine
        e = Engine(opened.source)
        context = _run_bootstrap(e, prof, pins, steps)
    except errors.DetectionError as err:
        if opened.check_alive is not None and not opened.check_alive():
            raise errors.TargetError(opened.info.pid, 'process exited during the probe') from err
        error = err
    except errors.ProfileError:
        raise
    except KeyboardInterrupt:
        raise
    except Exception as err:
        if opened.check_alive is not None and not opened.check_alive():
            raise errors.TargetError(opened.info.pid, 'process exited during the probe') from err
        raise

    ok = error is None
    unverified_list = context.unverified() if (ok and context is not None) else []
    unverified_set = set(unverified_list)

    values = []
    for key, label in e.provenance.items():
        value, resolved = _resolve_provenance_value(e, key)
        name = _ROW_NAMES.get(key, key)
        check = 'unresolved key' if not resolved else _row_check(key, e, steps)
        values.append(ProbeValue(name=name, key=key, value=value, how=label, check=check,
                                 unverified=(name in unverified_set or key in unverified_set)))

    game_name = e.settings.Generator.GameName or ''
    engine_version = e.settings.Generator.GameVersion or ''
    game_name_from = e.provenance.get('Settings.Generator.GameName', '')
    engine_version_from = e.provenance.get('Settings.Generator.GameVersion', '')
    stem = f'{engine_version}-{game_name}' if engine_version and game_name else ''

    return ProbeReport(
        ok=ok, target=info, profile=(prof.path if prof is not None else None), profile_note=note,
        values=tuple(values), unverified=tuple(unverified_list) if ok else (), steps=tuple(steps), error=error,
        explanations=tuple(e.messages), game_name=game_name, game_name_from=game_name_from,
        engine_version=engine_version, engine_version_from=engine_version_from, stem=stem,
        warnings=tuple(warnings), seconds=time.perf_counter() - t0, context=context if ok else None,
    )


def probe(target=None, *, profile=None, out=None, cache_bytes=None, _open_target=None) -> ProbeReport:
    target = _check_target(target)
    cache_bytes = _check_cache_bytes(cache_bytes)
    try:
        root = store.resolve_out_root(out, internal=target is None)
    except errors.OutputRootError:
        root = None  # P20: an internal probe without a root still runs
    prof = _check_profile(profile)  # loaded before the target is opened
    opened = (_open_target or open_target)(target, write=False, remote_calls=False, cache_bytes=cache_bytes)
    try:
        return probe_opened(opened, profile=prof, out_root=root)
    finally:
        opened.close()


# --------------------------------------------------------------------------------------------
# dump
# --------------------------------------------------------------------------------------------

def _report_after_calls(report: ProbeReport) -> ProbeReport:
    """Rebuilds the rows, stem and unverified set that run()'s calls may have changed in report.context.engine."""
    e = report.context.engine
    unverified_set = set(report.context.unverified())
    values = []
    for v in report.values:
        label = e.provenance.get(v.key, v.how)
        value, resolved = _resolve_provenance_value(e, v.key)
        if label != v.how or (resolved and value != v.value):
            v = dataclasses.replace(v, value=value, how=label, unverified=(v.name in unverified_set or v.key in unverified_set))
        values.append(v)
    game_name = e.settings.Generator.GameName or ''
    engine_version = e.settings.Generator.GameVersion or ''
    return dataclasses.replace(
        report, values=tuple(values), unverified=tuple(report.context.unverified()),
        game_name=game_name, game_name_from=e.provenance.get('Settings.Generator.GameName', ''),
        engine_version=engine_version, engine_version_from=e.provenance.get('Settings.Generator.GameVersion', ''),
        stem=f'{engine_version}-{game_name}' if engine_version and game_name else '',
    )


def dump(target=None, *, profile=None, out=None, exports=DEFAULT_DUMP_EXPORTS, allow_calls=None, log_file=None,
         cache_bytes=None, progress=None, strict: bool = False, _open_target=None) -> DumpResult:
    if not isinstance(exports, (list, tuple)):
        raise TypeError(f'exports must be a list or tuple, got {type(exports).__name__}')
    fmts = []
    for fmt in exports:
        if not isinstance(fmt, str):
            raise TypeError(f'export format must be a str, got {type(fmt).__name__}')
        if fmt not in EXPORT_SPECS and fmt != IMAGE_EXPORT:  # (7-c) image is a dump-only format
            raise ValueError(f'unknown export format {fmt!r}')
        if fmt not in fmts:
            fmts.append(fmt)
    features = remote_calls.parse_features(allow_calls)  # errors before any root or target access
    if log_file is not None and not isinstance(log_file, (str, os.PathLike)):
        raise TypeError(f'log_file must be str, os.PathLike or None, got {type(log_file).__name__}')
    if progress is not None and not callable(progress):
        raise TypeError(f'progress must be callable or None, got {type(progress).__name__}')
    if not isinstance(strict, bool):
        raise TypeError(f'strict must be a bool, got {type(strict).__name__}')

    target = _check_target(target)
    cache_bytes = _check_cache_bytes(cache_bytes)
    t0 = time.perf_counter()
    root = store.resolve_out_root(out, internal=target is None)  # OutputRootError before any target access (G7.3)
    prof = _check_profile(profile)

    ue_logger = logging.getLogger('nylib.ue')
    log_handler, prev_level = None, None
    if log_file is not None:
        log_file_str = os.fspath(log_file)
        os.makedirs(os.path.dirname(log_file_str) or '.', exist_ok=True)
        log_handler = logging.handlers.RotatingFileHandler(log_file_str, maxBytes=5 << 20, backupCount=3,
                                                            encoding='utf-8', delay=True)
        log_handler.setLevel(logging.DEBUG)
        log_handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(name)s: %(message)s'))
        prev_level = ue_logger.level
        ue_logger.addHandler(log_handler)
        ue_logger.setLevel(logging.DEBUG)

    try:
        opened = (_open_target or open_target)(target, write=False, remote_calls=bool(features), cache_bytes=cache_bytes)
        try:
            if features and opened.process is None:
                raise errors.UeError('--allow-calls needs a live target; a capture cannot run code')
            if progress is not None:
                progress('open', opened.info)
            report = probe_opened(opened, profile=prof, out_root=root)
            if not report.ok:
                raise report.error
            if features:
                transport = calls.open_transport('remote-thread' if opened.info.mode == 'external' else 'any-thread', opened.process)
                try:
                    results = remote_calls.run(report.context, transport, features)
                finally:
                    transport.close()
                report = _report_after_calls(report)
            else:
                results = ()
            if progress is not None:
                progress('probe', report)
                if features:
                    progress('calls', results)

            from . import reflect
            when = datetime.datetime.now().astimezone()
            folder = store.new_snapshot_dir(root, report.game_name or _exe_stem(opened.info.exe), when)
            ctx = report.context
            m = ctx.to_meta()
            info = opened.info
            if features:  # to_meta()'s own default ('called': False) stands when no call was requested
                m['globals']['AppendString']['called'] = any(r.feature == 'append-string' and r.ran for r in results)
            meta = {
                'created': when.isoformat(timespec='seconds'), 'mode': info.mode,
                'remote_calls': [r.feature for r in results if r.ran],
                'target': {**m['target'], 'pid': info.pid, 'exe': info.exe, 'exe_path': info.exe_path,
                          'exe_sha256': info.exe_sha256,
                          'module': {'base': _hex(info.module_base), 'size': _hex(info.size_of_image),
                                     'pe_timestamp': _hex(info.pe_timestamp)},
                          'file_version': info.file_version},
                'engine': m['engine'], 'globals': m['globals'],
            }

            opened.source.refresh()  # the walk starts a new cache epoch
            img = None
            if IMAGE_EXPORT in fmts:  # (7-c) before the walk, so its facts reach meta.json through meta
                img = image.write_image(opened.source, base=info.module_base, size_of_image=info.size_of_image,
                                        exe=info.exe, folder=f'{folder}.partial',
                                        disk_exe=info.exe_path if info.exe_sha256 is not None else None)
                meta['image'] = img.to_meta()
                for w in img.warnings:
                    logger.warning(w)
                if progress is not None:
                    progress('image', img)

            offsets_doc = ctx.to_offsets()

            walk_progress = (lambda done, total: progress('walk', (done, total))) if progress is not None else None
            try:
                wr = reflect.walk(ctx, folder, meta=meta, offsets=offsets_doc, check_alive=opened.check_alive,
                                  progress=walk_progress)
            except errors.TargetError:
                raise
            except KeyboardInterrupt:
                raise
            except Exception as err:
                if opened.check_alive is not None and not opened.check_alive():
                    raise errors.TargetError(opened.info.pid, 'process exited during the walk') from err
                raise
            if progress is not None:
                progress('snapshot', wr.counts)

            warning_list = list(report.warnings)  # order: the report's, the calls', the image's (7-c), the unreadable share's, the quality verdict's, the usmap export's
            warning_list.extend(f'--allow-calls {r.feature}: {r.detail}' for r in results if not r.ok)
            if img is not None:
                warning_list.extend(img.warnings)
            share = (wr.unreadable / wr.walked) if wr.walked else 0.0
            if share > UNREADABLE_FAIL:
                raise errors.UeError(f'{wr.unreadable:,} of {wr.walked:,} objects ({share:.1%}) could not be read; '
                                     f'the snapshot was left in {folder}.partial')
            if share > UNREADABLE_WARN:
                msg = f'{wr.unreadable:,} of {wr.walked:,} objects ({share:.1%}) could not be read'
                warning_list.append(msg)
                logger.warning(msg)
            if wr.quality['verdict'] == 'degraded':
                msg = f"export quality degraded: {'; '.join(wr.quality['reasons'])}"
                warning_list.append(msg)
                logger.warning(msg)
            if strict and wr.quality['verdict'] == 'degraded':
                err = errors.UeError(f"export quality degraded ({'; '.join(wr.quality['reasons'])}); "
                                     f'the snapshot was left in {folder}.partial')
                err.quality = wr.quality
                raise err

            image_written = img is not None and img.skipped is None
            written_fmts = tuple(f for f in fmts if f != IMAGE_EXPORT or image_written)
            token = export_warnings.set(warning_list)
            try:
                paths = store.publish(folder, [f for f in fmts if f != IMAGE_EXPORT])  # (7-c) publish never sees image
            finally:
                export_warnings.reset(token)
            paths_iter = iter(paths)
            export_paths = tuple(os.path.join(folder, *img.rel_path.split('/')) if f == IMAGE_EXPORT else next(paths_iter)
                                 for f in written_fmts)
            if progress is not None:
                progress('exports', written_fmts)

            return DumpResult(path=folder, target=opened.info, report=report, counts=dict(wr.counts),
                              unverified=report.unverified, exports=written_fmts, export_paths=export_paths,
                              warnings=tuple(warning_list), seconds=time.perf_counter() - t0, remote_calls=results,
                              quality=wr.quality)
        finally:
            opened.close()
    finally:
        if log_handler is not None:
            ue_logger.removeHandler(log_handler)
            log_handler.close()
            ue_logger.setLevel(prev_level)


# --------------------------------------------------------------------------------------------
# write_profile / list_targets
# --------------------------------------------------------------------------------------------

def write_profile(report: ProbeReport, *, out=None):
    if not isinstance(report, ProbeReport):
        raise TypeError(f'report must be a ProbeReport, got {type(report).__name__}')
    root = store.resolve_out_root(out, internal=report.target.mode == 'internal')  # before anything else (G7.3)

    from .engine.state import FChunkedFixedUObjectArrayLayouts
    default_layout = dataclasses.astuple(FChunkedFixedUObjectArrayLayouts[0])

    info = report.target
    rows = {v.key: v for v in report.values}
    pins = []
    if 'objects' in report.steps:
        chunked = rows.get('Off.FUObjectArray.bIsChunked')
        gobjects = rows.get('Off.InSDK.ObjArray.GObjects')
        if chunked is not None and chunked.value is True and gobjects is not None and isinstance(gobjects.value, int):
            kwargs = {}
            chunk_size = rows.get('Off.InSDK.ObjArray.ChunkSize')
            if chunk_size is not None and chunk_size.value != 0x10000:
                kwargs['elements_per_chunk'] = chunk_size.value
            layout_row = rows.get('Off.FUObjectArray.ChunkedFixedLayout')
            if layout_row is not None and layout_row.value != default_layout:
                kwargs['layout'] = layout_row.value
            pins.append(profiles.Pin('gobjects', rva=gobjects.value, build=info.pe_timestamp,
                                     image_size=info.size_of_image, **kwargs))
    if 'names' in report.steps:
        gnames = rows.get('Off.InSDK.NameArray.GNames')
        if gnames is not None and isinstance(gnames.value, int):
            pins.append(profiles.Pin('gnames', rva=gnames.value, build=info.pe_timestamp, image_size=info.size_of_image))

    name = report.game_name or _exe_stem(info.exe)
    text = profiles.render_profile(info.exe, name, pins, when=datetime.datetime.now().astimezone())
    try:
        path = profiles.write_profile_file(os.path.join(root, store.PROFILES_DIR, f'{store.safe_dir_name(name)}.toml'), text)
    except FileExistsError as e:
        e.profile_text = text  # F7.1 = A: lets the CLI show what would have been written (I4)
        raise
    return path, tuple(p.name for p in pins)


def _w16(text: str) -> bytes:
    return re.escape(text.encode('utf-16-le'))


_ENGINE_HINT_RE = re.compile(_w16('++UE') + rb'[45]\x00' + _w16('+Release-') + rb'(?:[0-9]\x00)+' + _w16('.') + rb'(?:[0-9]\x00)+')


def _find_engine_hint(source, image) -> str | None:
    sc = scan.Scanner(source, image)
    for section in image.sections:
        if section.executable:
            continue
        for _addr, data in sc.chunks(section):
            if m := _ENGINE_HINT_RE.search(data):
                return m.group(0).decode('utf-16-le')
    return None


def _profile_status(root: str, exe: str, image):
    matches = profiles.find_profiles(root, exe)
    if not matches:
        return None, '-'
    if len(matches) > 1:
        return None, f'ambiguous ({len(matches)} profiles)'
    prof = matches[0]
    name = os.path.basename(prof.path) if prof.path else None
    rva_pins = [p for p in prof.pins.values() if p.rva is not None]
    if not rva_pins:
        return name, 'no rva pins'
    ok = all(p.build == image.timestamp and (p.image_size is None or p.image_size == image.size) for p in rva_pins)
    return name, ('build matches' if ok else 'build differs')


def _inspect_candidate(pid: int, exe_name: str, root: str) -> TargetRow:
    try:
        process = memory.open_process(pid)
    except errors.TargetError as e:
        return TargetRow(pid=pid, exe=exe_name, engine_hint=None, note=e.reason, profile=None, profile_status='-')
    try:
        source = memory.ProcessSource(process, cache=False)
        main = source.main_module
        image = pe.PeImage(source, main.base)
        engine_hint = _find_engine_hint(source, image)
        profile_name, profile_status = _profile_status(root, main.name, image)
        return TargetRow(pid=pid, exe=main.name, engine_hint=engine_hint, note='', profile=profile_name,
                         profile_status=profile_status)
    except (errors.UeError, OSError) as e:
        return TargetRow(pid=pid, exe=exe_name, engine_hint=None, note=f'{type(e).__name__}: {e}', profile=None,
                         profile_status='-')
    finally:
        process.close()


def list_targets(*, out=None) -> list:
    root = store.resolve_out_root(out)
    rows = [_inspect_candidate(pid, exe, root) for pid, exe in _iter_unique_processes() if UE_EXE_RE.search(exe)]
    rows.sort(key=lambda r: r.pid)
    return rows
