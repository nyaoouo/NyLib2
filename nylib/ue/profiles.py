"""TOML game profiles: parsing, validation, auto-pickup and a minimal writer (I1)."""
import dataclasses
import datetime
import importlib.util
import logging
import os
import pathlib
import re
import tomllib

from .. import pattern
from .errors import ProfileError

logger = logging.getLogger('nylib.ue.profiles')

GLOBAL_PINS = ('gobjects', 'gnames', 'process_event')
HOOK_NAMES = ('decrypt_objects',)
LAYOUT_FIELDS = ('ObjectsOffset', 'MaxElementsOffset', 'NumElementsOffset', 'MaxChunksOffset', 'NumChunksOffset')

_GLOBAL_KEYS = {
    'gobjects': {'rva', 'sig', 'build', 'image_size', 'elements_per_chunk', 'layout', 'note'},
    'gnames': {'rva', 'sig', 'build', 'image_size', 'note'},
    'process_event': {'index', 'note'},
}
_OFFSET_KEY_RE = re.compile(r'[A-Za-z_]\w*(\.[A-Za-z_]\w*)+')
_BARE_KEY_RE = re.compile(r'[A-Za-z0-9_-]+')


def _is_int(x) -> bool:
    return isinstance(x, int) and not isinstance(x, bool)


@dataclasses.dataclass(frozen=True)
class Pin:
    name: str
    rva: int | None = None
    sig: str | None = None
    index: int | None = None
    build: int | None = None
    image_size: int | None = None
    elements_per_chunk: int | None = None
    layout: tuple[int, int, int, int, int] | None = None
    note: str | None = None


@dataclasses.dataclass(frozen=True)
class Profile:
    path: str | None
    exe: str | None
    pins: dict
    offsets: dict
    hooks: dict


def _check_int(p, name: str, key: str, value, lo: int, hi: int, exclusive_lo: bool):
    if not _is_int(value):
        raise ProfileError(p, f'[globals] {name}.{key} must be an int')
    ok = (lo < value < hi) if exclusive_lo else (lo <= value < hi)
    if not ok:
        bound = f'{lo:#x} < x < {hi:#x}' if exclusive_lo else f'{lo:#x} <= x < {hi:#x}'
        raise ProfileError(p, f'[globals] {name}.{key} must be in range {bound}')
    return value


def _parse_layout(v, p, name):
    if not isinstance(v, dict) or set(v) != set(LAYOUT_FIELDS):
        raise ProfileError(p, f'[globals] {name}.layout must be a table with exactly {", ".join(LAYOUT_FIELDS)}')
    return tuple(_check_int(p, name, f'layout.{f}', v[f], 0, 0x100, False) for f in LAYOUT_FIELDS)


def _parse_pin(name, v, p):
    kwargs = {}
    if name in ('gobjects', 'gnames'):
        has_rva, has_sig = 'rva' in v, 'sig' in v
        if has_rva == has_sig:
            raise ProfileError(p, f'[globals] {name} needs exactly one of rva, sig')
        if has_rva and 'build' not in v:
            raise ProfileError(p, f'[globals] {name} rva needs build')
        if has_sig and ('build' in v or 'image_size' in v):
            raise ProfileError(p, f'[globals] {name} sig takes no build')
        if has_rva:
            kwargs['rva'] = _check_int(p, name, 'rva', v['rva'], 0, 2 ** 31, True)
        if has_sig:
            sig = v['sig']
            if not isinstance(sig, str):
                raise ProfileError(p, f'[globals] {name}.sig must be a string')
            try:
                pattern.compile_pattern(sig)
            except Exception as e:
                raise ProfileError(p, f'[globals] {name} sig is not a valid pattern: {e}') from e
            kwargs['sig'] = sig
        if 'build' in v:
            kwargs['build'] = _check_int(p, name, 'build', v['build'], 0, 2 ** 32, False)
        if 'image_size' in v:
            kwargs['image_size'] = _check_int(p, name, 'image_size', v['image_size'], 0, 2 ** 32, True)
        if name == 'gobjects':
            if 'elements_per_chunk' in v:
                kwargs['elements_per_chunk'] = _check_int(p, name, 'elements_per_chunk', v['elements_per_chunk'], 0, 2 ** 31, True)
            if 'layout' in v:
                kwargs['layout'] = _parse_layout(v['layout'], p, name)
    else:  # process_event
        if 'index' not in v:
            raise ProfileError(p, f'[globals] {name} needs index')
        kwargs['index'] = _check_int(p, name, 'index', v['index'], 0, 0x10000, False)
    if 'note' in v:
        if not isinstance(v['note'], str):
            raise ProfileError(p, f'[globals] {name}.note must be a string')
        kwargs['note'] = v['note']
    return Pin(name=name, **kwargs)


def _parse_match(table, p):
    for k in table:
        if k != 'exe':
            raise ProfileError(p, f'unknown key [match] {k}')
    exe = table.get('exe')
    if exe is None:
        return None
    if not isinstance(exe, str) or not exe:
        raise ProfileError(p, '[match] exe must be a non-empty string')
    return exe


def _parse_globals(table, p):
    pins = {}
    for name, v in table.items():
        if name not in GLOBAL_PINS:
            raise ProfileError(p, f'unknown key [globals] {name}')
        if not isinstance(v, dict):
            raise ProfileError(p, f'[globals] {name} must be a table')
        for k2 in v:
            if k2 not in _GLOBAL_KEYS[name]:
                raise ProfileError(p, f'unknown key [globals] {name}.{k2}')
        pins[name] = _parse_pin(name, v, p)
    return pins


def _flatten_offsets(table, prefix, out, p):
    for k, v in table.items():
        key = f'{prefix}.{k}' if prefix else k
        if isinstance(v, dict):
            _flatten_offsets(v, key, out, p)
        else:
            if key in out:
                raise ProfileError(p, f'[offsets] {key} is given twice')
            out[key] = v


def _parse_offsets(table, p):
    flat = {}
    _flatten_offsets(table, '', flat, p)
    out = {}
    for k, v in flat.items():
        if not _OFFSET_KEY_RE.fullmatch(k):
            raise ProfileError(p, f'[offsets] {k} is not a valid key')
        if not _is_int(v) or not (0 <= v < 2 ** 31):
            raise ProfileError(p, f'[offsets] {k} must be an int in range 0x0 <= x < 0x80000000')
        out[k] = v
    return out


def _parse_hooks(table, p):
    hooks = {}
    for name, v in table.items():
        if name not in HOOK_NAMES:
            raise ProfileError(p, f'unknown key [hooks] {name}')
        if not isinstance(v, str) or ':' not in v:
            raise ProfileError(p, f'[hooks] {name} must be a string FILE:FUNC')
        file_part, _, func_part = v.rpartition(':')
        if not func_part.isidentifier():
            raise ProfileError(p, f'[hooks] {name} FUNC must be an identifier')
        if not file_part.endswith('.py'):
            raise ProfileError(p, f'[hooks] {name} FILE must end with .py')
        pure = pathlib.PureWindowsPath(file_part)
        if pure.drive:
            raise ProfileError(p, f'[hooks] {name} FILE must have no drive')
        if pure.is_absolute() or pure.root:
            raise ProfileError(p, f'[hooks] {name} FILE must not be absolute')
        if '..' in pure.parts:
            raise ProfileError(p, f'[hooks] {name} FILE must not contain ..')
        hooks[name] = (file_part, func_part)
    return hooks


def parse_profile(text: str, path=None) -> Profile:
    if not isinstance(text, str):
        raise TypeError(f'text must be str, got {type(text).__name__}')
    if path is not None and not isinstance(path, (str, os.PathLike)):
        raise TypeError(f'path must be str, os.PathLike or None, got {type(path).__name__}')
    p = os.path.abspath(path) if path is not None else '<string>'
    try:
        doc = tomllib.loads(text)
    except tomllib.TOMLDecodeError as e:
        raise ProfileError(p, f'not valid TOML: {e}') from e

    for k, v in doc.items():
        if k not in ('match', 'globals', 'offsets', 'hooks'):
            raise ProfileError(p, f'unknown table [{k}]')
        if not isinstance(v, dict):
            raise ProfileError(p, f'[{k}] must be a table')

    exe = _parse_match(doc['match'], p) if 'match' in doc else None
    pins = _parse_globals(doc['globals'], p) if 'globals' in doc else {}
    offsets = _parse_offsets(doc['offsets'], p) if 'offsets' in doc else {}
    hooks = _parse_hooks(doc['hooks'], p) if 'hooks' in doc else {}

    if 'gobjects' in pins and 'decrypt_objects' in hooks:
        raise ProfileError(p, '[globals] gobjects cannot be combined with [hooks] decrypt_objects: '
                               'a pinned GObjects is read without decryption')

    return Profile(path=os.path.abspath(path) if path is not None else None, exe=exe, pins=pins, offsets=offsets, hooks=hooks)


def load_profile(path) -> Profile:
    if not isinstance(path, (str, os.PathLike)):
        raise TypeError(f'path must be str or os.PathLike, got {type(path).__name__}')
    abs_path = os.path.abspath(path)
    try:
        with open(path, 'rb') as f:
            raw = f.read()
    except OSError as e:
        raise ProfileError(abs_path, f'cannot read: {e.strerror or e}') from e
    try:
        text = raw.decode('utf-8-sig')
    except UnicodeDecodeError:
        raise ProfileError(abs_path, 'not UTF-8')
    return parse_profile(text, path)


def find_profiles(out_root, exe: str) -> list:
    if not isinstance(exe, str):
        raise TypeError(f'exe must be str, got {type(exe).__name__}')
    if not exe:
        raise ValueError('exe must be a non-empty string')
    folder = os.path.join(os.fspath(out_root), 'profiles')
    try:
        names = sorted(n for n in os.listdir(folder) if n.lower().endswith('.toml'))
    except FileNotFoundError:
        return []
    target = exe.casefold()
    found = []
    for name in names:
        path = os.path.join(folder, name)
        try:
            prof = load_profile(path)
        except ProfileError as e:
            logger.warning('skipping profile %s: %s', e.path, e.reason)
            continue
        if prof.exe is not None and prof.exe.casefold() == target:
            found.append(prof)
    return found


def load_hook(profile: Profile, name: str):
    if name not in profile.hooks:
        raise KeyError(name)
    if profile.path is None:
        raise ProfileError('<string>', 'hooks need a profile file')
    file_rel, func_name = profile.hooks[name]
    logger.warning('hook %s:%s (profile %s)', file_rel, func_name, profile.path)
    hook_path = os.path.join(os.path.dirname(profile.path), file_rel)
    if not os.path.isfile(hook_path):
        raise ProfileError(profile.path, f'hook file {file_rel} not found')
    spec = importlib.util.spec_from_file_location(f'_nylib_ue_hook_{id(profile)}_{name}', hook_path)
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except Exception as e:
        raise ProfileError(profile.path, f'hook {file_rel}:{func_name} failed to load: {type(e).__name__}: {e}') from e
    func = getattr(module, func_name, None)
    if func is None or not callable(func):
        raise ProfileError(profile.path, f'hook {file_rel}:{func_name} is not a function')
    return func


def _dump_basic_string(s: str) -> str:
    out = []
    for ch in s:
        cp = ord(ch)
        if 0xD800 <= cp <= 0xDFFF:
            raise ValueError(f'invalid string: lone surrogate U+{cp:04X}')
        if ch == '\\':
            out.append('\\\\')
        elif ch == '"':
            out.append('\\"')
        elif ch == '\b':
            out.append('\\b')
        elif ch == '\t':
            out.append('\\t')
        elif ch == '\n':
            out.append('\\n')
        elif ch == '\f':
            out.append('\\f')
        elif ch == '\r':
            out.append('\\r')
        elif cp < 0x20 or cp == 0x7F:
            out.append(f'\\u{cp:04X}')
        else:
            out.append(ch)
    return '"' + ''.join(out) + '"'


def _dump_key(k) -> str:
    if not isinstance(k, str):
        raise TypeError(f'key must be str, got {type(k).__name__}')
    return k if _BARE_KEY_RE.fullmatch(k) else _dump_basic_string(k)


def _dump_value(v) -> str:
    if isinstance(v, bool):
        return 'true' if v else 'false'
    if isinstance(v, int):
        return f'0x{v:X}' if v >= 0 else str(v)
    if isinstance(v, str):
        return _dump_basic_string(v)
    if isinstance(v, dict):
        if not v:
            return '{}'
        return '{ ' + ', '.join(f'{_dump_key(k)} = {_dump_value(val)}' for k, val in v.items()) + ' }'
    raise TypeError(f'unsupported value type {type(v).__name__}')


def toml_dumps(tables: dict, *, header=(), comments=None) -> str:
    if not isinstance(tables, dict):
        raise TypeError(f'tables must be a mapping, got {type(tables).__name__}')
    comments = comments or {}
    lines = []
    for line in header:
        if '\n' in line or '\r' in line:
            raise ValueError('header line must not contain a newline')
        lines.append(f'# {line}')
    lines.append('')
    names = list(tables)
    for i, name in enumerate(names):
        body = tables[name]
        if not isinstance(body, dict):
            raise TypeError(f'[{name}] must be a mapping, got {type(body).__name__}')
        lines.append(f'[{name}]')
        for line in comments.get(name, ()):
            if '\n' in line or '\r' in line:
                raise ValueError(f'comment line for [{name}] must not contain a newline')
            lines.append(f'# {line}')
        for k, v in body.items():
            lines.append(f'{_dump_key(k)} = {_dump_value(v)}')
        if i != len(names) - 1:
            lines.append('')
    return '\n'.join(lines) + '\n'


def _pin_table(pin: Pin) -> dict:
    d = {}
    for f in dataclasses.fields(pin):
        if f.name == 'name':
            continue
        v = getattr(pin, f.name)
        if v is None:
            continue
        if f.name == 'layout':
            d['layout'] = {LAYOUT_FIELDS[i]: v[i] for i in range(len(LAYOUT_FIELDS))}
        else:
            d[f.name] = v
    return d


def render_profile(exe: str, game_name: str, pins, *, when: datetime.datetime) -> str:
    if not isinstance(exe, str):
        raise TypeError(f'exe must be str, got {type(exe).__name__}')
    if not isinstance(game_name, str):
        raise TypeError(f'game_name must be str, got {type(game_name).__name__}')
    if not isinstance(when, datetime.datetime):
        raise TypeError(f'when must be datetime.datetime, got {type(when).__name__}')
    by_name = {}
    for pin in pins:
        if not isinstance(pin, Pin):
            raise TypeError(f'pins must contain Pin instances, got {type(pin).__name__}')
        if pin.name in by_name:
            raise ValueError(f'duplicate pin name {pin.name!r}')
        by_name[pin.name] = pin

    lines = [
        f'# nylib.ue profile for {game_name}',
        '# Written by "nylib.ue probe --write-profile" on ' + when.strftime('%Y-%m-%d %H:%M') + '; edit freely.',
        '# Values here replace automatic detection. A profile can never enable remote calls.',
        '',
        '[match]',
        f'exe = {_dump_value(exe)}',
        '',
        '[globals]',
        '# An rva is only trusted for the build it was found in; a sig survives game updates.',
    ]
    for name in ('gobjects', 'gnames'):
        pin = by_name.get(name)
        if pin is not None:
            lines.append(f'{name} = {_dump_value(_pin_table(pin))}')
        else:
            lines.append(f'# {name} = {{ rva = 0x1000, build = 0x12345678 }}')
    pe_pin = by_name.get('process_event')
    if pe_pin is not None:
        lines.append(f'process_event = {_dump_value(_pin_table(pe_pin))}')
    lines += [
        '',
        '[offsets]',
        '# "UStruct.MinAlignment" = 0x5C',
        '',
        '[hooks]',
        '# FILE:FUNC relative to this file; runs locally (in the dumper, or in the game with --inject)',
        '# decrypt_objects = "hooks.py:decrypt_objects"',
    ]
    return '\n'.join(lines) + '\n'


def write_profile_file(path, text: str) -> str:
    if not isinstance(path, (str, os.PathLike)):
        raise TypeError(f'path must be str or os.PathLike, got {type(path).__name__}')
    if not isinstance(text, str):
        raise TypeError(f'text must be str, got {type(text).__name__}')
    path = os.fspath(path)
    if os.path.exists(path):
        raise FileExistsError(path)
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(path, 'w', encoding='utf-8', newline='\n') as f:
        f.write(text)
    return path
