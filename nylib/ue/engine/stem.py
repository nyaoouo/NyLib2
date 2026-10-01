"""Read-only stem: the engine version and project name that main.cpp @ ea0dab3 gets through ProcessEvent (DV6, P11)."""
import dataclasses
import ntpath
import re
import struct

from ..errors import MemoryReadError
from .accessor import view
from .containers import FString
from .utfn import utf_16_string_to_utf_8_string

_SCN_MEM_READ = 0x40000000  # IMAGE_SCN_MEM_READ
_SCN_MEM_WRITE = 0x80000000  # IMAGE_SCN_MEM_WRITE
_RT_VERSION = 16
_MAX_VERSION_DATA = 0x10000
_FIXED_FILE_INFO_SIG = struct.pack('<I', 0xFEEF04BD)
_INTERNAL_NAME_KEY = 'InternalName\0'.encode('utf-16-le')


def _w(text: str) -> bytes:
    return re.escape(text.encode('utf-16-le'))


_BRANCH = re.compile(_w('++UE') + rb'[45]\x00' + _w('+Release-') + rb'((?:[0-9]\x00)+)' + _w('.') + rb'((?:[0-9]\x00)+)\x00\x00')


@dataclasses.dataclass(frozen=True)
class Stem:
    engine_version: str
    game_name: str
    branch: str | None = None
    file_version: str | None = None
    internal_name: str | None = None

    @property
    def stem(self) -> str:
        """Dumper-7's GameVersion + '-' + GameName."""
        return f'{self.engine_version}-{self.game_name}'


class _Malformed(Exception):
    pass


def _sections(e, flag: int):
    return [s for s in e.platform.image.sections if s.characteristics & flag]


def _find_even(data: bytes, needle: bytes, base: int, start: int = 0) -> int:
    i = data.find(needle, start)
    while i >= 0 and (base + i) & 1:
        i = data.find(needle, i + 1)
    return i


def _failed(e, source: str, reason: str) -> None:
    e.cerr(f'Stem: {source} not usable: {reason}\n')


def _find_branch(e) -> tuple[str, int, int] | None:
    sc = e.platform.scanner
    for s in _sections(e, _SCN_MEM_READ):
        for addr, data in sc.chunks(s):
            pos = 0
            while m := _BRANCH.search(data, pos):
                if (addr + m.start()) & 1 == 0:
                    return m[0][:-2].decode('utf-16-le'), int(m[1][::2]), int(m[2][::2])
                pos = m.start() + 1
    return None


def _version_resource(e, base: int) -> tuple[str | None, str | None]:
    mem = e.mem
    opt = base + mem.u32(base + 0x3C) + 24
    if mem.u16(opt) != 0x20B or mem.u32(opt + 0x6C) <= 2:  # PE32+, NumberOfRvaAndSizes covers RESOURCE
        raise _Malformed('no resource data directory')
    rva, size = struct.unpack('<II', mem.read(opt + 0x70 + 2 * 8, 8))
    if not rva or not size:
        raise _Malformed('no resource directory')
    res = base + rva

    def entries(offset: int) -> tuple[list[tuple[int, int]], int]:
        if offset + 16 > size:
            raise _Malformed(f'directory at {offset:#x} outside the resource directory')
        named, ids = struct.unpack('<HH', mem.read(res + offset + 12, 4))
        if offset + 16 + 8 * (named + ids) > size:
            raise _Malformed(f'entries at {offset:#x} outside the resource directory')
        raw = mem.read(res + offset + 16, 8 * (named + ids))
        return [struct.unpack_from('<II', raw, 8 * i) for i in range(named + ids)], named

    def subdirectory(entry: tuple[int, int] | None) -> int:
        if entry is None or not entry[1] & 0x80000000:
            raise _Malformed('missing resource subdirectory')
        return entry[1] & 0x7FFFFFFF

    root, named = entries(0)
    level2 = entries(subdirectory(next((x for x in root[named:] if x[0] == _RT_VERSION), None)))[0]
    level3 = entries(subdirectory(level2[0] if level2 else None))[0]
    if not level3 or level3[0][1] & 0x80000000 or level3[0][1] + 16 > size:
        raise _Malformed('missing RT_VERSION data entry')
    data_rva, data_size = struct.unpack('<II', mem.read(res + level3[0][1], 8))
    data = mem.read(base + data_rva, min(data_size, _MAX_VERSION_DATA))

    file_version = internal_name = None
    i = data.find(_FIXED_FILE_INFO_SIG)
    while i >= 0 and i & 3:
        i = data.find(_FIXED_FILE_INFO_SIG, i + 1)
    if i >= 0:
        if i + 16 > len(data):
            raise _Malformed('truncated VS_FIXEDFILEINFO')
        ms, ls = struct.unpack_from('<II', data, i + 8)
        file_version = f'{ms >> 16}.{ms & 0xFFFF}.{ls >> 16}.{ls & 0xFFFF}'
    if (i := _find_even(data, _INTERNAL_NAME_KEY, 0)) >= 0:
        start = (i + len(_INTERNAL_NAME_KEY) + 3) & ~3
        if (end := _find_even(data, b'\0\0', 0, start)) < 0:
            raise _Malformed('unterminated InternalName')
        internal_name = utf_16_string_to_utf_8_string(data[start:end].decode('utf-16-le', 'surrogatepass')) or None
    return file_version, internal_name


def _engine_version_from_memory(e, branch: str, x: int, y: int) -> str | None:
    if x > 0xFFFF or y > 0xFFFF:
        _failed(e, 'FEngineVersion::Current (memory)', '0 candidates')
        return None
    sc, key, found = e.platform.scanner, struct.pack('<HH', x, y), []
    for s in _sections(e, _SCN_MEM_WRITE):
        for addr, data in sc.chunks(s):
            i = data.find(key)
            while i >= 0:
                if (p := addr + i) & 7 == 0 and s.contains(p + 0x20):
                    fs = view(FString, p + 0x10, e.acc)
                    if fs.is_valid() and fs.to_wstring() == branch:
                        found.append(p)
                i = data.find(key, i + 1)
    if len(found) == 1 or (len(found) == 2 and found[1] - found[0] == 0x20):
        p = found[0]
        return f'{x}.{y}.{e.mem.u16(p + 4)}-{e.mem.u32(p + 8) & 0x7FFFFFFF}+{branch}'
    _failed(e, 'FEngineVersion::Current (memory)', f'{len(found)} candidates')
    return None


def _project_name_from_memory(e, path: str) -> str | None:
    head, exe = ntpath.split(path)
    head, win64 = ntpath.split(head)
    head, binaries = ntpath.split(head)
    project = ntpath.split(head)[1]
    if not (exe and project and binaries.lower() == 'binaries' and win64.lower() == 'win64'):
        _failed(e, 'FApp::GetProjectName (memory)', f'{path!r} is not <Project>\\Binaries\\Win64\\<exe>')
        return None
    needle, sc = (project + '\0').encode('utf-16-le', 'surrogatepass'), e.platform.scanner
    for s in _sections(e, _SCN_MEM_WRITE):
        for addr, data in sc.chunks(s):
            if _find_even(data, needle, addr) >= 0:
                return utf_16_string_to_utf_8_string(project)
    _failed(e, 'FApp::GetProjectName (memory)', f'{project!r} not found in a writable section')
    return None


def detect_stem(e) -> Stem:
    """main.cpp @ ea0dab3 GetGameName / GetEngineVersion, read from memory instead of called (DV6)."""
    module = e.mem.main_module
    branch = file_version = internal_name = None

    try:
        if (found := _find_branch(e)) is None:
            _failed(e, 'branch string', 'not found')
    except MemoryReadError as ex:
        found = None
        _failed(e, 'branch string', str(ex))
    if found:
        branch, x, y = found

    try:
        file_version, internal_name = _version_resource(e, module.base)
    except (MemoryReadError, _Malformed) as ex:
        _failed(e, 'version resource', str(ex))

    engine_version, version_from = 'unknown', 'not found: no engine version source'
    if branch is None:
        _failed(e, 'FEngineVersion::Current (memory)', 'no branch string')
        _failed(e, 'file version', 'no branch string')
        _failed(e, 'branch string fallback', 'no branch string')
    else:
        try:
            v = _engine_version_from_memory(e, branch, x, y)
        except MemoryReadError as ex:
            v = None
            _failed(e, 'FEngineVersion::Current (memory)', str(ex))
        if v is not None:
            engine_version, version_from = v, 'auto: FEngineVersion::Current (memory)'
        elif file_version is not None and tuple(map(int, file_version.split('.')[:2])) == (x, y):
            a, b, c, _ = file_version.split('.')
            engine_version, version_from = f'{a}.{b}.{c}-0+{branch}', 'fallback: file version'
        else:
            _failed(e, 'file version', f'{file_version} is not {x}.{y}.*' if file_version else 'no VS_FIXEDFILEINFO')
            engine_version, version_from = f'{x}.{y}.0-0+{branch}', 'fallback: branch string'

    try:
        game_name = _project_name_from_memory(e, module.path)
    except MemoryReadError as ex:
        game_name = None
        _failed(e, 'FApp::GetProjectName (memory)', str(ex))
    name_from = 'auto: FApp::GetProjectName (memory)'
    if game_name is None:
        if internal_name and (name := internal_name[:-4] if internal_name.lower().endswith('.exe') else internal_name):
            game_name, name_from = name, 'fallback: version resource InternalName'
        else:
            _failed(e, 'version resource InternalName', 'empty' if internal_name else 'absent')
            game_name, name_from = ntpath.splitext(module.name)[0].split('-', 1)[0], 'fallback: exe name'

    e.settings.Generator.GameName = game_name
    e.provenance['Settings.Generator.GameName'] = name_from
    e.settings.Generator.GameVersion = engine_version
    e.provenance['Settings.Generator.GameVersion'] = version_from
    return Stem(engine_version, game_name, branch, file_version, internal_name)
