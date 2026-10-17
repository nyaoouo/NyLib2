"""Fetch, link, verify, install, and scan the bundled Oodle Data and Oodle Network DLLs.

Links oo2core_9_win64.dll / oo2net_9_win64.dll from UE 5.7.4's static libraries
(see nylib/utils/oodle/PROVENANCE.md for the rebuild story).
"""
import argparse
import gzip
import hashlib
import os
import pathlib
import re
import shutil
import struct
import subprocess
import sys
import urllib.request
import xml.etree.ElementTree as ET

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))  # repo root isn't on sys.path when run directly
from nylib.winutils.msvc import load_vcvarsall
from nylib.winutils.pe_map import parse_image

# -- Provenance (F1-F2): tag 5.7.4-release, Engine/Build/Commit.gitdeps.xml -----

UE_TAG = '5.7.4-release'
UE_COMMIT = '260bb2e1c5610b31c63a36206eedd289409c5f11'

LIB_FILES = {
    'core': ('Engine/Source/Runtime/OodleDataCompression/Sdks/2.9.14/lib/Win64/oo2core_win64.lib',
              'bf36d7973361b14ac64fdce2e2cef7eb37af152b'),
    'net': ('Engine/Plugins/Compression/OodleNetwork/Sdks/2.9.14/lib/Win64/oo2net_win64.lib',
             '2348c041f6fe3ec9598796b16ae1a93a0b9cf10b'),
}
LIB_FILENAMES = {'core': 'oo2core_win64.lib', 'net': 'oo2net_win64.lib'}
DLL_STEMS = {'core': 'oo2core_9_win64', 'net': 'oo2net_9_win64'}

# Every OOFUNC2-declared function in oodle2.h / oodle2net.h 2.9.14 (F4), sorted().
CORE_EXPORTS = (
    'OodleCore_Plugin_DisplayAssertion_Default', 'OodleCore_Plugin_Free_Default',
    'OodleCore_Plugin_MallocAligned_Default', 'OodleCore_Plugin_Printf_Default',
    'OodleCore_Plugin_Printf_Verbose', 'OodleCore_Plugin_RunJob_Default',
    'OodleCore_Plugin_WaitJob_Default', 'OodleCore_Plugins_SetAllocators',
    'OodleCore_Plugins_SetAssertion', 'OodleCore_Plugins_SetJobSystem',
    'OodleCore_Plugins_SetJobSystemAndCount', 'OodleCore_Plugins_SetPrintf',
    'OodleLZDecoder_Create', 'OodleLZDecoder_DecodeSome', 'OodleLZDecoder_Destroy',
    'OodleLZDecoder_MakeValidCircularWindowSize', 'OodleLZDecoder_MemorySizeNeeded',
    'OodleLZDecoder_Reset', 'OodleLZ_CheckSeekTableCRCs', 'OodleLZ_Compress',
    'OodleLZ_CompressOptions_GetDefault', 'OodleLZ_CompressOptions_Validate',
    'OodleLZ_CompressionLevel_GetName', 'OodleLZ_Compressor_GetName',
    'OodleLZ_CreateSeekTable', 'OodleLZ_Decompress', 'OodleLZ_FillSeekTable',
    'OodleLZ_FindSeekEntry', 'OodleLZ_FreeSeekTable', 'OodleLZ_GetAllChunksCompressor',
    'OodleLZ_GetChunkCompressor', 'OodleLZ_GetCompressScratchMemBound',
    'OodleLZ_GetCompressScratchMemBoundEx', 'OodleLZ_GetCompressedBufferSizeNeeded',
    'OodleLZ_GetCompressedStepForRawStep', 'OodleLZ_GetDecodeBufferSize',
    'OodleLZ_GetFirstChunkCompressor', 'OodleLZ_GetInPlaceDecodeBufferSize',
    'OodleLZ_GetNumSeekChunks', 'OodleLZ_GetSeekEntryPackedPos',
    'OodleLZ_GetSeekTableMemorySizeNeeded', 'OodleLZ_Jobify_GetName',
    'OodleLZ_MakeSeekChunkLen', 'OodleLZ_ThreadPhased_BlockDecoderMemorySizeNeeded',
    'Oodle_CheckVersion', 'Oodle_GetConfigValues', 'Oodle_LogHeader',
    'Oodle_SetConfigValues', 'Oodle_SetUsageWarnings',
)
NET_EXPORTS = (
    'OodleNet_Plugin_DisplayAssertion_Default', 'OodleNet_Plugin_Free_Default',
    'OodleNet_Plugin_MallocAligned_Default', 'OodleNet_Plugin_Printf_Default',
    'OodleNet_Plugin_Printf_Verbose', 'OodleNet_Plugin_RunJob_Default',
    'OodleNet_Plugin_WaitJob_Default', 'OodleNet_Plugins_SetAllocators',
    'OodleNet_Plugins_SetAssertion', 'OodleNet_Plugins_SetJobSystem',
    'OodleNet_Plugins_SetJobSystemAndCount', 'OodleNet_Plugins_SetPrintf',
    'OodleNetwork1TCP_Decode', 'OodleNetwork1TCP_Encode',
    'OodleNetwork1TCP_State_InitAsCopy', 'OodleNetwork1TCP_State_Reset',
    'OodleNetwork1TCP_State_Size', 'OodleNetwork1TCP_Train',
    'OodleNetwork1UDP_Decode', 'OodleNetwork1UDP_Encode',
    'OodleNetwork1UDP_StateCompacted_MaxSize', 'OodleNetwork1UDP_State_Compact',
    'OodleNetwork1UDP_State_Compact_ForVersion', 'OodleNetwork1UDP_State_Size',
    'OodleNetwork1UDP_State_Uncompact', 'OodleNetwork1UDP_State_Uncompact_ForVersion',
    'OodleNetwork1UDP_Train', 'OodleNetwork1_CompressedBufferSizeNeeded',
    'OodleNetwork1_SelectDictionaryFromPackets',
    'OodleNetwork1_SelectDictionaryFromPackets_Trials',
    'OodleNetwork1_SelectDictionarySupported', 'OodleNetwork1_Shared_SetWindow',
    'OodleNetwork1_Shared_Size',
)
EXPORTS = {'core': CORE_EXPORTS, 'net': NET_EXPORTS}

# Toolset/SDK recorded by the first successful build on this machine (S1.1/S1.2, F27).
DEFAULT_VCVARS = 'x64 10.0.28000.0 -vcvars_ver=14.51'

ALLOWED_IMPORT_EXACT = {'kernel32.dll', 'vcruntime140.dll'}
_ALLOWED_IMPORT_GLOB = re.compile(r'^api-ms-win-crt-.*\.dll$', re.IGNORECASE)

# Epic's build-machine path for the Oodle libs (F6); official Oodle DLLs carry the
# same prefix. Written without the trailing separator so this literal round-trips
# byte-for-byte through --scan on build.py's own source (Python escaping would
# otherwise double any backslash placed at the very end of a raw string).
ALLOWED_PATH_PREFIX = r'v:\devel\projects\oodle2'

_ASCII_RUN = re.compile(rb'[\x20-\x7e]{4,}')
_UTF16_RUN = re.compile(rb'(?:[\x20-\x7e]\x00){4,}')
_DRIVE_PATH = re.compile(r'(?<![A-Za-z])[A-Za-z]:[\\/]')
_USERS_HOME = re.compile(r'[\\/](users|home)[\\/]', re.IGNORECASE)
_UNC_PATH = re.compile(r'\\\\[^\\]+\\')

_IMAGE_DEBUG_TYPE_CODEVIEW = 2
_IMAGE_DEBUG_ENTRY_SIZE = 28


def _extract_strings(data: bytes) -> list[str]:
    """Pull printable ASCII and UTF-16LE runs out of raw bytes, per the scan rules (6.2)."""
    out = [m.group().decode('ascii') for m in _ASCII_RUN.finditer(data)]
    out += [m.group().decode('utf-16-le') for m in _UTF16_RUN.finditer(data)]
    return out


def _scan_string(s: str, is_dll: bool):
    """Classify one extracted string; return (hit message or None, allowlisted: bool)."""
    if m := _DRIVE_PATH.search(s):
        norm = s[m.start():].replace('/', '\\').lower()
        if norm.startswith(ALLOWED_PATH_PREFIX):
            return None, True
        return f'drive path: {s!r}', False
    if _USERS_HOME.search(s):
        return f'user/home path: {s!r}', False
    if is_dll:
        if _UNC_PATH.search(s):
            return f'UNC path: {s!r}', False
        low = s.lower()
        if 'nylib' in low:
            return f'nylib string: {s!r}', False
        if '.pdb' in low:
            return f'.pdb string: {s!r}', False
    return None, False


def scan_bytes(data: bytes, is_dll: bool) -> tuple[list[str], int]:
    """Return (hits, allowlisted_count) for raw file bytes, per the 6.2 rules."""
    hits = []
    allowlisted = 0
    for s in _extract_strings(data):
        hit, ok = _scan_string(s, is_dll)
        if hit:
            hits.append(hit)
        elif ok:
            allowlisted += 1
    return hits, allowlisted


def scan_path(path) -> tuple[list[str], int]:
    data = pathlib.Path(path).read_bytes()
    is_dll = str(path).lower().endswith('.dll') or data[:2] == b'MZ'
    return scan_bytes(data, is_dll)


def _rva_to_offset(parsed, rva: int) -> int:
    if rva < parsed.size_of_headers:
        return rva
    for s in parsed.sections:
        if s.target_rva <= rva < s.target_rva + s.source_size:
            return s.source_offset + (rva - s.target_rva)
    raise ValueError(f'rva {rva:#x} is not backed by file data')


def _has_codeview_entry(data: bytes, parsed) -> bool:
    """True if the Debug data directory carries an IMAGE_DEBUG_TYPE_CODEVIEW entry."""
    debug_dir = parsed.directories[6]
    if not debug_dir.size:
        return False
    offset = _rva_to_offset(parsed, debug_dir.rva)
    for i in range(debug_dir.size // _IMAGE_DEBUG_ENTRY_SIZE):
        type_, = struct.unpack_from('<I', data, offset + i * _IMAGE_DEBUG_ENTRY_SIZE + 12)
        if type_ == _IMAGE_DEBUG_TYPE_CODEVIEW:
            return True
    return False


def _sha1(path) -> str:
    return hashlib.sha1(pathlib.Path(path).read_bytes()).hexdigest()


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _toolchain_env(vcvars: str) -> dict:
    env = {k.upper(): v for k, v in os.environ.items()}
    env.update({k.upper(): v for k, v in load_vcvarsall(vcvars).items()})
    return env


def _find_tool(env: dict, name: str) -> str:
    # A subprocess with a custom env does not search that env's PATH for its own
    # argv[0] resolution on Windows, so the full path is resolved here and invoked
    # directly (prototype lesson).
    path = shutil.which(name, path=env.get('PATH', ''))
    if not path:
        raise FileNotFoundError(f'{name} not found via vcvarsall PATH')
    return path


def link_dll(kind: str, out_dir, *, libs_dir, exports=None, vcvars=DEFAULT_VCVARS) -> pathlib.Path:
    """Compile a minimal DllMain and link it against UE's static lib so it re-exports `exports`.

    `exports=None` links the full pinned tuple for `kind`.
    """
    exports = tuple(sorted(exports)) if exports is not None else EXPORTS[kind]
    lib_path = os.path.abspath(os.path.join(libs_dir, LIB_FILENAMES[kind]))
    if _sha1(lib_path) != LIB_FILES[kind][1]:
        raise ValueError(f'SHA-1 mismatch for {lib_path}')
    stem = DLL_STEMS[kind]
    work = pathlib.Path(out_dir).resolve()  # absolute: cl's cwd is `work`, so a relative arg would resolve twice
    work.mkdir(parents=True, exist_ok=True)
    def_path = work / f'{stem}.def'
    def_path.write_text('LIBRARY ' + stem + '\nEXPORTS\n' + ''.join(f'    {name}\n' for name in exports), encoding='ascii')
    c_path = work / 'dllmain.c'
    c_path.write_text('int __stdcall DllMain(void *h, unsigned long r, void *p) { return 1; }\n', encoding='ascii')
    out_path = work / f'{stem}.dll'
    env = _toolchain_env(vcvars)
    cl = _find_tool(env, 'cl.exe')
    _find_tool(env, 'link.exe')  # sanity: the linker must also be reachable through this PATH
    cmd = [cl, '/nologo', '/LD', '/MD', '/O2', '/Brepro', str(c_path), lib_path,
           '/link', f'/DEF:{def_path}', f'/OUT:{out_path}', '/Brepro', '/MANIFEST:NO']
    result = subprocess.run(cmd, cwd=work, env=env, capture_output=True, text=True)
    if result.returncode != 0:
        sys.stdout.write(result.stdout)
        sys.stderr.write(result.stderr)
        raise RuntimeError(f'cl/link failed for {kind} (rc={result.returncode})')
    return out_path


def _verify_dll(path, kind) -> dict:
    """Post-build checks (6.1): machine, exports, imports, no CodeView, path scan."""
    data = pathlib.Path(path).read_bytes()
    parsed = parse_image(data)
    if parsed.machine != 0x8664:
        raise RuntimeError(f'{path}: wrong machine {parsed.machine:#x}, expected AMD64')
    names = sorted(e.name for e in parsed.exports if e.name)
    expected = list(EXPORTS[kind])
    if names != expected:
        raise RuntimeError(f'{path}: export mismatch, missing {sorted(set(expected) - set(names))}, '
                            f'extra {sorted(set(names) - set(expected))}')
    if parsed.delay_imports:
        raise RuntimeError(f'{path}: has delay imports {[i.module for i in parsed.delay_imports]}')
    modules = sorted({i.module for i in parsed.imports})
    for module in modules:
        low = module.lower()
        if low not in ALLOWED_IMPORT_EXACT and not _ALLOWED_IMPORT_GLOB.match(low):
            raise RuntimeError(f'{path}: disallowed import module {module!r}')
    if _has_codeview_entry(data, parsed):
        raise RuntimeError(f'{path}: debug directory has a CodeView entry')
    hits, allowlisted = scan_bytes(data, True)
    if hits:
        raise RuntimeError(f'{path}: path scan failed: {hits[0]}')
    return {
        'path': path, 'exports': len(names), 'expected_exports': len(expected),
        'imports': modules, 'allowlisted': allowlisted, 'size': len(data),
        'sha256': _sha256_bytes(data),
    }


def _fetch_manifest(manifest_path: str, out_dir: str) -> str:
    root = ET.parse(manifest_path).getroot()
    base = root.get('BaseUrl')
    files = {f.get('Name'): f.get('Hash') for f in root.iter('File')}
    blobs = {b.get('Hash'): b for b in root.iter('Blob')}
    packs = {p.get('Hash'): p for p in root.iter('Pack')}
    os.makedirs(out_dir, exist_ok=True)
    cache = {}
    for kind, (name, sha1) in LIB_FILES.items():
        manifest_hash = files.get(name)
        if manifest_hash != sha1:
            print(f'manifest Hash for {name} is {manifest_hash!r}, expected {sha1!r}: SHA-1 mismatch')
            sys.exit(2)
        blob = blobs[manifest_hash]
        pack = packs[blob.get('PackHash')]
        pack_hash = pack.get('Hash')
        if pack_hash not in cache:
            url = f"{base}/{pack.get('RemotePath')}/{pack_hash}"
            print('fetching', url)
            data = urllib.request.urlopen(url, timeout=120).read()
            cache[pack_hash] = gzip.decompress(data)
        raw = cache[pack_hash]
        off, size = int(blob.get('PackOffset')), int(blob.get('Size'))
        body = raw[off:off + size]
        if hashlib.sha1(body).hexdigest() != sha1:
            print(f'fetched {name}: SHA-1 mismatch')
            sys.exit(2)
        dest = os.path.join(out_dir, LIB_FILENAMES[kind])
        tmp = dest + '.tmp'
        pathlib.Path(tmp).write_bytes(body)
        os.replace(tmp, dest)
    return out_dir


def _resolve_libs(args) -> str:
    """Return a directory holding verified oo2core_win64.lib / oo2net_win64.lib."""
    if args.libs:
        for kind, (_, sha1) in LIB_FILES.items():
            lib_path = os.path.join(args.libs, LIB_FILENAMES[kind])
            if _sha1(lib_path) != sha1:
                print(f'SHA-1 mismatch for {lib_path}')
                sys.exit(2)
        return args.libs
    return _fetch_manifest(args.manifest, os.path.join(args.work, 'libs'))


def _run_scan(paths) -> int:
    any_hit = False
    for p in paths:
        hits, allowlisted = scan_path(p)
        print(f'{p}: {len(hits)} hit(s), {allowlisted} allowlisted')
        for h in hits:
            print(f'  {h}')
            any_hit = True
    return 1 if any_hit else 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    libs_group = parser.add_mutually_exclusive_group()
    libs_group.add_argument('--manifest', help='UE Commit.gitdeps.xml to fetch the libs from')
    libs_group.add_argument('--libs', help='directory already holding the verified static libs')
    parser.add_argument('--work', default='scripts/oodle/build', help='scratch directory (default: scripts/oodle/build)')
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument('--install', action='store_true', help='copy the built DLLs into nylib/utils/oodle/')
    mode_group.add_argument('--check', action='store_true', help='compare SHA-256 with the installed DLLs; never writes them')
    parser.add_argument('--vcvars', default=DEFAULT_VCVARS, help='vcvarsall.bat arguments')
    parser.add_argument('--scan', nargs='+', metavar='PATH', help='run the path scan (6.2) on PATH... and exit')
    args = parser.parse_args(argv)

    if args.scan:
        return _run_scan(args.scan)
    if bool(args.manifest) == bool(args.libs):
        parser.error('exactly one of --manifest or --libs is required (unless --scan)')

    print(f'source: {UE_TAG} ({UE_COMMIT})')
    libs_dir = _resolve_libs(args)
    env = _toolchain_env(args.vcvars)
    sdk_version = env.get('WINDOWSSDKVERSION', '?').rstrip('\\')  # vcvarsall leaves a trailing backslash
    toolchain_line = f"MSVC {env.get('VCTOOLSVERSION', '?')}, SDK {sdk_version}, UCRT {env.get('UCRTVERSION', '?')}"

    results = {}
    try:
        for kind in ('core', 'net'):
            out_path = link_dll(kind, os.path.join(args.work, kind), libs_dir=libs_dir, vcvars=args.vcvars)
            info = _verify_dll(out_path, kind)
            results[kind] = info
            print(f"{kind}: exports {info['exports']}/{info['expected_exports']}")
            print(f"{kind}: imports {info['imports']}")
            print(f'{kind}: no CodeView')
            print(f"{kind}: 0 local paths, {info['allowlisted']} allowlisted")
            print(f"{kind}: size {info['size']} sha256 {info['sha256']}")
    except RuntimeError as e:
        print(e)
        return 1
    print(f'toolchain: {toolchain_line}')

    package_dir = pathlib.Path(__file__).resolve().parents[2] / 'nylib' / 'utils' / 'oodle'
    if args.install:
        package_dir.mkdir(parents=True, exist_ok=True)
        for kind, info in results.items():
            dest = package_dir / f'{DLL_STEMS[kind]}.dll'
            shutil.copyfile(info['path'], dest)
            print(f'installed {dest}')
    elif args.check:
        ok = True
        for kind, info in results.items():
            dest = package_dir / f'{DLL_STEMS[kind]}.dll'
            if not dest.is_file():
                print(f'{dest}: missing')
                ok = False
                continue
            installed_sha256 = _sha256_bytes(dest.read_bytes())
            if installed_sha256 != info['sha256']:
                print(f'{dest}: SHA-256 mismatch (built {info["sha256"]}, installed {installed_sha256})')
                ok = False
        if not ok:
            return 1
        print('check ok: byte-identical')
    return 0


if __name__ == '__main__':
    sys.exit(main())
