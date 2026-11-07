"""Build, verify, install and scan the bundled BC1 decoder DLL."""
import argparse
import ctypes
import hashlib
import os
import pathlib
import re
import shutil
import struct
import subprocess
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))
from nylib.winutils.msvc import load_vcvarsall
from nylib.winutils.pe_map import parse_image

DEFAULT_VCVARS = 'x64 10.0.28000.0 -vcvars_ver=14.51'
PINNED = {'VCTOOLSVERSION': '14.51.36231', 'WINDOWSSDKVERSION': '10.0.28000.0', 'UCRTVERSION': '10.0.28000.0'}
CFLAGS = ['/nologo', '/LD', '/MD', '/O2', '/DNDEBUG', '/utf-8', '/Brepro', '/W3']
LFLAGS = ['/link', '/Brepro', '/MANIFEST:NO', '/INCREMENTAL:NO']
SOURCE = pathlib.Path(__file__).resolve().with_name('bcn.c')
PACKAGE = SOURCE.parents[2] / 'nylib' / 'utils' / 'bcn'
NAME = 'bcn_win64.dll'
_ASCII_RUN = re.compile(rb'[\x20-\x7e]{4,}')
_UTF16_RUN = re.compile(rb'(?:[\x20-\x7e]\x00){4,}')
_DRIVE_PATH = re.compile(r'(?<![A-Za-z])[A-Za-z]:[\\/]')
_USERS_HOME = re.compile(r'[\\/](users|home)[\\/]', re.IGNORECASE)
_UNC_PATH = re.compile(r'\\\\[^\\]+\\')
_ALLOWED_IMPORT = re.compile(r'^api-ms-win-crt-.*\.dll$', re.IGNORECASE)


def scan_bytes(data: bytes) -> list[str]:
    """Find local paths and PDB strings in ASCII and UTF-16LE runs."""
    strings = [m.group().decode('ascii') for m in _ASCII_RUN.finditer(data)]
    strings += [m.group().decode('utf-16-le') for m in _UTF16_RUN.finditer(data)]
    return [s for s in strings if _DRIVE_PATH.search(s) or _USERS_HOME.search(s) or _UNC_PATH.search(s) or '.pdb' in s.lower()]


def _rva_to_offset(parsed, rva: int) -> int:
    if rva < parsed.size_of_headers:
        return rva
    for section in parsed.sections:
        if section.target_rva <= rva < section.target_rva + section.source_size:
            return section.source_offset + rva - section.target_rva
    raise ValueError(f'rva {rva:#x} is not backed by file data')


def _has_codeview_entry(data: bytes, parsed) -> bool:
    debug = parsed.directories[6]
    if not debug.size:
        return False
    offset = _rva_to_offset(parsed, debug.rva)
    return any(struct.unpack_from('<I', data, offset + i * 28 + 12)[0] == 2 for i in range(debug.size // 28))


def _toolchain_env(vcvars: str) -> dict:
    env = {k.upper(): v for k, v in os.environ.items()}
    env.update({k.upper(): v for k, v in load_vcvarsall(vcvars).items()})
    return env


def _find_tool(env: dict, name: str) -> str:
    if not (path := shutil.which(name, path=env.get('PATH', ''))):
        raise FileNotFoundError(f'{name} not found via vcvarsall PATH')
    return path


def compile_dll(work, *, env) -> pathlib.Path:
    """Compile the C source with reproducible MSVC flags."""
    work = pathlib.Path(work).resolve()
    work.mkdir(parents=True, exist_ok=True)
    out = work / NAME
    cl = _find_tool(env, 'cl.exe')
    _find_tool(env, 'link.exe')
    cmd = [cl, *CFLAGS, str(SOURCE), *LFLAGS, f'/OUT:{out}']
    print('compiler flags:', ' '.join(CFLAGS))
    print('linker flags:', ' '.join(LFLAGS))
    result = subprocess.run(cmd, cwd=work, env=env, capture_output=True, text=True)
    if result.returncode:
        sys.stdout.write(result.stdout)
        sys.stderr.write(result.stderr)
        raise RuntimeError(f'cl/link failed (rc={result.returncode})')
    return out


def _kat(path):
    """Check literal BC1 answers and the three error returns."""
    lib = ctypes.CDLL(str(path))
    fn = ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_size_t,
                          ctypes.c_size_t, ctypes.c_void_p, ctypes.c_size_t)(('bcn_decode_bc1', lib))
    white = bytes.fromhex('ffffffff')
    black = bytes.fromhex('000000ff')
    block0 = bytes.fromhex('ffff000000000000')
    cases = [
        (bytes.fromhex('ffff0000e4e4e4e4'), 4, 4, bytes.fromhex('ffffffff000000ffaaaaaaff555555ff') * 4),
        (bytes.fromhex('1f001f00ffffffff'), 4, 4, black * 16),
        (block0, 4, 4, white * 16),
        (block0 + bytes.fromhex('ffff000055555555'), 8, 4, (white * 4 + black * 4) * 4),
    ]
    for i, (src, w, h, expected) in enumerate(cases):
        dst = (ctypes.c_ubyte * len(expected))()
        rc = fn(src, len(src), w, h, dst, len(dst))
        if rc != 0 or bytes(dst) != expected:
            raise RuntimeError(f'KAT case {i + 1} failed (rc={rc})')
    for w, h, src_len, dst_len, expected in [(3, 4, 8, 64, -1), (4, 4, 7, 64, -2), (4, 4, 8, 63, -3)]:
        dst = (ctypes.c_ubyte * 64)(*([0xA5] * 64))
        rc = fn(block0, src_len, w, h, dst, dst_len)
        if rc != expected or bytes(dst) != b'\xa5' * 64:
            raise RuntimeError(f'KAT error return {expected} failed (rc={rc})')
    print('KAT ok: 4 literal cases; returns -1/-2/-3; errors write nothing')


def _verify_dll(path) -> dict:
    """Verify the PE surface, embedded strings and known answers."""
    data = pathlib.Path(path).read_bytes()
    parsed = parse_image(data)
    if parsed.machine != 0x8664:
        raise RuntimeError(f'wrong machine: {parsed.machine:#x}')
    names = sorted(e.name for e in parsed.exports if e.name)
    if names != ['bcn_decode_bc1'] or len(parsed.exports) != 1:
        raise RuntimeError(f'export mismatch: {names!r}')
    if parsed.delay_imports:
        raise RuntimeError('DLL has delay imports')
    modules = sorted({i.module for i in parsed.imports})
    for module in modules:
        if module.lower() not in {'kernel32.dll', 'vcruntime140.dll'} and not _ALLOWED_IMPORT.fullmatch(module):
            raise RuntimeError(f'disallowed import: {module!r}')
    if _has_codeview_entry(data, parsed):
        raise RuntimeError('DLL has a CodeView entry')
    if hits := scan_bytes(data):
        raise RuntimeError(f'path scan failed: {hits!r}')
    _kat(path)
    return {'imports': modules, 'size': len(data), 'sha256': hashlib.sha256(data).hexdigest()}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--work', default='scripts/bcn/build', help='scratch directory')
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--install', action='store_true')
    mode.add_argument('--check', action='store_true')
    parser.add_argument('--vcvars', default=DEFAULT_VCVARS)
    parser.add_argument('--scan', nargs='+', metavar='PATH')
    args = parser.parse_args(argv)
    if args.scan:
        failed = False
        for path in args.scan:
            hits = scan_bytes(pathlib.Path(path).read_bytes())
            print(f'{path}: {len(hits)} hit(s)')
            for hit in hits:
                print(f'  {hit!r}')
            failed |= bool(hits)
        return int(failed)
    env = _toolchain_env(args.vcvars)
    versions = {k: env.get(k, '?').rstrip('\\') for k in PINNED}
    print(f'toolchain: MSVC {versions["VCTOOLSVERSION"]}, SDK {versions["WINDOWSSDKVERSION"]}, UCRT {versions["UCRTVERSION"]}')
    if versions != PINNED:
        if args.install or args.check:
            print('refused: toolchain differs from the pin')
            return 2
        print('warning: toolchain differs from the pin')
    out = compile_dll(args.work, env=env)
    info = _verify_dll(out)
    print('exports: 1/1 (bcn_decode_bc1)')
    print(f'imports: {info["imports"]}')
    print('no CodeView; 0 local paths')
    print(f'size: {info["size"]} sha256: {info["sha256"]}')
    dest = PACKAGE / NAME
    if args.install:
        PACKAGE.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(out, dest)
        print(f'installed {dest}')
    elif args.check:
        if not dest.is_file() or out.read_bytes() != dest.read_bytes():
            print('check failed: installed DLL missing or differs')
            return 1
        provenance = PACKAGE / 'PROVENANCE.md'
        if not provenance.is_file() or info['sha256'] not in provenance.read_text(encoding='utf-8'):
            print('check failed: DLL SHA-256 missing from PROVENANCE.md')
            return 1
        print('check ok: byte-identical')
    return 0


if __name__ == '__main__':
    sys.exit(main())
