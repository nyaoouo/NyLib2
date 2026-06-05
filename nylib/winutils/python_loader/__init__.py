"""In-process Python loader for remote Win32 processes.

The C side lives in ``python_loader.cpp`` and is built into
``python_loader.dll`` by :func:`build_loader`. The Python helpers in this
module write a versioned config struct into the target process and invoke
``LoadPython`` / ``RunPython`` exported by the loader.

Highlights compared with the previous revision
----------------------------------------------
* ``Py_InitializeFromConfig`` is used in the loader instead of the bare
  ``Py_Initialize``, so the target process gets a correctly-configured
  interpreter (including PyInstaller-friendly home / sys.path).
* The interpreter is **kept alive** between calls to :func:`run_script`,
  :func:`run_code`, and :func:`run_packed`. The first call into a given
  process initialises Python; subsequent calls re-run the bootstrap and
  execute the new script under the existing interpreter.
* Scripts may be supplied as on-disk paths *or* as in-memory UTF-8
  source. The latter is what enables :func:`pack_script` /
  :func:`run_packed` to inject self-contained payloads built via
  :mod:`nylib.utils.pkg_archive`, which is also what makes PyInstaller
  bundling tractable.
* Every phase is traced via ``OutputDebugStringW`` from the C side - run
  Sysinternals DebugView (capture Win32 + global output) to follow what
  the loader is doing inside the target.

CLI
---
``python -m nylib.winutils.python_loader`` exposes ``build``, ``pack``,
``inject``, and ``info`` subcommands for debugging from a shell.
"""

from __future__ import annotations

import ctypes
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import typing

from ...process import Process

# ---------------------------------------------------------------------------
# Flag bits, must mirror python_loader.cpp.
# ---------------------------------------------------------------------------

PLF_CREATE_CONSOLE = 0x00000001
PLF_REUSE_INTERPRETER = 0x00000002
PLF_HAS_CODE = 0x00000004
PLF_FINALIZE_AFTER = 0x00000008
PLF_SKIP_INIT_DEBUG = 0x00000010

CONFIG_VERSION = 1


# ---------------------------------------------------------------------------
# Build / locate the loader DLL.
# ---------------------------------------------------------------------------

_LOADER_DIR = pathlib.Path(__file__).parent
_DEFAULT_DLL = _LOADER_DIR / 'python_loader.dll'
_DEFAULT_CPP = _LOADER_DIR / 'python_loader.cpp'


def build_loader(dst: str | pathlib.Path = _DEFAULT_DLL, build_dir=None) -> pathlib.Path:
    """Compile ``python_loader.cpp`` into ``dst``.

    Requires MSVC on the path (``nylib.winutils.ensure_env.ensure_msvc``).
    Safe to call repeatedly: removes a pre-existing ``dst`` first.
    """
    from .. import msvc, ensure_env
    ensure_env.ensure_msvc()
    plat_spec = 'x86_amd64'
    build_env = msvc.load_vcvarsall(plat_spec)
    dst = pathlib.Path(dst).absolute()
    if dst.exists():
        dst.unlink()
    if build_dir is None:
        tmp_dir = pathlib.Path(tempfile.mkdtemp())
        cleanup = True
    else:
        tmp_dir = pathlib.Path(build_dir)
        tmp_dir.mkdir(exist_ok=True, parents=True)
        cleanup = False
    src_file = _DEFAULT_CPP
    try:
        subprocess.run(
            [
                msvc.where('cl.exe', plat_spec),
                # /EHa enables structured-exception-aware C++ EH so the
                # loader's __try/__except blocks can catch hardware faults
                # raised inside python.dll (helpful when diagnosing why
                # Py_InitializeFromConfig aborts inside a foreign process).
                '/D_WINDLL', '/std:c++20', '/EHa', '/O2', '/W3',
                str(src_file),
                '/link', '/DLL', '/OUT:' + str(dst),
            ],
            cwd=tmp_dir,
            env=build_env,
            check=True,
            shell=True,
        )
    finally:
        if cleanup:
            shutil.rmtree(tmp_dir, ignore_errors=True)
    for ext in ('.exp', '.obj', '.lib'):
        side = dst.with_suffix(ext)
        if side.exists():
            side.unlink()
    return dst


def ensure_loader_dll(path: str | pathlib.Path | None = None, rebuild: bool = False) -> pathlib.Path:
    """Return a path to a buildable loader DLL, building it on demand."""
    path = pathlib.Path(path) if path is not None else _DEFAULT_DLL
    if rebuild or not path.exists():
        build_loader(path)
    return path


# ---------------------------------------------------------------------------
# Host-side Python layout discovery.
# ---------------------------------------------------------------------------

def default_python_dll() -> str:
    """Best-effort full path to the python3XX.dll loaded by this process."""
    dll_name = f"python{sys.version_info.major}{sys.version_info.minor}.dll"
    try:
        return Process.current.get_ldr_data(dll_name).FullDllName.value
    except KeyError:
        # Frozen bundles sometimes embed python under a different name; fall
        # back to the executable's directory.
        candidates = [pathlib.Path(sys.executable).with_name(dll_name)]
        meipass = getattr(sys, '_MEIPASS', None)
        if meipass:
            candidates.insert(0, pathlib.Path(meipass) / dll_name)
        for c in candidates:
            if c.exists():
                return str(c)
        raise


def default_python_home() -> str:
    """Best-effort PYTHONHOME for the target interpreter.

    Priority:

    1. ``sys._MEIPASS`` when frozen by PyInstaller (the bundled stdlib lives
       under that directory).
    2. ``sys.base_prefix`` - the *base* install behind a venv. ``sys.prefix``
       would point at the venv itself, which has no stdlib of its own, so
       using ``sys.prefix`` would make the injected interpreter fail to
       import ``os`` and trigger ``Py_FatalError`` -> the target crashes.
    3. ``sys.prefix`` as a last resort (for non-venv interpreters where
       both are the same).
    """
    meipass = getattr(sys, '_MEIPASS', None)
    if meipass:
        return str(meipass)
    base = getattr(sys, 'base_prefix', sys.prefix)
    return base or sys.prefix


def _editable_install_source_roots() -> list[str]:
    """Resolve on-disk source directories of every editable-installed dist.

    PEP 660 editable installs (``pip install -e``) register a path-hook
    finder via a ``.pth`` file in the venv's ``site-packages``. The hook is
    replayed by ``site.py`` at host startup, but **not** inside the injected
    interpreter (which is configured with ``python_home = sys.base_prefix``
    and never adds the venv's ``site-packages`` to ``sys.path`` for ``site.py``
    to process). Result: editable-installed packages that are perfectly
    importable in the launcher raise ``ModuleNotFoundError`` in the target.

    We sidestep this generically (works with setuptools, hatchling, pdm,
    flit, ...) by reading each distribution's ``direct_url.json``
    (standardised by PEP 610). Editable installs carry
    ``dir_info.editable == true`` and a ``file://`` ``url`` pointing at the
    source tree; the caller can add that path to ``sys.path`` to import the
    package via the ordinary filesystem finder.
    """
    import json
    import urllib.parse

    out: list[str] = []
    seen: set[str] = set()
    for sp_dir in sys.path:
        if not sp_dir or not os.path.isdir(sp_dir):
            continue
        # site-packages dirs hold ``*.dist-info``; other entries don't, but
        # the cheap check below short-circuits without listing entries that
        # have no ``.dist-info`` children.
        try:
            entries = os.listdir(sp_dir)
        except OSError:
            continue
        for name in entries:
            if not name.endswith('.dist-info'):
                continue
            direct_url = os.path.join(sp_dir, name, 'direct_url.json')
            if not os.path.isfile(direct_url):
                continue
            try:
                with open(direct_url, 'r', encoding='utf-8') as f:
                    data = json.load(f)
            except Exception:
                continue
            if not data.get('dir_info', {}).get('editable'):
                continue
            url = data.get('url', '')
            if not url.startswith('file://'):
                continue
            parsed = urllib.parse.urlparse(url)
            local = urllib.parse.unquote(parsed.path)
            # Windows: ``file:///D:/foo`` → parsed.path is ``/D:/foo``.
            if os.name == 'nt' and len(local) > 2 and local[0] == '/' and local[2] == ':':
                local = local[1:]
            local = os.path.normpath(local)
            if os.path.isdir(local) and local not in seen:
                seen.add(local)
                out.append(local)
    return out


def default_python_paths() -> list[str]:
    """Sys.path entries to pre-seed into the injected interpreter.

    Filters out empty strings, the current working directory ('') and
    directories that no longer exist, then de-duplicates while preserving
    order. Also appends source roots of editable-installed distributions (see
    :func:`_editable_install_source_roots`) so packages installed via
    ``pip install -e`` are importable in the target interpreter without the
    host's ``.pth``-driven path hook.
    """
    seen: set[str] = set()
    out: list[str] = []
    for raw in sys.path:
        if not raw:
            continue
        p = os.path.abspath(raw)
        if p in seen:
            continue
        if not os.path.exists(p):
            continue
        seen.add(p)
        out.append(p)
    for p in _editable_install_source_roots():
        if p not in seen:
            seen.add(p)
            out.append(p)
    return out


# ---------------------------------------------------------------------------
# Config marshalling.
# ---------------------------------------------------------------------------

_PTR_SIZE = 8  # we only ship x64


class _Layout(typing.NamedTuple):
    base: int
    pyDll_off: int
    pyHome_off: int
    pyPaths_off: int
    pyMain_off: int
    pyCode_off: int
    pyCodeLen_off: int


_HEADER_BYTES = (
    4   # version
    + 4   # flags
    + _PTR_SIZE  # pyDll
    + _PTR_SIZE  # pyHome
    + _PTR_SIZE  # pyPaths
    + _PTR_SIZE  # pyMain
    + _PTR_SIZE  # pyCode
    + 4           # pyCodeLen
    + 4           # reserved
    + _PTR_SIZE  # logPath
    + 8           # reserved2
)


def _wstring(value: str | None) -> bytes:
    """Encode a value as a NUL-terminated UTF-16LE byte string, or b''."""
    if value is None:
        return b''
    if not isinstance(value, str):
        value = str(value)
    return value.encode('utf-16-le') + b'\x00\x00'


def _write_config(
    process: Process,
    *,
    flags: int,
    pyDll: str,
    pyHome: str | None,
    pyPaths: str | None,
    pyMain: str | None,
    pyCode: bytes | None,
    logPath: str | None = None,
) -> int:
    """Allocate and populate a PyLoaderConfig in the remote process.

    Returns the address of the struct. The caller is responsible for
    freeing it (or leaks the alloc; the OS reclaims on process exit).
    """
    blobs: dict[str, bytes] = {
        'pyDll': _wstring(pyDll),
        'pyHome': _wstring(pyHome),
        'pyPaths': _wstring(pyPaths),
        'pyMain': _wstring(pyMain),
        'pyCode': (pyCode or b''),
        'logPath': _wstring(logPath),
    }

    total = _HEADER_BYTES + sum(len(b) for b in blobs.values())
    base = process.alloc(total)

    # Place each blob right after the header, in field order.
    cursor = base + _HEADER_BYTES
    blob_addrs: dict[str, int] = {}
    for key in ('pyDll', 'pyHome', 'pyPaths', 'pyMain', 'pyCode', 'logPath'):
        b = blobs[key]
        if b:
            blob_addrs[key] = cursor
            process.write(cursor, b)
            cursor += len(b)
        else:
            blob_addrs[key] = 0

    # Header.
    off = base
    process.write(off, ctypes.c_uint32(CONFIG_VERSION));  off += 4
    process.write(off, ctypes.c_uint32(flags));            off += 4
    process.write_ptr(off, blob_addrs['pyDll']);           off += _PTR_SIZE
    process.write_ptr(off, blob_addrs['pyHome']);          off += _PTR_SIZE
    process.write_ptr(off, blob_addrs['pyPaths']);         off += _PTR_SIZE
    process.write_ptr(off, blob_addrs['pyMain']);          off += _PTR_SIZE
    process.write_ptr(off, blob_addrs['pyCode']);          off += _PTR_SIZE
    process.write(off, ctypes.c_uint32(len(pyCode) if pyCode else 0));  off += 4
    process.write(off, ctypes.c_uint32(0));                off += 4
    process.write_ptr(off, blob_addrs['logPath']);         off += _PTR_SIZE
    process.write(off, ctypes.c_uint64(0));                off += 8
    return base


# ---------------------------------------------------------------------------
# Loader DLL injection / address resolution.
# ---------------------------------------------------------------------------

def ensure_loader_injected(
    process: Process,
    loader_dll: str | pathlib.Path | None = None,
) -> int:
    """Make sure ``python_loader.dll`` is loaded in *process* and return its base."""
    loader_path = ensure_loader_dll(loader_dll)
    try:
        ldr = process.get_ldr_data('python_loader.dll', rescan=True)
        return ldr.DllBase
    except KeyError:
        return process.load_library(loader_path)


def _resolve_export(process: Process, loader_base: int, name: str) -> int:
    return process.get_proc_address(loader_base, name)


# ---------------------------------------------------------------------------
# Public entry points.
# ---------------------------------------------------------------------------

def run_code(
    process: Process,
    code: str | bytes,
    *,
    filename: str = '<inject>',
    python_dll: str | None = None,
    python_home: str | None = None,
    python_paths: typing.Iterable[str] | str | None = None,
    create_console: bool = True,
    loader: str | pathlib.Path | None = None,
    reuse: bool = True,
    log_path: str | pathlib.Path | None = None,
    _skip_init_debug: bool = False,
) -> int:
    """Run UTF-8 Python *code* in the target *process*.

    Returns the loader's status word (0 = ok; non-zero values are
    ``OutputDebugString``ed by the loader). Re-uses the interpreter on
    subsequent calls into the same process when ``reuse`` is true (the
    default).
    """
    if isinstance(code, str):
        code_bytes = code.encode('utf-8')
    else:
        code_bytes = bytes(code)

    if python_dll is None:
        python_dll = default_python_dll()
    else:
        python_dll = os.path.abspath(python_dll)

    if python_paths is None:
        path_str = os.pathsep.join(default_python_paths())
    elif isinstance(python_paths, str):
        path_str = python_paths
    else:
        path_str = os.pathsep.join(python_paths)

    if python_home is None:
        python_home = default_python_home()

    loader_base = ensure_loader_injected(process, loader)
    pLoadPython = _resolve_export(process, loader_base, 'LoadPython')

    flags = PLF_HAS_CODE
    if create_console:
        flags |= PLF_CREATE_CONSOLE
    if reuse:
        flags |= PLF_REUSE_INTERPRETER
    if _skip_init_debug:
        flags |= PLF_SKIP_INIT_DEBUG

    cfg_addr = _write_config(
        process,
        flags=flags,
        pyDll=python_dll,
        pyHome=python_home,
        pyPaths=path_str,
        pyMain=os.path.abspath(filename),
        pyCode=code_bytes,
        logPath=str(log_path) if log_path is not None else None,
    )
    rc = process.call(pLoadPython, cfg_addr)
    # NOTE: not freeing cfg_addr - if the remote interpreter holds onto any
    # pointer (it shouldn't) we'd risk a UAF. The leak per call is small.
    return rc & 0xFFFFFFFF


def run_script(
    process: Process,
    main_script: str | pathlib.Path,
    *,
    python_dll: str | None = None,
    python_home: str | None = None,
    python_paths: typing.Iterable[str] | str | None = None,
    create_console: bool = True,
    loader: str | pathlib.Path | None = None,
    reuse: bool = True,
    log_path: str | pathlib.Path | None = None,
) -> int:
    """Run a script file in the target process.

    Compatible signature with the historical ``run_script`` API; extra
    keyword args are additive. The interpreter is kept alive across calls
    so this is safe to invoke many times.
    """
    main_script = pathlib.Path(main_script).resolve()
    if not main_script.is_file():
        raise FileNotFoundError(main_script)
    with open(main_script, 'rb') as f:
        code = f.read()
    if code.startswith(b'\xef\xbb\xbf'):
        code = code[3:]
    return run_code(
        process,
        code,
        filename=str(main_script),
        python_dll=python_dll,
        python_home=python_home,
        python_paths=python_paths,
        create_console=create_console,
        loader=loader,
        reuse=reuse,
        log_path=log_path,
    )


def pack_script(path: str | pathlib.Path, is_main: bool = True,
                package_name: str | None = None) -> str:
    """Pack a script (or package directory) into a self-extracting payload.

    Wraps :func:`nylib.utils.pkg_archive.pack`. The returned string is
    standalone Python source: feeding it to :func:`run_code` injects the
    user's script *and* any sibling submodules without writing files to
    the target process's filesystem.

    Set ``package_name`` to wrap the payload in a synthetic top-level
    package of that name. The entry script then runs with
    ``__package__=<package_name>`` so relative imports work inside it.
    Default ``None`` preserves the legacy top-level behaviour (sibling
    modules importable by bare name, no relative imports from entry).
    """
    from ...utils import pkg_archive
    return pkg_archive.pack(path, is_main=is_main, package_name=package_name)


def run_packed(
    process: Process,
    path: str | pathlib.Path,
    **kwargs,
) -> int:
    """Convenience: :func:`pack_script` + :func:`run_code` in one call."""
    source = pack_script(path)
    return run_code(
        process,
        source,
        filename=str(pathlib.Path(path).resolve()),
        **kwargs,
    )


def finalize_python(process: Process, loader: str | pathlib.Path | None = None) -> int:
    """Call the loader's ``FinalizePython`` export in *process*. Best-effort."""
    loader_base = ensure_loader_injected(process, loader)
    p = _resolve_export(process, loader_base, 'FinalizePython')
    return process.call(p) & 0xFFFFFFFF


def is_python_initialized(process: Process, loader: str | pathlib.Path | None = None) -> bool:
    loader_base = ensure_loader_injected(process, loader)
    p = _resolve_export(process, loader_base, 'IsPythonInitialized')
    return bool(process.call(p) & 0xFFFFFFFF)
