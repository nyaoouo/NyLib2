"""Command-line entry point for ``nylib.winutils.python_loader``.

Subcommands
-----------

* ``build`` - compile ``python_loader.cpp`` into ``python_loader.dll``.
* ``inject`` - inject a script (or inline code) into a running process.
* ``pack`` - dump a self-extracting packed script to stdout or a file.
* ``info`` - report what's currently injected in a target process.

Examples
~~~~~~~~

Build the loader DLL (overwriting any existing one)::

    python -m nylib.winutils.python_loader build --rebuild

Inject a script into Notepad once::

    python -m nylib.winutils.python_loader inject \
        --process Notepad.exe --script i_main.py --verbose

Inject the same script twice in a row to prove the interpreter is reused::

    python -m nylib.winutils.python_loader inject \
        --process Notepad.exe --script i_main.py --repeat 3

Inject inline code (handy for spot-checking the target)::

    python -m nylib.winutils.python_loader inject \
        --process Notepad.exe --code "import sys; print('pid', sys.executable)"

Inject a packed script (sibling .py modules travel with it)::

    python -m nylib.winutils.python_loader inject \
        --process Notepad.exe --script some_pkg/__init__.py --pack
"""

from __future__ import annotations

import argparse
import pathlib
import sys
import time

from . import (
    build_loader,
    ensure_loader_dll,
    finalize_python,
    is_python_initialized,
    pack_script,
    run_code,
    run_packed,
    run_script,
)


def _resolve_process(name_or_pid: str):
    from ...process import Process

    if name_or_pid.isdigit():
        return Process(int(name_or_pid))
    return Process.from_name(name_or_pid)


def _enable_priv():
    """Best-effort: SeDebugPrivilege so we can open foreign processes."""
    try:
        from ..process import enable_privilege

        enable_privilege()
    except Exception as e:  # noqa: BLE001
        print(f'[warn] enable_privilege failed: {e!r}', file=sys.stderr)


# ---------------------------------------------------------------------------
# build
# ---------------------------------------------------------------------------

def _cmd_build(args: argparse.Namespace) -> int:
    out = pathlib.Path(args.out).resolve() if args.out else None
    if args.rebuild and out and out.exists():
        out.unlink()
    elif args.rebuild and out is None:
        dll = ensure_loader_dll()
        if dll.exists():
            dll.unlink()
    path = build_loader(out) if out else ensure_loader_dll(rebuild=True)
    print(f'built loader: {path}')
    return 0


# ---------------------------------------------------------------------------
# pack
# ---------------------------------------------------------------------------

def _cmd_pack(args: argparse.Namespace) -> int:
    src = pathlib.Path(args.script).resolve()
    payload = pack_script(src, is_main=args.as_main)
    if args.out:
        out = pathlib.Path(args.out).resolve()
        out.write_text(payload, encoding='utf-8')
        print(f'wrote packed payload ({len(payload)} chars) -> {out}')
    else:
        sys.stdout.write(payload)
    return 0


# ---------------------------------------------------------------------------
# inject
# ---------------------------------------------------------------------------

def _cmd_inject(args: argparse.Namespace) -> int:
    if not args.script and not args.code:
        print('inject: --script or --code is required', file=sys.stderr)
        return 2

    _enable_priv()
    process = _resolve_process(args.process)
    print(f'[inject] target process: pid={process.process_id}')

    loader_dll = ensure_loader_dll(args.loader, rebuild=args.rebuild_loader)
    print(f'[inject] loader DLL: {loader_dll}')

    common = dict(
        python_dll=args.python_dll,
        python_home=args.python_home,
        python_paths=args.python_paths.split(';') if args.python_paths else None,
        create_console=not args.no_console,
        loader=loader_dll,
        reuse=not args.no_reuse,
        log_path=args.log_path,
    )

    if args.code:
        source = args.code
        filename = '<inject>'
        runner = lambda: run_code(process, source, filename=filename, **common)
    elif args.pack:
        runner = lambda: run_packed(process, args.script, **common)
    else:
        runner = lambda: run_script(process, args.script, **common)

    if args.verbose:
        print('[inject] command summary:')
        for k, v in common.items():
            print(f'    {k}: {v!r}')
        if args.script:
            print(f'    script: {args.script}')
        if args.code:
            print(f'    code: {args.code!r}')
        if args.pack:
            print('    packing: yes')

    for i in range(max(1, args.repeat)):
        if args.repeat > 1:
            print(f'[inject] iteration {i + 1}/{args.repeat}')
        t0 = time.perf_counter()
        rc = runner()
        dt = time.perf_counter() - t0
        print(f'[inject] LoadPython returned 0x{rc:08x} in {dt * 1000:.1f} ms')
        if rc != 0:
            print('[inject] non-zero status; check DebugView for details', file=sys.stderr)
            if not args.continue_on_error:
                return 1
    if args.finalize_after:
        rc = finalize_python(process, loader_dll)
        print(f'[inject] FinalizePython returned 0x{rc:08x}')
    return 0


# ---------------------------------------------------------------------------
# info
# ---------------------------------------------------------------------------

def _cmd_info(args: argparse.Namespace) -> int:
    _enable_priv()
    process = _resolve_process(args.process)
    print(f'pid: {process.process_id}')
    interesting = (
        'python_loader.dll',
        f'python{sys.version_info.major}{sys.version_info.minor}.dll',
        'python3.dll',
    )
    for dll in interesting:
        try:
            ldr = process.get_ldr_data(dll, rescan=True)
        except KeyError:
            print(f'  {dll}: (not loaded)')
        else:
            # FullDllName is a UNICODE_STRING whose buffer lives in the
            # *target* process - read it via remote_value, not .value.
            try:
                full = ldr.FullDllName.remote_value(process)
            except Exception as e:  # noqa: BLE001
                full = f'<remote_value failed: {e!r}>'
            print(f'  {dll}: base=0x{ldr.DllBase:x} path={full}')
    try:
        initialized = is_python_initialized(process)
    except Exception as e:  # noqa: BLE001
        print(f'  IsPythonInitialized failed: {e!r}')
    else:
        print(f'  IsPythonInitialized: {initialized}')
    return 0


# ---------------------------------------------------------------------------
# argparse plumbing
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog='python -m nylib.winutils.python_loader',
        description='Inject Python into a remote Win32 process via python_loader.dll',
    )
    sub = p.add_subparsers(dest='cmd', required=True)

    pb = sub.add_parser('build', help='compile python_loader.dll')
    pb.add_argument('--out', help='output DLL path (default: package-local)')
    pb.add_argument('--rebuild', action='store_true', help='delete an existing DLL first')
    pb.set_defaults(func=_cmd_build)

    pp = sub.add_parser('pack', help='dump a self-extracting packed script')
    pp.add_argument('--script', required=True, help='script or package dir to pack')
    pp.add_argument('--out', help='output .py path (default: stdout)')
    pp.add_argument('--as-main', dest='as_main', action='store_true', default=True,
                    help='emit as a __main__-style payload (default)')
    pp.add_argument('--not-main', dest='as_main', action='store_false',
                    help='emit as a submodule payload')
    pp.set_defaults(func=_cmd_pack)

    pi = sub.add_parser('inject', help='inject a script or code into a process')
    pi.add_argument('--process', required=True, help='target process name (Notepad.exe) or pid')
    pi.add_argument('--script', help='path to a .py file to run')
    pi.add_argument('--code', help='inline Python source to run')
    pi.add_argument('--pack', action='store_true',
                    help='pack the script (and its sibling modules) before injection')
    pi.add_argument('--no-console', action='store_true',
                    help='do NOT call AllocConsole in the target')
    pi.add_argument('--no-reuse', action='store_true',
                    help='disable PLF_REUSE_INTERPRETER (debugging)')
    pi.add_argument('--repeat', type=int, default=1,
                    help='number of injections to perform back-to-back')
    pi.add_argument('--continue-on-error', action='store_true',
                    help='keep going if a LoadPython call returns non-zero')
    pi.add_argument('--finalize-after', action='store_true',
                    help='call FinalizePython after the last script (dangerous)')
    pi.add_argument('--python-dll', dest='python_dll', default=None,
                    help='override python3XX.dll path passed to the loader')
    pi.add_argument('--python-home', dest='python_home', default=None,
                    help='override PYTHONHOME passed to the loader')
    pi.add_argument('--python-paths', dest='python_paths', default=None,
                    help='semicolon-separated extra sys.path entries')
    pi.add_argument('--loader', default=None, help='path to python_loader.dll')
    pi.add_argument('--rebuild-loader', action='store_true',
                    help='rebuild python_loader.dll before injecting')
    pi.add_argument('--log-path', dest='log_path', default=None,
                    help='write loader-side trace to this file (works without DebugView)')
    pi.add_argument('--verbose', '-v', action='store_true')
    pi.set_defaults(func=_cmd_inject)

    pn = sub.add_parser('info', help='report injection state for a process')
    pn.add_argument('--process', required=True)
    pn.set_defaults(func=_cmd_info)

    return p


def main(argv=None) -> int:
    args = _build_parser().parse_args(argv)
    return int(args.func(args) or 0)


if __name__ == '__main__':
    sys.exit(main())
