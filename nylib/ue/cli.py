"""`nylib.ue` command-line shell (I4): argument parsing, logging scope, exit codes.

`info` and `export` are fully implemented here (7-a2). `list`, `probe` and `dump` do their
usage-level checks (so a bad invocation fails the same way before and after 7-b lands) and then
lazily import `.pipeline`, which 7-b adds; their result rendering is completed there too.
"""
import argparse
import dataclasses
import importlib.metadata
import json
import logging
import logging.handlers
import os
import re
import shutil
import sys
import tempfile
import time

from . import errors
from . import exports as exports_mod
from . import snapshot as snapshot_mod
from . import store as store_mod

PROG = 'nylib.ue'
_PID_RE = re.compile(r'\d+')
_EXPORT_NAMES = frozenset({'idmap', 'gobjects', 'gobjects-props', 'usmap'})
_ALLOW_CALLS_NAMES = frozenset({'append-string', 'game-info', 'text'})
_ALLOW_CALLS_DEFAULT = 'append-string,game-info,text'


def _package_version() -> str:
    try:
        return importlib.metadata.version('nylib')
    except importlib.metadata.PackageNotFoundError:
        return '0+unknown'


class _ArgExit(Exception):
    """Raised instead of SystemExit by `_Parser`, so `main()` never lets argparse exit the process."""

    def __init__(self, status: int):
        self.status = status


class _Parser(argparse.ArgumentParser):
    def exit(self, status=0, message=None):
        if message:
            self._print_message(message, sys.stderr if status else sys.stdout)
        raise _ArgExit(status)


def _target_arg(raw: str):
    return int(raw) if _PID_RE.fullmatch(raw) else raw


def _split_list(raw: str) -> list:
    return [x for x in (p.strip() for p in raw.split(',')) if x]


def _parse_exports(raw: str) -> tuple:
    items = _split_list(raw)
    if 'none' in items:
        if len(items) > 1:
            raise ValueError('--exports: "none" cannot be combined with a format')
        return ()
    for x in items:
        if x not in _EXPORT_NAMES:
            raise ValueError(f'--exports: unknown format {x!r}')
    return tuple(items)


def _parse_allow_calls(raw: str) -> None:
    for x in _split_list(raw):
        if x not in _ALLOW_CALLS_NAMES:
            raise ValueError(f'--allow-calls: unknown value {x!r}')


def _build_parser() -> argparse.ArgumentParser:
    p = _Parser(
        prog=PROG,
        description='Unreal Engine reflection dumper. External and read-only unless a command says otherwise.',
        epilog='Exit status: 0 ok, 1 error, 2 usage, 3 detection failed, 4 cannot open target or the target exited, 130 interrupted.',
    )
    p.add_argument('--version', action='version', version=f'{PROG} {_package_version()}')
    sub = p.add_subparsers(dest='command', required=True, metavar='<command>')

    def common(sp):
        g = sp.add_mutually_exclusive_group()
        g.add_argument('-v', action='store_true', dest='verbose', help='debug output on stderr')
        g.add_argument('-q', action='store_true', dest='quiet', help='warnings only on stderr')
        sp.add_argument('--log-file', dest='log_file', default=None, help='default: <out>/_logs/<command>.log')

    pl = sub.add_parser('list', help='list running processes that look like Unreal Engine games')
    pl.add_argument('--out', dest='out', default=None, help='output root (default: .\\ue_dumps or env NYLIB_UE_OUT)')
    pl.add_argument('--json', action='store_true')
    common(pl)
    pl.set_defaults(func=_cmd_list)

    pp = sub.add_parser('probe', help='detect globals, layouts and offsets only; --write-profile saves them')
    pp.add_argument('target')
    pp.add_argument('--profile', dest='profile', default=None, help='game profile (TOML) with pinned values')
    pp.add_argument('--out', dest='out', default=None, help='output root (default: .\\ue_dumps or env NYLIB_UE_OUT)')
    pp.add_argument('--explain', action='store_true', help="Dumper-7's own console messages")
    pp.add_argument('--write-profile', dest='write_profile', action='store_true')
    pp.add_argument('--json', action='store_true')
    common(pp)
    pp.set_defaults(func=_cmd_probe)

    pd = sub.add_parser('dump', help='probe, walk reflection, write a snapshot and the default exports')
    pd.add_argument('target')
    pd.add_argument('--profile', dest='profile', default=None)
    pd.add_argument('--out', dest='out', default=None, help='output root (default: .\\ue_dumps or env NYLIB_UE_OUT)')
    pd.add_argument('--exports', dest='exports', default=None,
                     help='formats written after the snapshot: idmap, gobjects, gobjects-props, usmap '
                          '(default: idmap,gobjects,gobjects-props; "none" writes the snapshot only)')
    pd.add_argument('--allow-calls', dest='allow_calls', nargs='?', const=_ALLOW_CALLS_DEFAULT, default=None,
                     help='append-string, game-info, text; no value means all three (not implemented yet)')
    pd.add_argument('--json', action='store_true')
    common(pd)
    pd.set_defaults(func=_cmd_dump)

    pe = sub.add_parser('export', help='write another format from an existing snapshot; the game is not needed')
    pe.add_argument('snapshot')
    pe.add_argument('--format', dest='format', required=True, choices=sorted(_EXPORT_NAMES),
                     help='idmap, gobjects, gobjects-props, usmap (not implemented yet)')
    pe.add_argument('--out', dest='out', default=None, help='output file (default: the format\'s place in the snapshot)')
    common(pe)
    pe.set_defaults(func=_cmd_export)

    pi = sub.add_parser('info', help='summarize a snapshot folder')
    pi.add_argument('snapshot')
    pi.add_argument('--json', action='store_true')
    common(pi)
    pi.set_defaults(func=_cmd_info)

    return p


class _StderrFormatter(logging.Formatter):
    def format(self, record):
        msg = record.getMessage()
        if record.levelno >= logging.WARNING:
            return f'warning: {msg}'
        if record.levelno <= logging.DEBUG:
            return f'debug: {record.name}: {msg}'
        return msg


def _with_logging(log_file: str, verbose: bool, quiet: bool, body):
    """Attach `nylib.ue`'s file+stderr handlers for one call, run `body(logger)`, restore state after."""
    logger = logging.getLogger('nylib.ue')
    prev_level, prev_propagate, prev_handlers = logger.level, logger.propagate, list(logger.handlers)
    try:
        os.makedirs(os.path.dirname(log_file) or '.', exist_ok=True)
    except OSError as e:
        print(f'error: cannot write the log file {log_file}: {e}', file=sys.stderr)
        return 1

    file_handler = logging.handlers.RotatingFileHandler(log_file, maxBytes=5 << 20, backupCount=3,
                                                          encoding='utf-8', delay=True)
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(name)s: %(message)s'))
    stream_level = logging.DEBUG if verbose else logging.WARNING if quiet else logging.INFO
    stream_handler = logging.StreamHandler(sys.stderr)
    stream_handler.setLevel(stream_level)
    stream_handler.setFormatter(_StderrFormatter())

    logger.handlers = [file_handler, stream_handler]
    logger.setLevel(logging.DEBUG)
    logger.propagate = False
    try:
        return body(logger)
    finally:
        logger.removeHandler(file_handler)
        logger.removeHandler(stream_handler)
        file_handler.close()
        stream_handler.close()
        logger.handlers = prev_handlers
        logger.setLevel(prev_level)
        logger.propagate = prev_propagate


def _print_json(doc: dict) -> None:
    print(json.dumps(doc, ensure_ascii=True, separators=(',', ':')))


def _pin_for_step(step: str):
    if step.startswith('ObjectArray::'):
        return 'gobjects'
    if step.startswith('FName::') or step.startswith('NameArray::'):
        return 'gnames'
    return None


def _detection_fix_lines(e, target) -> list:
    pin = _pin_for_step(e.step)
    fill = f' (writes what was found; fill in [globals] {pin})' if pin else ' (writes what was found)'
    return [
        'fix: pin it in a profile, then probe again:',
        f'  {PROG} probe {target} --write-profile    {fill.strip()}',
        f'  {PROG} probe {target} --explain          (what the finders reported)',
    ]


def _classify(e: Exception, target) -> tuple:
    """Map an exception to (exit_code, fix_lines) per I4's table."""
    if isinstance(e, errors.AmbiguousTargetError):
        return 2, ['fix: pass one of the PIDs instead of the name']
    if isinstance(e, errors.ProfileError):
        return 2, []
    if isinstance(e, errors.DetectionError):
        return 3, _detection_fix_lines(e, target)
    if isinstance(e, errors.TargetError):
        return 4, []
    if isinstance(e, NotImplementedError):
        return 1, []
    if isinstance(e, errors.UeError):  # OutputRootError and every other UeError
        return 1, []
    return 1, []


def _finish_error(e: Exception, json_mode: bool, *, target, log_file: str, logger=None) -> int:
    if logger is not None:
        logger.debug('%s: %s', type(e).__name__, e, exc_info=True)
    exit_code, fix_lines = _classify(e, target)
    message = str(e)
    known = isinstance(e, (errors.UeError, NotImplementedError))
    if json_mode:
        _print_json({'ok': False, 'error': {'type': type(e).__name__, 'message': message, 'exit': exit_code}})
        return exit_code
    if known:
        print(f'error: {message}', file=sys.stderr)
    else:
        print(f'error: unexpected {type(e).__name__}: {message} (details: {log_file})', file=sys.stderr)
    for line in fix_lines:
        print(line, file=sys.stderr)
    return exit_code


# --------------------------------------------------------------------------------------------
# info (full)
# --------------------------------------------------------------------------------------------

def _info_doc(path: str, snap) -> dict:
    present = []
    for fmt in sorted(_EXPORT_NAMES):
        rel = exports_mod.export_path(fmt, snap)
        if os.path.isfile(os.path.join(snap.path, rel)):
            present.append(rel.replace(os.sep, '/'))
    return {'ok': True, 'snapshot': os.path.abspath(path), 'exports': present, 'meta': snap.meta}


def _meta_get(meta: dict, dotted: str, default='?'):
    cur = meta
    for part in dotted.split('.'):
        if not isinstance(cur, dict) or part not in cur:
            return default
        cur = cur[part]
    return cur if cur not in (None, '') else default


def _info_text_lines(doc: dict) -> list:
    meta = doc['meta']
    engine = meta.get('engine') if isinstance(meta.get('engine'), dict) else {}
    counts = meta.get('counts') if isinstance(meta.get('counts'), dict) else {}
    prop_word = ('FProperty' if engine.get('use_fproperty') else 'UProperty') if 'use_fproperty' in engine else '?'
    pool_word = ('FNamePool' if engine.get('use_name_pool') else 'TNameEntryArray') if 'use_name_pool' in engine else '?'
    return [
        f"snapshot  schema {_meta_get(meta, 'schema.version')} · {_meta_get(meta, 'generator.tool')} "
        f"{_meta_get(meta, 'generator.version')} · {_meta_get(meta, 'created')} · {_meta_get(meta, 'mode')} · read-only",
        f"game      {_meta_get(meta, 'target.game_name')} · pe {_meta_get(meta, 'target.module.pe_timestamp')} / "
        f"{_meta_get(meta, 'target.module.size')} · engine {_meta_get(meta, 'target.engine_version')} · "
        f"{prop_word} · {pool_word}",
        f"counts    {counts.get('objects', '?')} objects · {counts.get('packages', '?')} packages · "
        f"{counts.get('classes', '?')} classes · {counts.get('structs', '?')} structs · "
        f"{counts.get('enums', '?')} enums · {counts.get('functions', '?')} functions",
        f"exports   {', '.join(doc['exports']) if doc['exports'] else '-'}",
    ]


def _cmd_info(args, _open_target=None) -> int:
    root = store_mod.resolve_out_root(None)
    log_file = args.log_file or os.path.join(root, store_mod.LOGS_DIR, 'info.log')

    def body(logger):
        try:
            with snapshot_mod.Snapshot.load(args.snapshot) as snap:
                doc = _info_doc(args.snapshot, snap)
        except Exception as e:
            return _finish_error(e, args.json, target=args.snapshot, log_file=log_file, logger=logger)
        if args.json:
            _print_json(doc)
        else:
            for line in _info_text_lines(doc):
                print(line)
        return 0

    return _with_logging(log_file, args.verbose, args.quiet, body)


# --------------------------------------------------------------------------------------------
# export (full)
# --------------------------------------------------------------------------------------------

def _do_export(snapshot_path: str, fmt: str, out_file):
    t0 = time.perf_counter()
    with snapshot_mod.Snapshot.load(snapshot_path) as snap:
        if out_file is None:
            path = exports_mod.run_export(fmt, snap, snapshot_path)
        else:
            out_file = os.path.abspath(out_file)
            out_dir = os.path.dirname(out_file) or '.'
            os.makedirs(out_dir, exist_ok=True)
            tmp_dir = tempfile.mkdtemp(dir=out_dir)
            try:
                written = exports_mod.run_export(fmt, snap, tmp_dir)
                os.replace(written, out_file)
                path = out_file
            finally:
                shutil.rmtree(tmp_dir, ignore_errors=True)
    return path, time.perf_counter() - t0


def _cmd_export(args, _open_target=None) -> int:
    root = store_mod.resolve_out_root(None)
    log_file = args.log_file or os.path.join(root, store_mod.LOGS_DIR, 'export.log')

    def body(logger):
        try:
            path, seconds = _do_export(args.snapshot, args.format, args.out)
        except Exception as e:
            return _finish_error(e, False, target=args.snapshot, log_file=log_file, logger=logger)
        size = os.path.getsize(path)
        print(f'wrote {path}')
        print(f'{args.format} · {size:,} bytes · {seconds:.1f}s')
        return 0

    return _with_logging(log_file, args.verbose, args.quiet, body)


# --------------------------------------------------------------------------------------------
# list / probe / dump: usage-level checks are real; result rendering lands with 7-b's pipeline.py
# --------------------------------------------------------------------------------------------

def _cmd_list(args, _open_target=None) -> int:
    try:
        root = store_mod.resolve_out_root(args.out)
    except errors.UeError as e:
        print(f'error: {e}', file=sys.stderr)
        return 1
    log_file = args.log_file or os.path.join(root, store_mod.LOGS_DIR, 'list.log')

    def body(logger):
        try:
            from . import pipeline  # lazy: lands with 7-b (fan-out rule)
            rows = pipeline.list_targets(out=args.out)
        except Exception as e:
            return _finish_error(e, args.json, target=None, log_file=log_file, logger=logger)
        if args.json:
            _print_json({'ok': True, 'processes': [dataclasses.asdict(r) for r in rows]})
        else:
            print(f'{"pid":<6} {"process":<34} {"engine hint":<20} profile')
            for r in rows:
                prof = f'{r.profile} ({r.profile_status})' if r.profile else '-'
                print(f'{r.pid:<6} {r.exe:<34} {r.engine_hint or "-":<20} {prof}')
        return 0

    return _with_logging(log_file, args.verbose, args.quiet, body)


def _cmd_probe(args, _open_target=None) -> int:
    try:
        root = store_mod.resolve_out_root(args.out)
    except errors.UeError as e:
        print(f'error: {e}', file=sys.stderr)
        return 1
    log_file = args.log_file or os.path.join(root, store_mod.LOGS_DIR, 'probe.log')

    def body(logger):
        try:
            from . import pipeline  # lazy: lands with 7-b (fan-out rule)
            report = pipeline.probe(_target_arg(args.target), profile=args.profile, out=args.out,
                                     _open_target=_open_target)
            written = pipeline.write_profile(report, out=args.out)[0] if args.write_profile else None
        except Exception as e:
            return _finish_error(e, args.json, target=args.target, log_file=log_file, logger=logger)
        if args.json:
            _print_json({
                'ok': report.ok, 'steps': list(report.steps), 'seconds': round(report.seconds, 1),
                'profile_written': written,
                'error': None if report.error is None else
                {'type': type(report.error).__name__, 'message': str(report.error), 'exit': 3},
            })
        else:
            if report.ok:
                print(f'{len(report.values)} values found, {len(report.unverified)} unverified.')
            else:
                print(f'detection stopped at {report.error.step}; later steps did not run')
            if written:
                print(f'wrote {written}')
        return 0 if report.ok else 3

    return _with_logging(log_file, args.verbose, args.quiet, body)


def _cmd_dump(args, _open_target=None) -> int:
    exports = exports_mod.DEFAULT_EXPORTS if args.exports is None else None
    if args.exports is not None:
        try:
            exports = _parse_exports(args.exports)
        except ValueError as e:
            print(f'{PROG} dump: error: {e}', file=sys.stderr)
            return 2
    if 'usmap' in exports:  # before importing or calling the pipeline (walking takes minutes)
        print('error: the usmap writer is not implemented yet', file=sys.stderr)
        return 1
    if args.allow_calls is not None:
        try:
            _parse_allow_calls(args.allow_calls)
        except ValueError as e:
            print(f'{PROG} dump: error: {e}', file=sys.stderr)
            return 2
        print('error: --allow-calls is not implemented yet', file=sys.stderr)
        return 1

    try:
        root = store_mod.resolve_out_root(args.out)
    except errors.UeError as e:
        print(f'error: {e}', file=sys.stderr)
        return 1
    log_file = args.log_file or os.path.join(root, store_mod.LOGS_DIR, 'dump.log')

    def body(logger):
        try:
            from . import pipeline  # lazy: lands with 7-b (fan-out rule)
            result = pipeline.dump(_target_arg(args.target), profile=args.profile, out=args.out, exports=exports,
                                    log_file=log_file, _open_target=_open_target)
        except Exception as e:
            return _finish_error(e, args.json, target=args.target, log_file=log_file, logger=logger)
        if args.json:
            _print_json({'ok': True, 'snapshot': result.path, 'mode': result.target.mode,
                         'seconds': round(result.seconds, 1), 'counts': result.counts,
                         'exports': list(result.exports), 'unverified': list(result.unverified),
                         'warnings': list(result.warnings)})
        else:
            print(result.path)
        return 0

    return _with_logging(log_file, args.verbose, args.quiet, body)


def main(argv=None, *, _open_target=None) -> int:
    """Never raises: argparse usage errors, KeyboardInterrupt and every other exception become an exit code."""
    try:
        parser = _build_parser()
        try:
            args = parser.parse_args(list(sys.argv[1:] if argv is None else argv))
        except _ArgExit as e:
            return e.status
        try:
            return args.func(args, _open_target=_open_target)
        except _ArgExit as e:
            return e.status
        except KeyboardInterrupt:
            print('interrupted', file=sys.stderr)
            return 130
    except Exception as e:  # last-resort net around a bug in this module itself
        print(f'error: unexpected {type(e).__name__}: {e}', file=sys.stderr)
        return 1
