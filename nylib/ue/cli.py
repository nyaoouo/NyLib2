"""`nylib.ue` command-line shell (I4): argument parsing, logging scope, exit codes."""
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
_DUMP_EXPORT_NAMES = _EXPORT_NAMES | frozenset({'image'})  # (7-c) dump --exports also takes image
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


def _nonempty(raw: str) -> str:
    if raw == '':
        raise argparse.ArgumentTypeError('must not be empty')
    return raw


def _split_list(raw: str) -> list:
    return [x for x in (p.strip() for p in raw.split(',')) if x]


def _parse_exports(raw: str) -> tuple:
    items = _split_list(raw)
    if 'none' in items:
        if len(items) > 1:
            raise ValueError('--exports: "none" cannot be combined with a format')
        return ()
    for x in items:
        if x not in _DUMP_EXPORT_NAMES:
            raise ValueError(f'--exports: unknown format {x!r}')
    return tuple(items)


def _parse_allow_calls(raw: str) -> tuple:
    items = _split_list(raw)
    if not items:
        raise ValueError('--allow-calls: name at least one of append-string, game-info, text, or give no value for all three')
    for x in items:
        if x not in _ALLOW_CALLS_NAMES:
            raise ValueError(f'--allow-calls: unknown value {x!r}')
    return tuple(items)


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
        sp.add_argument('--log-file', dest='log_file', default=None, type=_nonempty,
                        help='default: <out>/_logs/<command>.log')

    pl = sub.add_parser('list', help='list running processes that look like Unreal Engine games')
    pl.add_argument('--out', dest='out', default=None, type=_nonempty,
                    help='output root (default: .\\ue_dumps or env NYLIB_UE_OUT)')
    pl.add_argument('--json', action='store_true')
    common(pl)
    pl.set_defaults(func=_cmd_list)

    pp = sub.add_parser('probe', help='detect globals, layouts and offsets only; --write-profile pins GObjects and GNames')
    pp.add_argument('target', type=_nonempty)
    pp.add_argument('--profile', dest='profile', default=None, help='game profile (TOML) with pinned values')
    pp.add_argument('--out', dest='out', default=None, type=_nonempty,
                    help='output root (default: .\\ue_dumps or env NYLIB_UE_OUT)')
    pp.add_argument('--explain', action='store_true', help="Dumper-7's own console messages")
    pp.add_argument('--write-profile', dest='write_profile', action='store_true')
    pp.add_argument('--json', action='store_true')
    common(pp)
    pp.set_defaults(func=_cmd_probe)

    pd = sub.add_parser('dump', help='probe, walk reflection, write a snapshot and the default exports')
    pd.add_argument('target', type=_nonempty)
    pd.add_argument('--profile', dest='profile', default=None)
    pd.add_argument('--out', dest='out', default=None, type=_nonempty,
                    help='output root (default: .\\ue_dumps or env NYLIB_UE_OUT)')
    pd.add_argument('--exports', dest='exports', default=None,
                     help="formats written with the snapshot: idmap, gobjects, gobjects-props, image (the game's "
                          'main module as a PE file), usmap (default: idmap,gobjects,gobjects-props,image,usmap; '
                          '"none" writes the snapshot only)')
    pd.add_argument('--allow-calls', dest='allow_calls', nargs='?', const=_ALLOW_CALLS_DEFAULT, default=None,
                     help='append-string, game-info, text; no value means all three. Each makes a call in the game '
                          'that can crash it; a profile can never enable calls')
    pd.add_argument('--strict', action='store_true',
                     help='raise instead of publishing when the export quality verdict is degraded')
    pd.add_argument('--json', action='store_true')
    common(pd)
    pd.set_defaults(func=_cmd_dump)

    pe = sub.add_parser('export', help='write another format from an existing snapshot; the game is not needed')
    pe.add_argument('snapshot')
    pe.add_argument('--format', dest='format', required=True, choices=sorted(_EXPORT_NAMES),
                     help='idmap, gobjects, gobjects-props, usmap')
    pe.add_argument('--out', dest='out', default=None, type=_nonempty,
                    help='output file (default: the format\'s place in the snapshot)')
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


def _with_logging(log_file: str, verbose: bool, quiet: bool, body, *, json_mode: bool, target):
    """Attach `nylib.ue`'s file+stderr handlers for one call, run `body(logger)`, restore state after.
    `body` is the outermost boundary (rules §4c): KeyboardInterrupt and any other exception it raises
    are handled here, while the handlers are still attached."""
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
        try:
            return body(logger)
        except KeyboardInterrupt as e:
            logger.debug('KeyboardInterrupt', exc_info=True)
            if json_mode:
                _print_json({'ok': False, 'error': {'type': 'KeyboardInterrupt', 'message': str(e), 'exit': 130}})
            else:
                print('interrupted', file=sys.stderr)
            return 130
        except Exception as e:
            return _finish_error(e, json_mode, target=target, log_file=log_file, logger=logger)
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


def _hex(value: int) -> str:
    return f'-0x{-value:X}' if value < 0 else f'0x{value:X}'


def _json_value(v):
    """root §6: ints as hex strings, tuples as lists of hex strings; bool/str/None pass through."""
    if isinstance(v, bool) or v is None or isinstance(v, str):
        return v
    if isinstance(v, int):
        return _hex(v)
    if isinstance(v, tuple):
        return [_json_value(x) for x in v]
    return v


def _target_json(target) -> dict:
    return {'mode': target.mode, 'pid': target.pid, 'exe': target.exe, 'exe_path': target.exe_path,
            'exe_sha256': target.exe_sha256, 'module_base': _hex(target.module_base),
            'size_of_image': _hex(target.size_of_image), 'pe_timestamp': _hex(target.pe_timestamp),
            'file_version': target.file_version}


def _probe_json_doc(report, written) -> dict:
    return {
        'ok': report.ok, 'target': _target_json(report.target), 'profile': report.profile,
        'profile_note': report.profile_note,
        'values': [{'name': v.name, 'key': v.key, 'value': _json_value(v.value), 'how': v.how, 'check': v.check,
                    'unverified': v.unverified} for v in report.values],
        'unverified': list(report.unverified), 'steps': list(report.steps), 'stem': report.stem,
        'game_name': report.game_name, 'game_name_from': report.game_name_from,
        'engine_version': report.engine_version, 'engine_version_from': report.engine_version_from,
        'warnings': list(report.warnings), 'seconds': round(report.seconds, 1),
        'error': None if report.error is None else
        {'type': type(report.error).__name__, 'message': str(report.error), 'exit': 3},
        'profile_written': written,
    }


_PROBE_GLOBAL_ROW_NAMES = ('GObjects', 'GNames', 'AppendString', 'ProcessEvent.Index', 'ProcessEvent', 'GWorld')

_GNAMES_IDA_HINT = (
    'the FNamePool constructor initialises an SRWLOCK and then references L"ByteProperty"; '
    'the `lea rcx` before the call points at GNames; NySigWorker2 can turn that site into a signature.'
)


def _render_probe_value(v) -> str:
    val = v.value
    if val is None:
        return '-'
    if isinstance(val, bool):
        return str(val)
    if isinstance(val, int):
        return _hex(val)
    if isinstance(val, tuple):
        return ', '.join(_hex(x) if isinstance(x, int) else str(x) for x in val)
    return str(val)


def _probe_header_lines(report, version: str) -> list:
    t = report.target
    lines = [
        f'{PROG} {version} · probe · {t.exe} (pid {t.pid}) · {t.mode} · read-only',
        f'build    pe {_hex(t.pe_timestamp)} / size {_hex(t.size_of_image)} · file {t.file_version or "-"}',
        f'game     {report.game_name or "-"} ({report.game_name_from or "-"}) · '
        f'engine {report.engine_version or "-"} ({report.engine_version_from or "-"})',
    ]
    if report.profile:
        lines.append(f'profile  {report.profile} ({report.profile_note})')
    else:
        lines.append(f'profile  {report.profile_note}')
    return lines


def _probe_table_lines(report, verbose: bool) -> list:
    """I4's `value | result | how | check` table: by default the six global rows, every unverified
    row and every `profile:` row (original order, with the rest collapsed into `... N more`);
    `-v` lists every row."""
    if verbose:
        shown, hidden = report.values, 0
    else:
        shown = [v for v in report.values
                 if v.name in _PROBE_GLOBAL_ROW_NAMES or v.unverified or v.how.startswith('profile:')]
        hidden = len(report.values) - len(shown)
    lines = [f'{"value":<25} {"result":<17} {"how":<42} check']
    for v in shown:
        lines.append(f'{v.name:<25} {_render_probe_value(v):<17} {v.how:<42} {v.check}')
    if hidden:
        lines.append(f'... {hidden} more (-v lists every value)')
    return lines


def _pin_for_step(step: str):
    if step.startswith('ObjectArray::'):
        return 'gobjects'
    if step.startswith('FName::') or step.startswith('NameArray::'):
        return 'gnames'
    return None


def _detection_fix_lines(e, target) -> list:
    pin = _pin_for_step(e.step)
    if pin is None:
        return [
            'fix: pin it in a profile written by hand (see docs/nylib/ue/dump.md), then probe again:',
            f'  {PROG} probe {target} --explain          (what the finders reported)',
        ]
    return [
        'fix: pin it in a profile, then probe again:',
        f'  {PROG} probe {target} --write-profile    (pins the GObjects and GNames found so far; fill in [globals] {pin})',
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
        error_doc = {'type': type(e).__name__, 'message': message, 'exit': exit_code}
        if (quality := getattr(e, 'quality', None)) is not None:
            error_doc['quality'] = quality
        _print_json({'ok': False, 'error': error_doc})
        return exit_code
    if known:
        print(f'error: {message}', file=sys.stderr)
    else:
        print(f'error: unexpected {type(e).__name__}: {message} (details: {log_file})', file=sys.stderr)
    for line in fix_lines:
        print(line, file=sys.stderr)
    return exit_code


def _make_dump_progress(version: str, features=()):
    """I4 dump progress: header/profile/[n/3] INFO lines on `nylib.ue.cli`, each with its own elapsed seconds.
    (7-c) `image` prints nothing: its elapsed time is folded into `[3/3]`, not `[2/3]` (G7.6)."""
    cli_logger = logging.getLogger('nylib.ue.cli')
    t0 = time.perf_counter()
    image_seconds = 0.0

    def progress(event, payload):
        nonlocal t0, image_seconds
        if event == 'walk':  # per-object ticks inside step 2 must not restart its clock
            return
        now = time.perf_counter()
        elapsed, t0 = now - t0, now
        if event == 'image':
            image_seconds = elapsed
            return
        if event == 'exports':
            elapsed += image_seconds
        if event == 'open':
            tail = f'calls: {", ".join(features)}' if features else 'read-only'
            cli_logger.info('%s %s · dump · %s (pid %s) · %s · %s', PROG, version, payload.exe, payload.pid, payload.mode, tail)
        elif event == 'probe':
            report = payload
            if report.profile:
                cli_logger.info('profile  %s (%s)', report.profile, report.profile_note)
            else:
                cli_logger.info('profile  %s', report.profile_note)
            names = ', '.join(report.unverified) if report.unverified else '-'
            cli_logger.info('[1/3] probe ok %d values (%d unverified: %s) (%.1fs)',
                            len(report.values), len(report.unverified), names, report.seconds)
        elif event == 'calls':
            results = payload
            status = ' · '.join(f'{r.feature} {"ok" if r.ok else "failed" if r.ran else "not called"}' for r in results)
            cli_logger.info('calls    %s (%.1fs)', status, sum(r.seconds for r in results))
        elif event == 'snapshot':
            c = payload
            cli_logger.info('[2/3] snapshot ok %s · %s · %s · %s · %s · %s (%.1fs)',
                            c.get('classes'), c.get('structs'), c.get('enums'), c.get('functions'),
                            c.get('packages'), c.get('objects'), elapsed)
        elif event == 'exports':
            cli_logger.info('[3/3] exports ok %s (%.1fs)', ','.join(payload), elapsed)

    return progress


# --------------------------------------------------------------------------------------------
# info (full)
# --------------------------------------------------------------------------------------------

def _image_export_rel(meta: dict, snap_path: str) -> str | None:
    """(7-c) `meta.image.file` as an `exports` entry: exactly `image/<name>`, `<name>` neither `.` nor `..`,
    naming an existing file."""
    img = meta.get('image') if isinstance(meta, dict) else None
    file = img.get('file') if isinstance(img, dict) else None
    if not isinstance(file, str) or '\\' in file:
        return None
    parts = file.split('/')
    if len(parts) != 2 or parts[0] != 'image' or parts[1] in ('', '.', '..'):
        return None
    if not os.path.isfile(os.path.join(snap_path, 'image', parts[1])):
        return None
    return file


def _info_doc(path: str, snap) -> dict:
    present = []
    for fmt in sorted(_EXPORT_NAMES):
        rel = exports_mod.export_path(fmt, snap)
        if os.path.isfile(os.path.join(snap.path, rel)):
            present.append(rel.replace(os.sep, '/'))
    if (img_rel := _image_export_rel(snap.meta, snap.path)) is not None:  # (7-c)
        present.append(img_rel)
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
    rc = meta.get('remote_calls')
    tail = f"calls: {', '.join(rc)}" if isinstance(rc, list) and rc and all(isinstance(x, str) for x in rc) else 'read-only'
    return [
        f"snapshot  schema {_meta_get(meta, 'schema.version')} · {_meta_get(meta, 'generator.tool')} "
        f"{_meta_get(meta, 'generator.version')} · {_meta_get(meta, 'created')} · {_meta_get(meta, 'mode')} · {tail}",
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

    return _with_logging(log_file, args.verbose, args.quiet, body, json_mode=args.json, target=args.snapshot)


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

    return _with_logging(log_file, args.verbose, args.quiet, body, json_mode=False, target=args.snapshot)


# --------------------------------------------------------------------------------------------
# list / probe / dump
# --------------------------------------------------------------------------------------------

def _cmd_list(args, _open_target=None) -> int:
    try:
        root = store_mod.resolve_out_root(args.out)
    except errors.UeError as e:
        return _finish_error(e, args.json, target=args.out, log_file=args.log_file, logger=None)
    log_file = args.log_file or os.path.join(root, store_mod.LOGS_DIR, 'list.log')

    def body(logger):
        try:
            from . import pipeline  # lazy import: cli avoids pipeline at module load
            rows = pipeline.list_targets(out=args.out)
        except Exception as e:
            return _finish_error(e, args.json, target=None, log_file=log_file, logger=logger)
        if args.json:
            _print_json({'ok': True, 'processes': [dataclasses.asdict(r) for r in rows]})
        else:
            print(f'{"pid":<6} {"process":<34} {"engine hint":<20} profile')
            for r in rows:
                if r.profile:
                    prof = f'{r.profile} ({r.profile_status})'
                elif r.profile_status != '-':
                    prof = r.profile_status
                else:
                    prof = '-'
                print(f'{r.pid:<6} {r.exe:<34} {r.engine_hint or "-":<20} {prof}')
        return 0

    return _with_logging(log_file, args.verbose, args.quiet, body, json_mode=args.json, target=None)


def _cmd_probe(args, _open_target=None) -> int:
    try:
        root = store_mod.resolve_out_root(args.out)
    except errors.UeError as e:
        return _finish_error(e, args.json, target=args.out, log_file=args.log_file, logger=None)
    log_file = args.log_file or os.path.join(root, store_mod.LOGS_DIR, 'probe.log')

    def body(logger):
        cli_logger = logging.getLogger('nylib.ue.cli')
        try:
            from . import pipeline  # lazy import: cli avoids pipeline at module load
            report = pipeline.probe(_target_arg(args.target), profile=args.profile, out=args.out,
                                     _open_target=_open_target)
        except Exception as e:
            return _finish_error(e, args.json, target=args.target, log_file=log_file, logger=logger)
        for w in report.warnings:
            cli_logger.warning(w)
        cli_logger.info('done in %.1fs', report.seconds)

        if args.json:
            written, pin_names = None, ()
            if args.write_profile:
                try:
                    written, pin_names = pipeline.write_profile(report, out=args.out)
                except FileExistsError as e:  # F7.1 = A
                    logger.debug('%s: %s', type(e).__name__, e, exc_info=True)
                    path = e.args[0] if e.args else str(e)
                    message = f'{path} exists; merge the lines above by hand, or move it away and run again'
                    _print_json({'ok': False, 'error': {'type': 'FileExistsError', 'message': message, 'exit': 1}})
                    return 1
                except Exception as e:
                    return _finish_error(e, args.json, target=args.target, log_file=log_file, logger=logger)
            _print_json(_probe_json_doc(report, written))
            return 0 if report.ok else 3

        for line in _probe_header_lines(report, _package_version()):
            print(line)
        print()
        for line in _probe_table_lines(report, args.verbose):
            print(line)
        if args.explain:
            print()
            for line in report.explanations:
                print(line)
            if report.error is not None and _pin_for_step(report.error.step) == 'gnames':
                print(_GNAMES_IDA_HINT)
        print()
        if report.ok:
            print(f'{len(report.values)} values found, {len(report.unverified)} unverified. No snapshot was written.')
            print('Next:')
            print(f'  {PROG} dump {args.target}')
            print(f'  {PROG} probe {args.target} --write-profile    (pin GObjects and GNames for this game)')
        else:
            print(f'detection stopped at {report.error.step}; later steps did not run')
            print(f'error: {report.error}', file=sys.stderr)
            for line in _detection_fix_lines(report.error, args.target):
                print(line, file=sys.stderr)

        if args.write_profile:  # F7.1 = A: the report above is printed either way
            try:
                written, pin_names = pipeline.write_profile(report, out=args.out)
            except FileExistsError as e:
                logger.debug('%s: %s', type(e).__name__, e, exc_info=True)
                path = e.args[0] if e.args else str(e)
                message = f'{path} exists; merge the lines above by hand, or move it away and run again'
                text = getattr(e, 'profile_text', None)
                if text is not None:
                    print(text, end='' if text.endswith('\n') else '\n')
                print(f'error: {message}', file=sys.stderr)
                return 1
            except Exception as e:
                return _finish_error(e, args.json, target=args.target, log_file=log_file, logger=logger)
            print(f'wrote {written} ({len(pin_names)} globals pinned for build {_hex(report.target.pe_timestamp)}; '
                  'offsets stay automatic)')

        return 0 if report.ok else 3

    return _with_logging(log_file, args.verbose, args.quiet, body, json_mode=args.json, target=args.target)


def _cmd_dump(args, _open_target=None) -> int:
    exports = None  # (7-c) None means pipeline.DEFAULT_DUMP_EXPORTS, read after the lazy import below
    if args.exports is not None:
        try:
            exports = _parse_exports(args.exports)
        except ValueError as e:
            print(f'{PROG} dump: error: {e}', file=sys.stderr)
            return 2
    features = ()
    if args.allow_calls is not None:
        try:
            features = _parse_allow_calls(args.allow_calls)
        except ValueError as e:
            print(f'{PROG} dump: error: {e}', file=sys.stderr)
            return 2

    try:
        root = store_mod.resolve_out_root(args.out)
    except errors.UeError as e:
        return _finish_error(e, args.json, target=args.out, log_file=args.log_file, logger=None)
    log_file = args.log_file or os.path.join(root, store_mod.LOGS_DIR, 'dump.log')

    def body(logger):
        cli_logger = logging.getLogger('nylib.ue.cli')
        try:
            from . import pipeline, remote_calls  # lazy import: cli avoids pipeline at module load
            dump_exports = pipeline.DEFAULT_DUMP_EXPORTS if exports is None else exports
            allow_calls_kwargs = {'allow_calls': features} if args.allow_calls is not None else {}
            result = pipeline.dump(_target_arg(args.target), profile=args.profile, out=args.out, exports=dump_exports,
                                    progress=_make_dump_progress(_package_version(), remote_calls.parse_features(features)),
                                    strict=args.strict, _open_target=_open_target, **allow_calls_kwargs)
        except Exception as e:
            return _finish_error(e, args.json, target=args.target, log_file=log_file, logger=logger)
        for w in result.warnings:
            cli_logger.warning(w)
        cli_logger.info('done in %.1fs', result.seconds)
        if args.json:
            _print_json({'ok': True, 'snapshot': result.path, 'mode': result.target.mode,
                         'seconds': round(result.seconds, 1), 'counts': result.counts, 'quality': result.quality,
                         'exports': list(result.exports), 'unverified': list(result.unverified),
                         'warnings': list(result.warnings),
                         'remote_calls': [{'feature': r.feature, 'ran': r.ran, 'ok': r.ok, 'detail': r.detail,
                                            'seconds': round(r.seconds, 1)} for r in result.remote_calls]})
        else:
            print(result.path)
        return 0

    return _with_logging(log_file, args.verbose, args.quiet, body, json_mode=args.json, target=args.target)


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
