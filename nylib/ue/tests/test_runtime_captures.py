"""Capture-backed checks for nylib.ue.runtime: the runtime gate (## Verification: O9.1-O9.5, the menu
values, the unverified-write and close checks) and the capture-based guards G9.9/G9.10. Gated on
NYLIB_UE_CAPTURES / NYLIB_UE_REQUIRED_TARGETS (real.py); see test_runtime.py for the capture-free
guards G9.1-G9.8.

Per real target: one snapshot session and one live session are opened once (through
real.capture_target), every check below runs against both, results are kept, then both sessions
close before the next target -- the per-test methods only assert on the kept results."""
import collections
import dataclasses
import os
import random
import unittest

from .. import errors
from .. import model
from .. import runtime
from .. import snapshot as snapshot_mod
from .. import store
from ..names import make_name_valid, strip_path
from ... import ctype
from . import port
from . import real
from . import runtime_oracle as ro

_CAPTURES_VAR = 'NYLIB_UE_CAPTURES'
_UNVERIFIED_KEYS = frozenset({'Off.InSDK.Text.TextDatOffset', 'Off.InSDK.Text.InTextDataStringOffset'})
_SERIAL_OFFSET = 0x10
# Planning probes (2026-10-02, root node's table): menu-state values per target, read-only sanity.
_MENU_EXPECTED = {
    'pal': dict(world='PL_MainWorld5', game_instance='BP_PalGameInstance_C', controller=None, pawn=None, actors=3192),
    'ts': dict(world='Title_Demo', game_instance='BP_NeweraGameInstance_C',
              controller='BP_SystemMapPlayerController_C', pawn='DefaultPawn', actors=19),
    'fb': dict(world='BattleWorld', game_instance='CardGameInstance_C', controller='CardGameController_C',
              pawn=None, actors=170),
}


@dataclasses.dataclass(frozen=True)
class _Check:
    ok: bool
    detail: str = ''


def _ok(detail: str = '') -> _Check:
    return _Check(True, detail)


def _fail(detail: str) -> _Check:
    return _Check(False, detail)


def _run(fn, *args, **kwargs):
    """Run one check function, turning any exception into a single failing _Check so one bad
    check never stops the rest (siblings keep running; the detail names the exception)."""
    try:
        return fn(*args, **kwargs)
    except Exception as e:  # noqa: BLE001 -- isolate one check's crash from its siblings
        return _fail(f'{type(e).__name__}: {e}')


def _store_per_kind(checks: dict, name: str, result) -> None:
    if isinstance(result, dict):
        for kind, v in result.items():
            checks[f'{name}:{kind}'] = v
    else:
        checks[f'{name}:snapshot'] = result
        checks[f'{name}:live'] = result


def _short_name(proxy) -> str | None:
    return None if proxy is None else type(proxy)._ue_name_


def _object_name(proxy) -> str | None:
    """The object's own leaf name (its FName, via _path_), not its runtime class -- UWorld is rarely
    subclassed, so the planning probe's 'world' values are the loaded map's object name, e.g. PL_MainWorld5."""
    if proxy is None:
        return None
    return proxy._path_.rsplit(':', 1)[-1].rsplit('.', 1)[-1]


_INTERFACE_PATH = '/Script/CoreUObject.Interface'


def _is_interface(rec, by_path: dict) -> bool:
    """True when rec is UInterface or its super chain reaches it: Dumper-7 drops the super there
    (CppGenerator.cpp bHasValidSuper = ... && !Struct.IsInterface()), so its align/sizeof assertion
    is not the real UObject-derived layout and cannot be compared."""
    if rec.path == _INTERFACE_PATH:
        return True
    seen = set()
    path = rec.super
    while path is not None and path not in seen:
        if path == _INTERFACE_PATH:
            return True
        seen.add(path)
        sup = by_path.get(path)
        path = sup.super if sup is not None else None
    return False


# ---------------------------------------------------------------------------------------------
# O9.1 test_layouts
# ---------------------------------------------------------------------------------------------

def _check_layouts(ues: dict, records: list, assertions: dict) -> dict:
    name_counts = collections.Counter(
        r.cpp_name for r in records if isinstance(r, (model.ClassRecord, model.StructRecord)))
    by_path = {r.path: r for r in records if isinstance(r, (model.ClassRecord, model.StructRecord))}
    candidates = [r for r in records if isinstance(r, (model.ClassRecord, model.StructRecord))
                  and name_counts[r.cpp_name] == 1 and r.cpp_name in assertions and not _is_interface(r, by_path)]
    results = {}
    for kind, ue in ues.items():
        structs = ro.FloorCheck('O9.1 structs', floor=1000)
        members = ro.FloorCheck('O9.1 member pairs', floor=10000)
        class_rule = 0
        for rec in candidates:
            oracle = assertions[rec.cpp_name]
            cls = ue.type(rec.path)
            if cls is None:
                structs.record(False, f'{rec.path}: type() is None')
                continue
            align = max(rec.min_alignment, 1)
            stride = -(-rec.size // align) * align
            d7 = ro.d7_alignof(rec, by_path)
            if oracle.alignof is not None and oracle.alignof != d7:
                ok = False  # model drift: Dumper-7's rule or our model of it changed
            elif d7 == align:
                ok = oracle.sizeof in (None, stride)
            else:  # ea0dab3's class rule ignored MinAlignment; align must be the predicted exception
                sup = by_path.get(rec.super)
                ok = (isinstance(rec, model.ClassRecord) and align > d7 and align & (align - 1) == 0
                      and (sup is None or align >= max(sup.min_alignment, 1))
                      and (not rec.path.startswith('/Script/') or rec.size % align == 0)
                      and oracle.sizeof in (None, -(-rec.size // d7) * d7))
                class_rule += 1
            structs.record(ok, f'{rec.cpp_name}: align {align} vs d7 {d7} (oracle {oracle.alignof}), '
                                f'stride {stride} vs {oracle.sizeof}')
            # ea0dab3 CollisionManager renames a same-struct name collision's second occurrence
            # with a trailing _<n> (Struct::StringifyName); pair by name like port.py's dumpspace
            # check does, so each property pairs with its own offsetof entry, in reflection order.
            valid_name = make_name_valid(strip_path(rec.name))
            pairs, _unpaired_o, _unpaired_u = port._ds_pair_by_name(
                list(oracle.offsets.items()), rec.properties, key_of_our=lambda p: make_name_valid(p.name),
                candidates_of_oracle=lambda n: port._ds_name_candidates(n, name_suffix=valid_name))
            for _oname, offset, prop in pairs:
                members.record(prop.offset == offset, f'{rec.cpp_name}.{prop.name}: {prop.offset:#x} vs {offset:#x}')
        problem = structs.problem() or members.problem()
        results[kind] = _fail(problem) if problem else _ok(
            f'structs {structs.checked} (class rule {class_rule}), members {members.checked}')
    return results


# ---------------------------------------------------------------------------------------------
# O9.2 test_predefined_members
# ---------------------------------------------------------------------------------------------

def _check_predefined(ues: dict, assertions: dict) -> dict:
    targets = (('ULevel', '/Script/Engine.Level', 'Actors'), ('UDataTable', '/Script/Engine.DataTable', 'RowMap'))
    results = {}
    for kind, ue in ues.items():
        detail = []
        for cpp_name, path, member in targets:
            oracle_rec = assertions.get(cpp_name)
            oracle_off = oracle_rec.offsets.get(member) if oracle_rec is not None else None
            cls = ue.type(path)
            descriptor = cls._ue_members_.get(member) if cls is not None else None
            if cls is None or oracle_off is None or descriptor is None:
                detail.append(f'{cpp_name}.{member}: missing (cls={cls is not None}, oracle={oracle_off!r}, '
                              f'descriptor={descriptor is not None})')
                continue
            our_off = ctype.offsetof(descriptor)
            if our_off != oracle_off:
                detail.append(f'{cpp_name}.{member}: {our_off:#x} vs {oracle_off:#x}')
        results[kind] = _ok() if not detail else _fail('; '.join(detail))
    return results


# ---------------------------------------------------------------------------------------------
# O9.3 test_enum_names
# ---------------------------------------------------------------------------------------------

def _check_enum_names(ues: dict, records: list, enums_info: dict) -> dict:
    name_counts = collections.Counter(r.cpp_name for r in records if isinstance(r, model.EnumRecord))
    candidates = [r for r in records if isinstance(r, model.EnumRecord) and name_counts[r.cpp_name] == 1
                  and len(enums_info.get(r.cpp_name, ())) == 1]
    results = {}
    for kind, ue in ues.items():
        fc = ro.FloorCheck('O9.3 enums', floor=500, max_fail_rate=0.01)
        for rec in candidates:
            oracle_names = set(ro.enum_member_names(enums_info[rec.cpp_name][0].members))
            our_cls = ue.enum(rec.path)
            if our_cls is None:
                fc.record(False, f'{rec.path}: enum() is None')
                continue
            fc.record(set(our_cls.__members__) == oracle_names, f'{rec.cpp_name}: name set differs')
        results[kind] = _fail(fc.problem()) if fc.problem() else _ok(f'{fc.checked} compared')
    return results


# ---------------------------------------------------------------------------------------------
# O9.4 test_lookups
# ---------------------------------------------------------------------------------------------

def _check_lookups(ues: dict, snap_doc, records: list) -> dict:
    all_records = list(snap_doc.objects)
    path_samples = []
    for i in ro.sample_indices(len(all_records), 1000):
        rec = all_records[i]
        try:
            p = snap_doc.objects.path(rec.index)
        except ValueError:
            continue
        path_samples.append((p, rec.address))

    class_records = [r for r in records if isinstance(r, model.ClassRecord)]
    by_short = collections.defaultdict(list)
    for r in class_records:
        by_short[r.name].append(r)
    unique_names = sorted(n for n, rs in by_short.items() if len(rs) == 1)
    dup_names = sorted(n for n, rs in by_short.items() if len(rs) > 1)
    unique_sample = [unique_names[i] for i in ro.sample_indices(len(unique_names), 200)]
    dup_sample = dup_names[:20]

    results = {}
    for kind, ue in ues.items():
        find_fc = ro.FloorCheck('O9.4 find', floor=min(1000, len(path_samples)))
        for p, addr in path_samples:
            obj = ue.find(p)
            find_fc.record(obj is not None and obj._address_ == addr, f'{p}: {obj!r} vs {addr:#x}')

        class_fc = ro.FloorCheck('O9.4 find_class', floor=min(200, len(unique_sample)))
        for name in unique_sample:
            obj = ue.find_class(name)
            expected_path = by_short[name][0].path
            class_fc.record(obj is not None and obj._path_ == expected_path, f'{name}: {obj!r} vs {expected_path!r}')

        amb_fc = ro.FloorCheck('O9.4 ambiguous', floor=0)
        for name in dup_sample:
            try:
                ue.find_class(name)
            except errors.AmbiguousNameError as e:
                expected = {r.path for r in by_short[name]}
                amb_fc.record(set(e.candidates) == expected, f'{name}: {e.candidates!r} vs {expected!r}')
            else:
                amb_fc.record(False, f'{name}: did not raise AmbiguousNameError')

        problem = find_fc.problem() or class_fc.problem() or amb_fc.problem()
        results[kind] = _fail(problem) if problem else _ok(
            f'find {find_fc.checked}, find_class {class_fc.checked}, ambiguous {amb_fc.checked}')
    return results


# ---------------------------------------------------------------------------------------------
# O9.5 test_serial_offset (and G9.9's weak-pointer side, via the same ctx.index)
# ---------------------------------------------------------------------------------------------

def _check_serial_offset(ues: dict) -> dict:
    results = {}
    for kind, ue in ues.items():
        ctx = getattr(ue, '_ctx', None)
        if ctx is None:
            results[kind] = _fail('Unreal exposes no _ctx attribute for white-box access (adjust in 9-G)')
            continue
        offset = ctx.index.serial_offset()
        if offset != _SERIAL_OFFSET:
            results[kind] = _fail(f'serial_offset() = {offset!r}, expected {_SERIAL_OFFSET:#x}')
            continue
        fc = ro.FloorCheck('O9.5 weak serials', floor=0, max_fail_rate=0.01)
        n = ctx.e.objects.num()
        for i in ro.sample_indices(n, 2000):
            try:
                addr, serial = ctx.index.item(i)
            except (IndexError, errors.DetectionError):
                continue
            if addr == 0 or serial == 0:
                continue
            fc.record(ctx.weak_get(i, serial) is not None, f'slot {i} serial {serial}: weak_get -> None')
        results[kind] = _fail(fc.problem()) if fc.problem() else _ok(f'{fc.checked} checked')
    return results


# ---------------------------------------------------------------------------------------------
# test_menu_values
# ---------------------------------------------------------------------------------------------

def _check_menu_values(ues: dict, target: str) -> dict:
    expected = _MENU_EXPECTED.get(target)
    results = {}
    for kind, ue in ues.items():
        if expected is None:
            results[kind] = _fail(f'no expected menu values recorded for target {target!r}')
            continue
        detail = []
        world = ue.world()
        if _object_name(world) != expected['world']:
            detail.append(f'world: {_object_name(world)!r} vs {expected["world"]!r}')
        game_instance = world._get_('OwningGameInstance') if world is not None else None
        if _short_name(game_instance) != expected['game_instance']:
            detail.append(f'game_instance: {_short_name(game_instance)!r} vs {expected["game_instance"]!r}')
        controller = ue.local_player_controller()
        if _short_name(controller) != expected['controller']:
            detail.append(f'controller: {_short_name(controller)!r} vs {expected["controller"]!r}')
        pawn = controller._get_('Pawn') if controller is not None else None
        if _short_name(pawn) != expected['pawn']:
            detail.append(f'pawn: {_short_name(pawn)!r} vs {expected["pawn"]!r}')
        actors = len(world.PersistentLevel.Actors) if world is not None else None
        if actors != expected['actors']:
            detail.append(f'actors: {actors!r} vs {expected["actors"]!r}')
        results[kind] = _ok() if not detail else _fail('; '.join(detail))
    return results


# ---------------------------------------------------------------------------------------------
# test_unverified_on_captures, test_close (D13 / root Q33 = B amended; each opens its own session)
# ---------------------------------------------------------------------------------------------

def _rw_factory(session: real.Session):
    """A write=True attach needs an _open_target that still accepts write=True: real.capture_target's
    factory asserts not write and not remote_calls, so this opens the capture read-only underneath
    (the image itself refuses writes) and lets Unreal.attach's own gate see the requested write=True."""
    inner = real.capture_target(session)

    def factory(target, *, write, remote_calls, cache_bytes):
        return inner(target, write=False, remote_calls=False, cache_bytes=cache_bytes)
    return factory


def _check_unverified(session: real.Session) -> _Check:
    factory = _rw_factory(session)
    try:
        runtime.Unreal.attach(1, write=True, _open_target=factory)
    except errors.UnverifiedOffsetsError as e:
        if set(e.keys) != _UNVERIFIED_KEYS:
            return _fail(f'keys = {e.keys!r}, expected {sorted(_UNVERIFIED_KEYS)}')
    else:
        return _fail('write=True attach did not raise UnverifiedOffsetsError')

    ue = runtime.Unreal.attach(1, write=True, allow_unverified=True, _open_target=factory)
    try:
        if set(ue.unverified) != _UNVERIFIED_KEYS:
            return _fail(f'ue.unverified = {ue.unverified!r}')
        actor_cls = ue.find_class('Actor')
        cdo = ue.cdo(actor_cls) if actor_cls is not None else None
        if cdo is None:
            return _fail('no Actor CDO to attempt a write on')
        try:
            cdo.CustomTimeDilation = cdo.CustomTimeDilation
        except errors.MemoryWriteError:
            return _ok()
        except AttributeError as e:
            return _fail(f'Actor has no CustomTimeDilation member: {e}')
        return _fail('a member write reached the read-only capture without MemoryWriteError')
    finally:
        ue.close()


def _check_close(session: real.Session) -> _Check:
    factory = real.capture_target(session)
    ue = runtime.Unreal.attach(1, _open_target=factory)
    world = ue.world()
    ue.close()
    if world is None:
        return _fail('world() is None; cannot exercise a post-close member read')
    try:
        _ = world.PersistentLevel
    except errors.SessionError:
        return _ok()
    return _fail('a member read after close() did not raise SessionError')


# ---------------------------------------------------------------------------------------------
# G9.9 test_weak_stale
# ---------------------------------------------------------------------------------------------

def _check_weak_stale(ue) -> _Check:
    ctx = getattr(ue, '_ctx', None)
    if ctx is None:
        return _fail('Unreal exposes no _ctx attribute for white-box access (adjust in 9-G)')
    fc = ro.FloorCheck('G9.9 stale weak', floor=100)
    n = ctx.e.objects.num()
    rng = random.Random(0x5EED)
    order = list(range(n))
    rng.shuffle(order)
    for i in order:
        if fc.checked >= 500:
            break
        try:
            addr, serial = ctx.index.item(i)
        except (IndexError, errors.DetectionError):
            continue
        if addr == 0 or serial == 0:
            continue
        if ctx.weak_get(i, serial) is None:
            continue
        fc.record(ctx.weak_get(i, serial + 1) is None, f'slot {i}: weak_get(serial+1) did not resolve to None')
    return _fail(fc.problem()) if fc.problem() else _ok(f'{fc.checked} checked')


# ---------------------------------------------------------------------------------------------
# G9.10 test_value_sweep (partial: object pointers, names, native bools -- see the report's note)
# ---------------------------------------------------------------------------------------------

def _check_value_sweep(ue) -> _Check:
    ctx = getattr(ue, '_ctx', None)
    if ctx is None:
        return _fail('Unreal exposes no _ctx attribute for white-box access (adjust in 9-G)')
    rows = list(ctx.index.table())
    sample = [rows[i] for i in ro.sample_indices(len(rows), 10000)]

    obj_ptr = ro.FloorCheck('sweep object pointers', floor=min(10000, len(sample)), max_fail_rate=0.001)
    names_ok = ro.FloorCheck('sweep names decode', floor=min(10000, len(sample)))
    bools = ro.FloorCheck('sweep native bools', floor=0)

    for row in sample:
        proxy = ctx.proxy(row.address)
        if proxy is None:
            obj_ptr.record(False, f'{row.address:#x}: proxy is None')
            continue
        obj_ptr.record(True)
        try:
            path = proxy._path_
        except errors.MemoryReadError:
            path = None
        names_ok.record(path is not None, f'{row.address:#x}: _path_ failed')
        for attr_name, descriptor in list(type(proxy)._ue_attrs_.items())[:8]:
            ptype = descriptor.record.type
            if ptype.kind != 'BoolProperty' or ptype.bit is not None:
                continue
            try:
                value = getattr(proxy, attr_name)
            except errors.MemoryReadError:
                continue
            bools.record(isinstance(value, bool), f'{row.address:#x}.{attr_name}: {value!r}')

    problem = obj_ptr.problem() or names_ok.problem() or (bools.problem() if bools.checked else None)
    if problem:
        return _fail(problem)
    return _ok(f'objects {obj_ptr.checked}, names {names_ok.checked}, bools {bools.checked}')


# ---------------------------------------------------------------------------------------------
# Per-session report
# ---------------------------------------------------------------------------------------------

@dataclasses.dataclass
class _SessionRuntime:
    session: real.Session
    checks: dict


def _build_report(session: real.Session) -> _SessionRuntime:
    checks: dict = {}
    ours_root = os.path.join(session.dir, 'ours')
    refs = store.find_snapshots(ours_root)
    if not refs:
        return _SessionRuntime(session=session, checks=checks)

    oracle_dir = os.path.join(session.dir, 'oracle', session.data['oracle']['folder'])
    assertions = _run(ro.parse_assertions, os.path.join(oracle_dir, 'CppSDK', 'Assertions.inl'))
    if isinstance(assertions, _Check):
        assertions = {}
    enums_info = _run(ro.parse_enums_info, os.path.join(oracle_dir, 'Dumpspace', 'EnumsInfo.json'))
    if isinstance(enums_info, _Check):
        enums_info = {}

    factory = real.capture_target(session)
    snap_doc = snapshot_mod.Snapshot.load(refs[0].path)
    try:
        records = list(snap_doc.types())
        ues = {}
        try:
            ues['snapshot'] = runtime.Unreal.attach(1, dump=refs[0].path, _open_target=factory)
            ues['live'] = runtime.Unreal.attach(1, _open_target=factory)

            _store_per_kind(checks, 'layouts', _run(_check_layouts, ues, records, assertions))
            _store_per_kind(checks, 'predefined_members', _run(_check_predefined, ues, assertions))
            _store_per_kind(checks, 'enum_names', _run(_check_enum_names, ues, records, enums_info))
            _store_per_kind(checks, 'lookups', _run(_check_lookups, ues, snap_doc, records))
            _store_per_kind(checks, 'serial_offset', _run(_check_serial_offset, ues))
            _store_per_kind(checks, 'menu_values', _run(_check_menu_values, ues, session.target))
            for kind, ue in ues.items():
                checks[f'weak_stale:{kind}'] = _run(_check_weak_stale, ue)
                checks[f'value_sweep:{kind}'] = _run(_check_value_sweep, ue)
        finally:
            for ue in ues.values():
                try:
                    ue.close()
                except Exception:
                    pass
    finally:
        snap_doc.close()

    checks['unverified:both'] = _run(_check_unverified, session)
    checks['close:both'] = _run(_check_close, session)
    return _SessionRuntime(session=session, checks=checks)


class CaptureRuntimeTests(unittest.TestCase):
    """9-G.1: real-capture gate for the runtime (## Verification). setUpClass opens each required
    target's sessions once; the test_* methods below only assert on the kept per-check results."""

    @classmethod
    def setUpClass(cls):
        if real.captures_root() is None:
            raise unittest.SkipTest(f'{_CAPTURES_VAR} not set')
        cls.sessions = real.iter_sessions()
        cls.reports: dict[str, _SessionRuntime] = {}
        for target in real.required_targets():
            matches = [s for s in cls.sessions if s.target == target]
            if not matches or not store.find_snapshots(os.path.join(matches[-1].dir, 'ours')):
                continue
            cls.reports[target] = _build_report(matches[-1])

    def test_sessions_present(self):
        """A guard: fails, never skips, when a required target has no complete session or no 7-G snapshot."""
        for target in real.required_targets():
            with self.subTest(target=target):
                matches = [s for s in self.sessions if s.target == target]
                self.assertTrue(matches, f'required target {target!r} has no complete session')
                ours_root = os.path.join(matches[-1].dir, 'ours')
                self.assertTrue(store.find_snapshots(ours_root),
                                f'required target {target!r} has no 7-G snapshot under {ours_root}')

    def _assert_all(self, name: str):
        for target, report in self.reports.items():
            for kind in ('snapshot', 'live'):
                key = f'{name}:{kind}'
                with self.subTest(target=target, kind=kind, check=name):
                    result = report.checks.get(key)
                    self.assertIsNotNone(result, f'{key} did not run')
                    self.assertTrue(result.ok, result.detail)

    def test_layouts(self):
        self._assert_all('layouts')

    def test_predefined_members(self):
        self._assert_all('predefined_members')

    def test_enum_names(self):
        self._assert_all('enum_names')

    def test_lookups(self):
        self._assert_all('lookups')

    def test_serial_offset(self):
        self._assert_all('serial_offset')

    def test_menu_values(self):
        self._assert_all('menu_values')

    def test_weak_stale(self):
        self._assert_all('weak_stale')

    def test_value_sweep(self):
        self._assert_all('value_sweep')

    def test_unverified_on_captures(self):
        for target, report in self.reports.items():
            with self.subTest(target=target):
                result = report.checks.get('unverified:both')
                self.assertIsNotNone(result, 'unverified:both did not run')
                self.assertTrue(result.ok, result.detail)

    def test_close(self):
        for target, report in self.reports.items():
            with self.subTest(target=target):
                result = report.checks.get('close:both')
                self.assertIsNotNone(result, 'close:both did not run')
                self.assertTrue(result.ok, result.detail)


if __name__ == '__main__':
    unittest.main()
