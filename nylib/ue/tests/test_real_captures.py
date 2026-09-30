"""Session discovery and per-session checks.

Five always-on tests run with no environment at all. RealCapturesTests and RequiredTargetsTests are
env-gated: see real.py for the discovery/check API and plans/PLAN-ue-dumper/20-capture-sessions/index.md
for the session.json contract. Later stages add their own V5 test modules and use real.py for
discovery; they never edit this module.
"""
import copy
import hashlib
import json
import os
import pathlib
import struct
import tempfile
import unittest
from unittest import mock

from ..capture import ImageSource, write_capture
from ..memory import Module
from .oracle import GObjectsDump, parse_gobjects_dump
from .real import (
    REQUIRED_ORACLE_FILES, Session, TARGET_APPIDS, captures_root, check_session, env_path,
    iter_sessions, required_targets, same_instance, validate_session,
)

_CAPTURES_VAR = 'NYLIB_UE_CAPTURES'
_REQUIRED_TARGETS_VAR = 'NYLIB_UE_REQUIRED_TARGETS'


# Synthetic session fixtures (verification / mutation-testing only; callers must use a temp
# directory, never ue_dumps/ -- this is dev-tooling support, not itself a captured session).
def _make_valid_doc(*, short: str = 'pal', session_id: str = 'SYN-1', oracle_stem: str = 'Synthetic-1.0') -> dict:
    """A complete, self-consistent session.json document (no backing files on disk)."""
    install_dir = 'D:\\Synth\\Game'
    shipping_exe = install_dir + '\\Binaries\\Shipping.exe'
    oracle_files = {name: {'size': 1, 'sha256': '0' * 64} for name in REQUIRED_ORACLE_FILES}
    oracle_files[f'IDAMappings/{oracle_stem}.idmap'] = {'size': 1, 'sha256': '1' * 64}
    return {
        'schema': {'name': 'nylib.ue.capture-session', 'version': '1.0'},
        'session_id': session_id,
        'status': 'complete',
        'reason': None,
        'harness_version': 'TEST',
        'state': 'idle',
        'target': {
            'name': 'Synthetic Target', 'short': short, 'appid': TARGET_APPIDS[short], 'buildid': '1',
            'install_dir': install_dir, 'shipping_exe': shipping_exe,
            'pe_timestamp': '0x12345678', 'size_of_image': '0x3000', 'module_base': '0x7FF600000000',
        },
        'launch': {
            'steam_exe': 'C:\\Steam\\steam.exe', 'command_line': 'steam.exe -applaunch 1',
            'launch_time': '2026-01-01T00:00:00+00:00', 'launch_filetime': 1,
            'recorded_command_line': None, 'arguments_arrived': None,
        },
        'processes': [{'pid': 1111, 'creation_filetime': 1, 'image_path': shipping_exe, 'role': 'shipping'}],
        'capture': {
            'file': 'capture.zip', 'attempts': 1, 'seconds': 1.0, 'bytes': 1, 'chunks': 1,
            'skipped_bytes': 0, 'excluded_bytes': 0, 'excluded_by_reason': {}, 'verified': True,
            'quality': {'passed': True},
        },
        'oracle': {'stem': oracle_stem, 'folder': oracle_stem, 'longest_path': 10, 'files': oracle_files},
        'dumper7_folders': {
            'D:\\Dumper-7': {'exists_before': False, 'exists_after': False, 'unchanged': True},
            'C:\\Dumper-7': {'exists_before': False, 'exists_after': False, 'unchanged': True},
        },
        'kill': None,
    }


def _build_pe_bytes(timestamp: int, size_of_image: int) -> bytes:
    """A minimal valid PE32+ AMD64 image (DOS/COFF/optional header, zero sections)."""
    nt_offset, opt_size = 0x80, 0x70
    opt = nt_offset + 24
    buf = bytearray(size_of_image)
    buf[0:2] = b'MZ'
    struct.pack_into('<I', buf, 0x3C, nt_offset)
    buf[nt_offset:nt_offset + 4] = b'PE\0\0'
    struct.pack_into('<H', buf, nt_offset + 4, 0x8664)  # machine: AMD64
    struct.pack_into('<H', buf, nt_offset + 6, 0)        # num sections
    struct.pack_into('<I', buf, nt_offset + 8, timestamp)
    struct.pack_into('<H', buf, nt_offset + 20, opt_size)
    struct.pack_into('<H', buf, opt, 0x20B)              # magic: PE32+
    struct.pack_into('<I', buf, opt + 0x38, size_of_image)
    return bytes(buf)


def _gobjects_bytes(line1: str, stem: str, rows) -> bytes:
    header = f'{line1}\r\n\r\n{stem}\r\n\r\nCount: {len(rows)}\r\n\r\n\r\n'
    body = '\r\n'.join(f'[{index:08X}] {{{address:#x}}} {name}' for index, address, name in rows)
    return (header + body + '\r\n').encode('utf-8')


def build_synthetic_session(root: str, *, short: str = 'pal', session_id: str = 'SYN-1',
                             folder: str = '260101-000000', object_count: int = 12000) -> str:
    """Materialize one complete session (session.json + capture.zip + oracle/) under root: a real
    capture over a local MemorySource plus a Dumper-7-shaped oracle folder, for RealCapturesTests
    verification and mutation testing. Fixture only -- never write this under ue_dumps/."""
    session_dir = os.path.join(root, short, folder)
    os.makedirs(session_dir, exist_ok=True)

    main_base, size_of_image, pe_timestamp = 0x7FF600000000, 0x3000, 0x12345678
    obj_base, stride = main_base + size_of_image, 0x20
    module_name = 'Shipping-Win64-Shipping.exe'
    install_dir = 'D:\\Synth\\Game'
    shipping_exe = install_dir + '\\Binaries\\Win64\\' + module_name

    module_data = _build_pe_bytes(pe_timestamp, size_of_image)
    objects = bytearray(stride * object_count)
    for i in range(object_count):
        objects[i * stride:i * stride + 8] = main_base.to_bytes(8, 'little')  # vtable into the main module
    modules = [Module(module_name, main_base, size_of_image, shipping_exe)]
    image = ImageSource([(main_base, module_data), (obj_base, bytes(objects))], modules=modules)
    stats = write_capture(os.path.join(session_dir, 'capture.zip'), image,
                           [(main_base, size_of_image), (obj_base, len(objects))], modules=modules)

    oracle_stem = 'Synthetic-1.0'
    oracle_dir = os.path.join(session_dir, 'oracle', oracle_stem)
    rows = [(i, obj_base + i * stride, f'Class Pkg.Obj_{i}') for i in range(object_count)]
    file_bytes = {name: b'placeholder\n' for name in REQUIRED_ORACLE_FILES}
    file_bytes['GObjects-Dump.txt'] = _gobjects_bytes('Object dump by nylib.ue (Dumper-7 format)', oracle_stem, rows)
    file_bytes[f'IDAMappings/{oracle_stem}.idmap'] = b'\x00' * 16
    oracle_files = {}
    for rel, raw in file_bytes.items():
        path = os.path.join(oracle_dir, *rel.split('/'))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'wb') as f:
            f.write(raw)
        oracle_files[rel] = {'size': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}

    doc = _make_valid_doc(short=short, session_id=session_id, oracle_stem=oracle_stem)
    doc['target'].update({
        'install_dir': install_dir, 'shipping_exe': shipping_exe,
        'pe_timestamp': f'0x{pe_timestamp:X}', 'size_of_image': f'0x{size_of_image:X}', 'module_base': f'0x{main_base:X}',
    })
    doc['processes'] = [{'pid': 1111, 'creation_filetime': 1, 'image_path': shipping_exe, 'role': 'shipping'}]
    doc['capture'] = {
        'file': 'capture.zip', 'attempts': 1, 'seconds': stats['seconds'], 'bytes': stats['bytes'],
        'chunks': stats['chunks'], 'skipped_bytes': stats['skipped_bytes'], 'excluded_bytes': 0,
        'excluded_by_reason': {}, 'verified': True, 'quality': {'passed': True},
    }
    doc['oracle'] = {'stem': oracle_stem, 'folder': oracle_stem, 'longest_path': 40, 'files': oracle_files}
    with open(os.path.join(session_dir, 'session.json'), 'w', encoding='utf-8') as f:
        json.dump(doc, f, ensure_ascii=False, indent=1)
    return session_dir


def _write_session(root, short, folder, doc):
    session_dir = os.path.join(root, short, folder)
    os.makedirs(session_dir, exist_ok=True)
    with open(os.path.join(session_dir, 'session.json'), 'w', encoding='utf-8') as f:
        json.dump(doc, f)
    return session_dir


def _edit_doc(session_dir, fn):
    """Load session_dir's session.json, apply fn(doc) in place, and write it back (fixture only)."""
    doc_path = os.path.join(session_dir, 'session.json')
    with open(doc_path, encoding='utf-8') as f:
        doc = json.load(f)
    fn(doc)
    with open(doc_path, 'w', encoding='utf-8') as f:
        json.dump(doc, f, ensure_ascii=False, indent=1)


def _rewrite_gobjects(session_dir, row_fn):
    """Rewrite GObjects-Dump.txt via row_fn(index, address, name) -> new row, refreshing its
    recorded size/sha256 in session.json (fixture only)."""
    with open(os.path.join(session_dir, 'session.json'), encoding='utf-8') as f:
        folder = json.load(f)['oracle']['folder']
    path = os.path.join(session_dir, 'oracle', folder, 'GObjects-Dump.txt')
    dump = parse_gobjects_dump(pathlib.Path(path))
    raw = _gobjects_bytes(dump.line1, dump.stem, [row_fn(i, a, n) for i, a, n in dump.rows])
    pathlib.Path(path).write_bytes(raw)
    _edit_doc(session_dir, lambda d: d['oracle']['files'].__setitem__(
        'GObjects-Dump.txt', {'size': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}))


def _corrupt_sampled_vtables(session_dir, fraction):
    """Overwrite `fraction` of the vtables same_instance would sample, in place in capture.zip
    (fixture only; pins check_session's same-instance drift threshold)."""
    with open(os.path.join(session_dir, 'session.json'), encoding='utf-8') as f:
        doc = json.load(f)
    obj_base = int(doc['target']['module_base'], 16) + int(doc['target']['size_of_image'], 16)
    dump = parse_gobjects_dump(pathlib.Path(session_dir, 'oracle', doc['oracle']['folder'], 'GObjects-Dump.txt'))
    step = max(1, len(dump.rows) // 1000)
    sampled = dump.rows[::step]

    path = os.path.join(session_dir, 'capture.zip')
    with ImageSource.load(path) as img:
        mods = img.modules()
        regions = [(r.base, r.size) for r in img.regions()]
        segs = [(b, bytearray(img.read(b, n))) for b, n in regions]
    seg_base, seg = next(s for s in segs if s[0] <= obj_base < s[0] + len(s[1]))
    for _index, address, _name in sampled[:int(len(sampled) * fraction)]:
        off = address - seg_base
        seg[off:off + 8] = (0xDEAD0000).to_bytes(8, 'little')
    os.remove(path)
    write_capture(path, ImageSource([(b, bytes(x)) for b, x in segs], modules=mods), regions, modules=mods)


def _load_session(session_dir) -> Session:
    """Build a Session straight from session.json on disk, bypassing validate_session (check_session
    does not need a schema-validated document -- it checks the capture and oracle, not the JSON)."""
    with open(os.path.join(session_dir, 'session.json'), encoding='utf-8') as f:
        doc = json.load(f)
    return Session(dir=session_dir, data=doc, target=doc['target']['short'], state=doc['state'],
                    session_id=doc['session_id'])


# Always-on tests
class SessionSchemaTests(unittest.TestCase):
    def test_validate_and_discover(self):
        doc = _make_valid_doc()
        with tempfile.TemporaryDirectory() as root:
            session_dir = _write_session(root, 'pal', '260101-000000', doc)
            with mock.patch.dict(os.environ, {_CAPTURES_VAR: root}):
                sessions = iter_sessions()
            self.assertEqual(len(sessions), 1)
            s = sessions[0]
            self.assertEqual(s.dir, session_dir)
            self.assertEqual(s.target, 'pal')
            self.assertEqual(s.state, 'idle')
            self.assertEqual(s.session_id, 'SYN-1')
            self.assertEqual(s.data, doc)

        # an incomplete session missing most keys is discovered but skipped (not counted, not a failure)
        with tempfile.TemporaryDirectory() as root:
            _write_session(root, 'pal', '260101-000000', doc)
            incomplete = {'schema': dict(doc['schema']), 'session_id': 'SYN-2', 'status': 'incomplete', 'reason': 'in progress'}
            _write_session(root, 'pal', '260101-000001', incomplete)
            with mock.patch.dict(os.environ, {_CAPTURES_VAR: root}):
                sessions = iter_sessions()
            self.assertEqual([s.session_id for s in sessions], ['SYN-1'])

        # _dumper7/ (a top-level entry starting with _) is never visited, even with a garbage session.json
        with tempfile.TemporaryDirectory() as root:
            _write_session(root, 'pal', '260101-000000', doc)
            dumper7_dir = os.path.join(root, '_dumper7', 'x')
            os.makedirs(dumper7_dir, exist_ok=True)
            with open(os.path.join(dumper7_dir, 'session.json'), 'w', encoding='utf-8') as f:
                f.write('not json at all')
            with mock.patch.dict(os.environ, {_CAPTURES_VAR: root}):
                sessions = iter_sessions()
            self.assertEqual([s.session_id for s in sessions], ['SYN-1'])

        # a session.json that is not JSON fails discovery, naming the file
        with tempfile.TemporaryDirectory() as root:
            session_dir = _write_session(root, 'pal', '260101-000000', doc)
            with open(os.path.join(session_dir, 'session.json'), 'w', encoding='utf-8') as f:
                f.write('{not valid json')
            with mock.patch.dict(os.environ, {_CAPTURES_VAR: root}):
                with self.assertRaises(ValueError) as cm:
                    iter_sessions()
            self.assertIn('session.json', str(cm.exception))

        # one single-key corruption per row of the session.json validation table (index.md)
        def two_shipping(d): d['processes'].append(dict(d['processes'][0]))
        def module_base_null(d): d['target']['module_base'] = None
        def files_backslash(d): d['oracle']['files']['bad\\path'] = {'size': 1, 'sha256': '0' * 64}
        def extra_idmap(d): d['oracle']['files']['IDAMappings/Extra.idmap'] = {'size': 1, 'sha256': '2' * 64}
        def dumper7_unchanged_false(d): d['dumper7_folders']['D:\\Dumper-7']['unchanged'] = False
        def short_mismatch(d): d['target']['short'] = 'ts'

        cases = {
            'reason non-null': lambda d: d.__setitem__('reason', 'oops'),
            'session_id empty': lambda d: d.__setitem__('session_id', ''),
            'harness_version not str': lambda d: d.__setitem__('harness_version', 1),
            'state invalid': lambda d: d.__setitem__('state', 'bogus'),
            'target.short mismatch': short_mismatch,
            'target.name not str': lambda d: d['target'].__setitem__('name', 1),
            'target.appid not int': lambda d: d['target'].__setitem__('appid', '1'),
            'target.appid bool rejected': lambda d: d['target'].__setitem__('appid', True),
            'target.appid not the known Steam appid': lambda d: d['target'].__setitem__('appid', 1),
            'target.buildid not digits': lambda d: d['target'].__setitem__('buildid', '1a'),
            'target.install_dir relative': lambda d: d['target'].__setitem__('install_dir', 'relative\\path'),
            'target.shipping_exe outside install_dir': lambda d: d['target'].__setitem__('shipping_exe', 'D:\\Other\\x.exe'),
            'target.pe_timestamp no 0x': lambda d: d['target'].__setitem__('pe_timestamp', '12345678'),
            'target.module_base null': module_base_null,
            'launch missing key': lambda d: d['launch'].pop('steam_exe'),
            'processes two shipping': two_shipping,
            'capture.verified false': lambda d: d['capture'].__setitem__('verified', False),
            'oracle.files missing required': lambda d: d['oracle']['files'].pop('GObjects-Dump.txt'),
            'oracle.files backslash key': files_backslash,
            'oracle.files second idmap': extra_idmap,
            'dumper7_folders unchanged false': dumper7_unchanged_false,
            'kill wrong type': lambda d: d.__setitem__('kill', 'nope'),
        }
        for label, mutate in cases.items():
            with self.subTest(case=label):
                with tempfile.TemporaryDirectory() as root:
                    bad = copy.deepcopy(doc)
                    mutate(bad)
                    _write_session(root, 'pal', '260101-000000', bad)
                    with mock.patch.dict(os.environ, {_CAPTURES_VAR: root}):
                        with self.assertRaises(ValueError) as cm:
                            iter_sessions()
                    self.assertIn('session.json', str(cm.exception))

    def test_validate_session_requires_complete(self):
        # a direct call (bypassing iter_sessions's own incomplete-skip) requires status == 'complete'
        doc = _make_valid_doc()
        doc['status'] = 'incomplete'
        with self.assertRaises(ValueError):
            validate_session(doc, short='pal')

    def test_env_path(self):
        with self.assertRaises(TypeError):
            env_path(123)
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop('NYLIB_UE_TEST_VAR', None)
            self.assertIsNone(env_path('NYLIB_UE_TEST_VAR'))
            os.environ['NYLIB_UE_TEST_VAR'] = ''
            self.assertIsNone(env_path('NYLIB_UE_TEST_VAR'))
            with tempfile.TemporaryDirectory() as tmp:
                os.environ['NYLIB_UE_TEST_VAR'] = tmp
                self.assertEqual(env_path('NYLIB_UE_TEST_VAR'), tmp)
                os.environ['NYLIB_UE_TEST_VAR'] = os.path.join(tmp, 'does-not-exist')
                with self.assertRaises(FileNotFoundError):
                    env_path('NYLIB_UE_TEST_VAR')

    def test_required_targets(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop(_REQUIRED_TARGETS_VAR, None)
            self.assertEqual(required_targets(), ())
            os.environ[_REQUIRED_TARGETS_VAR] = 'pal, ts'
            self.assertEqual(required_targets(), ('pal', 'ts'))
            for bad in ('', 'pal,', 'pal,xx', 'pal,pal'):
                os.environ[_REQUIRED_TARGETS_VAR] = bad
                with self.assertRaises(ValueError):
                    required_targets()


class SameInstanceTests(unittest.TestCase):
    def test_synthetic(self):
        main_base, main_size = 0x140000000, 0x2000
        obj_base, stride, count = main_base + 0x100000, 0x20, 2000
        module_data = bytes(main_size)
        objects = bytearray(stride * count)
        for i in range(count):
            objects[i * stride:i * stride + 8] = main_base.to_bytes(8, 'little')
        modules = [Module('Game-Win64-Shipping.exe', main_base, main_size)]
        image = ImageSource([(main_base, module_data), (obj_base, bytes(objects))], modules=modules)
        rows = [(i, obj_base + i * stride, f'Class Pkg.Obj_{i}') for i in range(count)]
        dump = GObjectsDump(line1='x', stem='', count=count, rows=rows, props={})

        sampled, hits = same_instance(image, dump)
        expected_step = max(1, len(rows) // 1000)
        self.assertEqual(sampled, len(rows[::expected_step]))  # honors sample, not every row
        self.assertGreaterEqual(sampled, 1000)
        self.assertEqual(hits, sampled)

        # a foreign oracle: shifting every dump address by an amount that is NOT a multiple of the
        # object stride lands mid-object (the zero-filled body, not a vtable), so every sample misses
        shifted_dump = GObjectsDump(line1='x', stem='', count=count, rows=[(i, a + 8, n) for i, a, n in rows], props={})
        _, shifted_hits = same_instance(image, shifted_dump)
        self.assertEqual(shifted_hits, 0)

        # known limitation, pinned: a stride-aligned shift lands exactly on the next object's vtable
        # slot, so it still hits -- same_instance cannot tell this apart from a same-instance oracle
        aligned_dump = GObjectsDump(line1='x', stem='', count=count, rows=[(i, a + stride, n) for i, a, n in rows], props={})
        aligned_sampled, aligned_hits = same_instance(image, aligned_dump)
        self.assertEqual(aligned_hits, aligned_sampled)

        # the upper bound is exclusive: a vtable pointing exactly at main.end is not a hit
        boundary_objects = bytearray(8)
        boundary_objects[:8] = (main_base + main_size).to_bytes(8, 'little')
        boundary_base = obj_base + len(objects) + 0x2000
        boundary_image = ImageSource(
            [(main_base, module_data), (obj_base, bytes(objects)), (boundary_base, bytes(boundary_objects))],
            modules=modules)
        boundary_dump = GObjectsDump(line1='x', stem='', count=1, rows=[(0, boundary_base, 'Boundary')], props={})
        _, boundary_hits = same_instance(boundary_image, boundary_dump, sample=1)
        self.assertEqual(boundary_hits, 0)


class GateTests(unittest.TestCase):
    """Always-on: exercises real.check_session directly over a synthetic session (no env needed)."""

    def test_check_session(self):
        with tempfile.TemporaryDirectory() as root:
            check_session(_load_session(build_synthetic_session(root)))  # the happy path must pass

        def foreign_oracle(session_dir):
            _rewrite_gobjects(session_dir, lambda i, a, n: (i, a + 0x10000000, n))

        def sha256_mismatch(session_dir):
            # same length as the fixture's placeholder bytes, so only the hash (not the size) differs
            with open(os.path.join(session_dir, 'session.json'), encoding='utf-8') as f:
                folder = json.load(f)['oracle']['folder']
            pathlib.Path(session_dir, 'oracle', folder, 'CppSDK', 'SDK', 'Basic.hpp').write_bytes(b'x' * 11 + b'\n')

        def pe_timestamp_mismatch(session_dir):
            _edit_doc(session_dir, lambda d: d['target'].__setitem__('pe_timestamp', '0x00000001'))

        def stem_mismatch(session_dir):
            _edit_doc(session_dir, lambda d: d['oracle'].__setitem__('stem', 'Other-Stem'))

        def module_name_mismatch(session_dir):
            _edit_doc(session_dir, lambda d: d['target'].__setitem__(
                'shipping_exe', 'D:\\Synth\\Game\\Binaries\\Win64\\Other.exe'))

        def module_base_mismatch(session_dir):
            _edit_doc(session_dir, lambda d: d['target'].__setitem__('module_base', '0x7FF600010000'))

        # (mutation, build_synthetic_session kwargs) per negative variant; each must make check_session raise
        variants = {
            'foreign oracle': (foreign_oracle, {}),
            'sha256 mismatch': (sha256_mismatch, {}),
            'PE timestamp mismatch': (pe_timestamp_mismatch, {}),
            # 5000 keeps same_instance's own >= 1000 sampled floor satisfied, isolating the row-count check
            'fewer than 10k rows': (lambda session_dir: None, {'object_count': 5000}),
            'stem mismatch': (stem_mismatch, {}),
            'module name mismatch': (module_name_mismatch, {}),
            'module_base mismatch': (module_base_mismatch, {}),
            'same-instance drift below the 0.99 threshold': (lambda session_dir: _corrupt_sampled_vtables(session_dir, 0.05), {}),
        }
        for label, (mutate, build_kwargs) in variants.items():
            with self.subTest(variant=label):
                with tempfile.TemporaryDirectory() as root:
                    session_dir = build_synthetic_session(root, **build_kwargs)
                    mutate(session_dir)
                    with self.assertRaises(AssertionError):
                        check_session(_load_session(session_dir))


# Env-gated tests
class RealCapturesTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if captures_root() is None:
            raise unittest.SkipTest(f'{_CAPTURES_VAR} not set')
        cls.sessions = iter_sessions()
        for s in cls.sessions:
            print(f'discovered session {s.session_id} (target={s.target}, folder={os.path.basename(s.dir)})')

    def test_sessions(self):
        for session in self.sessions:
            with self.subTest(session_id=session.session_id, folder=os.path.basename(session.dir)):
                check_session(session)


class RequiredTargetsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        has_captures = bool(os.environ.get(_CAPTURES_VAR))
        has_required = _REQUIRED_TARGETS_VAR in os.environ
        if not has_captures and not has_required:
            raise unittest.SkipTest(f'neither {_CAPTURES_VAR} nor {_REQUIRED_TARGETS_VAR} is set')

    def test_required_targets_present(self):
        sessions = iter_sessions()
        discovered = sorted({(s.target, s.session_id, os.path.basename(s.dir)) for s in sessions})
        for target, session_id, folder in discovered:
            print(f'discovered: target={target} session_id={session_id} folder={folder}')
        for target in required_targets():
            with self.subTest(target=target):
                self.assertTrue(any(s.target == target for s in sessions), f'no complete session found for target {target!r}')


if __name__ == '__main__':
    unittest.main()
