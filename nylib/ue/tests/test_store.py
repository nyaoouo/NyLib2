import datetime
import json
import os
import tempfile
import unittest
import unittest.mock

from nylib.ue import errors, snapshot
from nylib.ue import exports as exports_mod
from nylib.ue import store


def _meta(game_name='Pal', exe='Pal-Win64-Shipping.exe', pe_ts=0x1000, size=0x2000, created='2026-01-01T00:00:00+00:00'):
    return {
        'created': created, 'mode': 'external', 'remote_calls': [],
        'target': {'pid': 1, 'exe': exe, 'exe_path': '', 'exe_sha256': None,
                   'module': {'base': '0x140000000', 'size': f'{size:#X}'.replace('0X', '0x'),
                              'pe_timestamp': f'{pe_ts:#X}'.replace('0X', '0x')},
                   'file_version': None, 'game_name': game_name, 'game_name_from': 'x', 'game_version': None,
                   'engine_version': '5.3', 'engine_version_from': 'x', 'stem': f'5.3-{game_name}'},
        'engine': {}, 'globals': {},
    }


def _publish(root, game_name, when, **meta_kwargs):
    folder = store.new_snapshot_dir(root, game_name, when)
    snapshot.write_snapshot(folder, _meta(game_name=game_name, **meta_kwargs), {}, [], [], [])
    store.publish(folder, ())
    return folder


class ResolveOutRootTests(unittest.TestCase):
    def test_type_error_out(self):
        with self.assertRaises(TypeError):
            store.resolve_out_root(123)

    def test_value_error_empty(self):
        with self.assertRaises(ValueError):
            store.resolve_out_root('')

    def test_out_wins(self):
        with tempfile.TemporaryDirectory() as d:
            got = store.resolve_out_root(os.path.join(d, 'x'))
            self.assertEqual(got, os.path.abspath(os.path.join(d, 'x')))

    def test_env_var_used_when_out_is_none(self):
        with tempfile.TemporaryDirectory() as d:
            with unittest.mock.patch.dict(os.environ, {store.OUT_ENV: os.path.join(d, 'y')}):
                got = store.resolve_out_root()
                self.assertEqual(got, os.path.abspath(os.path.join(d, 'y')))

    def test_internal_without_out_or_env_raises(self):
        with unittest.mock.patch.dict(os.environ, {store.OUT_ENV: ''}):
            with self.assertRaises(errors.OutputRootError) as ctx:
                store.resolve_out_root(internal=True)
            self.assertEqual(ctx.exception.cwd, os.getcwd())

    def test_default_is_cwd_ue_dumps(self):
        with unittest.mock.patch.dict(os.environ, {store.OUT_ENV: ''}):
            got = store.resolve_out_root()
            self.assertEqual(got, os.path.abspath(os.path.join(os.getcwd(), store.DEFAULT_DIR)))

    def test_internal_mode_still_runs_with_out_given(self):
        with tempfile.TemporaryDirectory() as d:
            got = store.resolve_out_root(d, internal=True)
            self.assertEqual(got, os.path.abspath(d))


class SafeDirNameTests(unittest.TestCase):
    def test_type_error(self):
        with self.assertRaises(TypeError):
            store.safe_dir_name(123)

    def test_examples(self):
        cases = {'Pal': 'Pal', 'a:b': 'a_b', 'con': 'con_', 'COM1.txt': 'COM1_.txt', 'x.': 'x_', '': 'unknown'}
        for name, expect in cases.items():
            with self.subTest(name=name):
                self.assertEqual(store.safe_dir_name(name), expect)


class NewSnapshotDirTests(unittest.TestCase):
    def test_type_errors(self):
        now = datetime.datetime.now()
        with self.assertRaises(TypeError):
            store.new_snapshot_dir(123, 'Pal', now)
        with self.assertRaises(TypeError):
            store.new_snapshot_dir('x', 123, now)
        with self.assertRaises(TypeError):
            store.new_snapshot_dir('x', 'Pal', 'not-a-datetime')

    def test_creates_game_dir_and_reserves_partial(self):
        with tempfile.TemporaryDirectory() as d:
            when = datetime.datetime(2026, 1, 2, 3, 4, 5)
            folder = store.new_snapshot_dir(d, 'Pal', when)
            self.assertEqual(os.path.basename(os.path.dirname(folder)), 'Pal')
            self.assertTrue(os.path.isdir(folder + '.partial'))
            self.assertFalse(os.path.exists(folder))

    def test_collision_increments_stamp(self):
        with tempfile.TemporaryDirectory() as d:
            when = datetime.datetime(2026, 1, 2, 3, 4, 5)
            f1 = store.new_snapshot_dir(d, 'Pal', when)
            f2 = store.new_snapshot_dir(d, 'Pal', when)
            self.assertNotEqual(f1, f2)
            self.assertTrue(f2.endswith('-2'))

    def test_skips_name_whose_partial_exists(self):  # G7.2 part 3
        with tempfile.TemporaryDirectory() as d:
            when = datetime.datetime(2026, 1, 2, 3, 4, 5)
            stamp = when.strftime('%Y%m%d-%H%M%S')
            game_dir = os.path.join(d, store.safe_dir_name('Pal'))
            os.makedirs(game_dir)
            os.mkdir(os.path.join(game_dir, f'{stamp}.partial'))
            folder = store.new_snapshot_dir(d, 'Pal', when)
            self.assertEqual(os.path.basename(folder), f'{stamp}-2')


class PublishTests(unittest.TestCase):
    def test_type_errors(self):
        with self.assertRaises(TypeError):
            store.publish(123, ())
        with self.assertRaises(TypeError):
            store.publish('x', 'idmap')
        with self.assertRaises(TypeError):
            store.publish('x', (1,))

    def test_unknown_format_checked_before_loading(self):
        # No `.partial` folder exists at all; a load-first implementation would raise SnapshotError.
        with self.assertRaises(ValueError):
            store.publish(os.path.join(tempfile.gettempdir(), 'no-such-nylib-ue-folder'), ('bogus',))

    def test_happy_path_renames_and_returns_export_paths(self):
        with tempfile.TemporaryDirectory() as d:
            folder = store.new_snapshot_dir(d, 'Pal', datetime.datetime(2026, 1, 1))
            snapshot.write_snapshot(folder, _meta(), {}, [], [], [])
            paths = store.publish(folder, ('idmap',))
            self.assertTrue(os.path.isdir(folder))
            self.assertFalse(os.path.exists(folder + '.partial'))
            self.assertEqual(len(paths), 1)
            self.assertTrue(os.path.isfile(paths[0]))

    def test_exporter_failure_leaves_only_partial(self):  # G7.2 part 2
        with tempfile.TemporaryDirectory() as d:
            folder = store.new_snapshot_dir(d, 'Pal', datetime.datetime(2026, 1, 1))
            snapshot.write_snapshot(folder, _meta(), {}, [], [], [])

            def boom(_snap, _out_dir):
                raise RuntimeError('boom')

            bad_spec = exports_mod.ExportSpec('idmap', lambda s: 'IDAMappings/x.idmap', boom)
            with unittest.mock.patch.dict(exports_mod.EXPORT_SPECS, {'idmap': bad_spec}):
                with self.assertRaises(RuntimeError):
                    store.publish(folder, ('idmap',))
            self.assertFalse(os.path.exists(folder))
            self.assertTrue(os.path.isdir(folder + '.partial'))


class FindSnapshotsTests(unittest.TestCase):
    def test_missing_root_returns_empty(self):
        self.assertEqual(store.find_snapshots(os.path.join(tempfile.gettempdir(), 'no-such-nylib-ue-root')), [])

    def test_type_errors(self):
        with self.assertRaises(TypeError):
            store.find_snapshots('x', exe=123)
        with self.assertRaises(TypeError):
            store.find_snapshots('x', pe_timestamp='a')
        with self.assertRaises(TypeError):
            store.find_snapshots('x', pe_timestamp=True)  # bool is rejected, not treated as int
        with self.assertRaises(TypeError):
            store.find_snapshots('x', size_of_image=True)

    def test_excludes_partial_and_missing_meta_orders_newest_first(self):  # G7.2 part 1
        with tempfile.TemporaryDirectory() as d:
            f1 = _publish(d, 'Pal', datetime.datetime(2026, 1, 1), created='2026-01-01T00:00:00+00:00')
            f2 = _publish(d, 'Pal', datetime.datetime(2026, 1, 2), created='2026-01-02T00:00:00+00:00')
            # a stale .partial WITH a complete meta.json inside it: still excluded
            f3 = store.new_snapshot_dir(d, 'Pal', datetime.datetime(2026, 1, 3))
            snapshot.write_snapshot(f3, _meta(created='2026-01-03T00:00:00+00:00'), {}, [], [], [])
            # a folder with no meta.json at all
            os.makedirs(os.path.join(d, 'Pal', '20260104-000000'))

            refs = store.find_snapshots(d)
            self.assertEqual([r.path for r in refs], [os.path.abspath(f2), os.path.abspath(f1)])

    def test_filters_and_fields(self):
        with tempfile.TemporaryDirectory() as d:
            _publish(d, 'Pal', datetime.datetime(2026, 1, 1), exe='Pal-Win64-Shipping.exe', pe_ts=0x1000, size=0x2000)
            refs = store.find_snapshots(d, exe='pal-win64-shipping.exe')  # casefold match
            self.assertEqual(len(refs), 1)
            ref = refs[0]
            self.assertEqual(ref.exe, 'Pal-Win64-Shipping.exe')
            self.assertEqual(ref.pe_timestamp, 0x1000)
            self.assertEqual(ref.size_of_image, 0x2000)
            self.assertEqual(ref.game_name, 'Pal')
            self.assertEqual(ref.schema_version, snapshot.SCHEMA_VERSION)
            self.assertIsNotNone(ref.created)
            self.assertIsNotNone(ref.created.tzinfo)
            self.assertEqual(store.find_snapshots(d, exe='nope'), [])
            self.assertEqual(store.find_snapshots(d, pe_timestamp=0x9999), [])
            self.assertEqual(store.find_snapshots(d, size_of_image=0x9999), [])

    def test_naive_created_becomes_local_time(self):
        with tempfile.TemporaryDirectory() as d:
            _publish(d, 'Pal', datetime.datetime(2026, 1, 1), created='2026-01-01T12:00:00')
            ref = store.find_snapshots(d)[0]
            self.assertIsNotNone(ref.created.tzinfo)
            self.assertEqual(ref.created.replace(tzinfo=None), datetime.datetime(2026, 1, 1, 12, 0, 0))

    def test_skips_profiles_and_underscore_dirs(self):
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, 'profiles', '20260101-000000'))
            os.makedirs(os.path.join(d, '_logs'))
            self.assertEqual(store.find_snapshots(d), [])

    def test_skips_bad_and_mismatched_meta(self):
        with tempfile.TemporaryDirectory() as d:
            bad = os.path.join(d, 'Pal', '20260101-000000')
            os.makedirs(bad)
            with open(os.path.join(bad, 'meta.json'), 'wb') as f:
                f.write(b'\xff\xfe not json')
            other = os.path.join(d, 'Pal', '20260102-000000')
            os.makedirs(other)
            with open(os.path.join(other, 'meta.json'), 'w', encoding='utf-8') as f:
                json.dump({'schema': {'name': 'something.else', 'version': '1.0'}}, f)
            no_version = os.path.join(d, 'Pal', '20260103-000000')
            os.makedirs(no_version)
            with open(os.path.join(no_version, 'meta.json'), 'w', encoding='utf-8') as f:
                json.dump({'schema': {'name': snapshot.SCHEMA_NAME}}, f)
            self.assertEqual(store.find_snapshots(d), [])


if __name__ == '__main__':
    unittest.main()
