"""Guards for pipeline.py and the CLI integration (I3): G7.3 (output-root-before-target) and
G7.4 (a --json error is one clean document, with nothing from logging leaking onto stdout)."""
import contextlib
import io
import json
import logging
import os
import tempfile
import unittest
import unittest.mock

from nylib.ue import cli, errors, image, pipeline, profiles, store


def _internal_report() -> pipeline.ProbeReport:
    """A hand-built ProbeReport whose target is internal mode; only `target.mode` matters here."""
    target = pipeline.TargetInfo(mode='internal', pid=1, exe='x.exe', exe_path='', exe_sha256=None, module_base=0,
                                 size_of_image=0, pe_timestamp=0, file_version=None, version_info=None)
    return pipeline.ProbeReport(ok=True, target=target, profile=None, profile_note='none', values=(), unverified=(),
                                steps=(), error=None, explanations=(), game_name='', game_name_from='',
                                engine_version='', engine_version_from='', stem='', warnings=(), seconds=0.0,
                                context=None)


class OutputRootGuardTests(unittest.TestCase):
    """G7.3: with NYLIB_UE_OUT unset and the cwd a fresh temp folder, dump(target=None) and
    write_profile(<an internal report>) raise OutputRootError before touching the folder."""

    def test_dump_raises_before_any_target_access(self):
        with tempfile.TemporaryDirectory() as d:
            old_cwd = os.getcwd()
            os.chdir(d)
            try:
                with unittest.mock.patch.dict(os.environ, {store.OUT_ENV: ''}):
                    with self.assertRaises(errors.OutputRootError):
                        pipeline.dump(target=None)
                self.assertEqual(os.listdir(d), [])
            finally:
                os.chdir(old_cwd)

    def test_write_profile_raises_before_any_target_access(self):
        with tempfile.TemporaryDirectory() as d:
            old_cwd = os.getcwd()
            os.chdir(d)
            try:
                with unittest.mock.patch.dict(os.environ, {store.OUT_ENV: ''}):
                    with self.assertRaises(errors.OutputRootError):
                        pipeline.write_profile(_internal_report())
                self.assertEqual(os.listdir(d), [])
            finally:
                os.chdir(old_cwd)


class JsonErrorIsolationTests(unittest.TestCase):
    """G7.4: a --json dump error is exactly one JSON line on stdout; a logging marker never
    leaks onto stdout, and does reach stderr (-v) and the log file."""

    def test_json_dump_error_is_one_line_and_logging_stays_off_stdout(self):
        marker = 'G7.4-MARKER-f3a9'

        def factory(target, *, write, remote_calls, cache_bytes):
            logging.getLogger('nylib.ue.tests').debug(marker)
            raise errors.TargetError(target, 'synthetic failure for G7.4')

        with tempfile.TemporaryDirectory() as d:
            out_buf, err_buf = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out_buf), contextlib.redirect_stderr(err_buf):
                code = cli.main(['dump', 'x', '--json', '-v', '--out', d], _open_target=factory)

            self.assertEqual(code, 4)
            stdout_text = out_buf.getvalue()
            lines = [line for line in stdout_text.splitlines() if line]
            self.assertEqual(len(lines), 1)
            doc = json.loads(lines[0])
            self.assertEqual(doc, {'ok': False, 'error': {'type': 'TargetError', 'message': 'cannot open target \'x\': synthetic failure for G7.4', 'exit': 4}})
            self.assertNotIn(marker, stdout_text)

            stderr_text = err_buf.getvalue()
            self.assertIn(marker, stderr_text)

            log_path = os.path.join(d, store.LOGS_DIR, 'dump.log')
            with open(log_path, encoding='utf-8') as f:
                log_text = f.read()
            self.assertIn(marker, log_text)
            self.assertEqual(log_text.count(marker), 1)  # I1: dump.log must not get two handlers

        self.assertEqual(logging.getLogger('nylib.ue').handlers, [])


def _probe_report(**overrides) -> pipeline.ProbeReport:
    info = pipeline.TargetInfo(mode='external', pid=1, exe='x.exe', exe_path='', exe_sha256=None,
                               module_base=0, size_of_image=0, pe_timestamp=0x1234, file_version=None,
                               version_info=None)
    kwargs = dict(ok=True, target=info, profile=None, profile_note='none', values=(), unverified=(),
                  steps=(), error=None, explanations=(), game_name='X', game_name_from='', engine_version='',
                  engine_version_from='', stem='', warnings=(), seconds=0.0, context=None)
    kwargs.update(overrides)
    return pipeline.ProbeReport(**kwargs)


class DumpProgressAndWarningsTests(unittest.TestCase):
    """C1: dump's stderr progress lines and warning: lines."""

    def test_dump_progress_and_warnings_on_stderr(self):
        info = pipeline.TargetInfo(mode='external', pid=1, exe='x.exe', exe_path='', exe_sha256=None,
                                   module_base=0, size_of_image=0, pe_timestamp=0, file_version=None,
                                   version_info=None)
        report = _probe_report(target=info)

        def fake_dump(target, *, profile=None, out=None, exports=(), cache_bytes=None, log_file=None,
                      progress=None, _open_target=None):
            if progress is not None:
                progress('open', info)
                progress('probe', report)
                progress('snapshot', {'classes': 1, 'structs': 2, 'enums': 3, 'functions': 4, 'packages': 5, 'objects': 6})
                progress('exports', ('idmap',))
            return pipeline.DumpResult(path=out or '.', target=info, report=report, counts={'objects': 6},
                                       unverified=(), exports=('idmap',), export_paths=(),
                                       warnings=('a pin was ignored',), seconds=0.2)

        with tempfile.TemporaryDirectory() as d:
            err_buf = io.StringIO()
            with contextlib.redirect_stderr(err_buf), contextlib.redirect_stdout(io.StringIO()), \
                 unittest.mock.patch('nylib.ue.pipeline.dump', side_effect=fake_dump):
                code = cli.main(['dump', 'x', '--out', d])
            self.assertEqual(code, 0)
            text = err_buf.getvalue()
            self.assertIn('[1/3]', text)
            self.assertIn('[2/3]', text)
            self.assertIn('[3/3]', text)
            self.assertIn('done in', text)
            self.assertIn('warning:', text)
            self.assertIn('a pin was ignored', text)


class DumpProgressTimingTests(unittest.TestCase):
    """The [2/3] seconds cover the whole walk, not the time since the last walk tick."""

    def test_walk_ticks_do_not_restart_the_step_clock(self):
        clock = iter([0.0, 1.0, 2.0, 9.0, 9.5, 12.0, 13.0])  # creation, open, probe, snapshot, exports (walk ticks read none)
        with unittest.mock.patch('nylib.ue.cli.time.perf_counter', side_effect=lambda: next(clock)):
            progress = cli._make_dump_progress('v')
        with unittest.mock.patch('nylib.ue.cli.time.perf_counter', side_effect=lambda: next(clock)), \
             self.assertLogs('nylib.ue.cli', level='INFO') as logs:
            info = pipeline.TargetInfo(mode='external', pid=1, exe='x.exe', exe_path='', exe_sha256=None,
                                       module_base=0, size_of_image=0, pe_timestamp=0, file_version=None,
                                       version_info=None)
            progress('open', info)
            progress('probe', _probe_report(target=info))
            for done in (4096, 8192):
                progress('walk', (done, 8192))
            progress('snapshot', {'classes': 1, 'structs': 2, 'enums': 3, 'functions': 4, 'packages': 5, 'objects': 6})
            progress('exports', ('idmap',))
        step2 = [m for m in logs.output if '[2/3]' in m]
        self.assertEqual(len(step2), 1)
        self.assertTrue(step2[0].endswith('(7.0s)'), step2[0])


class DumpProgressImageTimingTests(unittest.TestCase):
    """G7.6: the image step's seconds are excluded from [2/3] and folded into [3/3]; `image` prints nothing."""

    def test_image_seconds_move_from_snapshot_to_exports(self):
        clock = iter([0.0, 1.0, 2.0, 4.0, 9.0, 9.5])  # creation, open, probe, image, snapshot, exports
        with unittest.mock.patch('nylib.ue.cli.time.perf_counter', side_effect=lambda: next(clock)):
            progress = cli._make_dump_progress('v')
        with unittest.mock.patch('nylib.ue.cli.time.perf_counter', side_effect=lambda: next(clock)), \
             self.assertLogs('nylib.ue.cli', level='INFO') as logs:
            info = pipeline.TargetInfo(mode='external', pid=1, exe='x.exe', exe_path='', exe_sha256=None,
                                       module_base=0, size_of_image=0, pe_timestamp=0, file_version=None,
                                       version_info=None)
            progress('open', info)
            progress('probe', _probe_report(target=info))
            img = image.ImageResult(rel_path='image/x.exe', path='/d/image/x.exe', size=4, sha256='00' * 32,
                                    image_base=0x140000000, original_image_base=0x140000000, unreadable_pages=0,
                                    first_unreadable=None, skipped=None, seconds=0.0)
            progress('image', img)
            for done in (4096, 8192):
                progress('walk', (done, 8192))
            progress('snapshot', {'classes': 1, 'structs': 2, 'enums': 3, 'functions': 4, 'packages': 5, 'objects': 6})
            progress('exports', ('idmap', 'image'))
        self.assertEqual(len(logs.output), 5)  # profile + [1/3] + [2/3] + [3/3]; no line for 'image'
        step2 = [m for m in logs.output if '[2/3]' in m]
        step3 = [m for m in logs.output if '[3/3]' in m]
        self.assertEqual(len(step2), 1)
        self.assertEqual(len(step3), 1)
        self.assertTrue(step2[0].endswith('(5.0s)'), step2[0])
        self.assertTrue(step3[0].endswith('(2.5s)'), step3[0])
        self.assertIn('idmap,image', step3[0])


class DumpExportsDefaultTests(unittest.TestCase):
    """(7-c) without --exports, dump passes pipeline.DEFAULT_DUMP_EXPORTS; --exports now also takes image."""

    def test_default_exports_is_pipeline_default_dump_exports(self):
        captured = {}

        def fake_dump(target, *, profile=None, out=None, exports=(), cache_bytes=None, log_file=None,
                      progress=None, _open_target=None):
            captured['exports'] = exports
            info = pipeline.TargetInfo(mode='external', pid=1, exe='x.exe', exe_path='', exe_sha256=None,
                                       module_base=0, size_of_image=0, pe_timestamp=0, file_version=None,
                                       version_info=None)
            return pipeline.DumpResult(path=out or '.', target=info, report=_probe_report(target=info), counts={},
                                       unverified=(), exports=exports, export_paths=(), warnings=(), seconds=0.0)

        with tempfile.TemporaryDirectory() as d:
            with unittest.mock.patch('nylib.ue.pipeline.dump', side_effect=fake_dump), \
                 contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                code = cli.main(['dump', 'x', '--out', d])
            self.assertEqual(code, 0)
            self.assertEqual(captured['exports'], pipeline.DEFAULT_DUMP_EXPORTS)

    def test_exports_image_is_accepted(self):
        self.assertEqual(cli._parse_exports('image'), ('image',))

    def test_exports_bogus_with_image_is_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                code = cli.main(['dump', 'x', '--exports', 'image,bogus', '--out', d])
            self.assertEqual(code, 2)


class IgnoredRvaPinWarningTests(unittest.TestCase):
    """C1: a dropped rva pin logs at WARNING where it is appended, not only into the warnings tuple."""

    def test_ignored_rva_pin_logs_warning(self):
        info = pipeline.TargetInfo(mode='external', pid=1, exe='x.exe', exe_path='', exe_sha256=None,
                                   module_base=0, size_of_image=0x9000, pe_timestamp=0x5000, file_version=None,
                                   version_info=None)
        prof = profiles.Profile(path='x.toml', exe=None, pins={}, offsets={}, hooks={})
        pin = profiles.Pin('gnames', rva=0x100, build=0x1234, image_size=None)
        warnings = []
        with self.assertLogs('nylib.ue', level='WARNING') as cm:
            result = pipeline._rva_pin(prof, 'gnames', pin, info, warnings)
        self.assertIsNone(result)
        self.assertEqual(len(warnings), 1)
        self.assertTrue(any('ignored' in m for m in cm.output))


class JsonKeyboardInterruptTests(unittest.TestCase):
    """I2: Ctrl+C under --json still prints one document and is logged."""

    @staticmethod
    def _factory(target, *, write, remote_calls, cache_bytes):
        raise KeyboardInterrupt()

    def test_json_keyboard_interrupt_is_one_document(self):
        with tempfile.TemporaryDirectory() as d:
            for argv in (['dump', 'x', '--json', '--out', d], ['probe', 'x', '--json', '--out', d]):
                with self.subTest(argv=argv):
                    out_buf = io.StringIO()
                    with contextlib.redirect_stdout(out_buf):
                        code = cli.main(argv, _open_target=self._factory)
                    self.assertEqual(code, 130)
                    lines = [l for l in out_buf.getvalue().splitlines() if l]
                    self.assertEqual(len(lines), 1)
                    doc = json.loads(lines[0])
                    self.assertEqual(doc['error']['exit'], 130)
            log_path = os.path.join(d, store.LOGS_DIR, 'dump.log')
            with open(log_path, encoding='utf-8') as f:
                self.assertIn('KeyboardInterrupt', f.read())


class EmptyArgumentTests(unittest.TestCase):
    """M1: an empty target/--out/--log-file is a usage error (exit 2), not a runtime ValueError."""

    def test_empty_args_exit_2(self):
        cases = [
            ['list', '--out', ''],
            ['probe', '', '--out', 'd'],
            ['probe', 'x', '--out', 'd', '--log-file', ''],
        ]
        for argv in cases:
            with self.subTest(argv=argv):
                with contextlib.redirect_stderr(io.StringIO()), contextlib.redirect_stdout(io.StringIO()):
                    code = cli.main(argv)
                self.assertEqual(code, 2)


class JsonPrePipelineErrorTests(unittest.TestCase):
    """M2: a failure before the pipeline still prints the one JSON error document under --json."""

    def test_json_usmap_prints_error_document(self):
        with tempfile.TemporaryDirectory() as d:
            out_buf = io.StringIO()
            with contextlib.redirect_stdout(out_buf), contextlib.redirect_stderr(io.StringIO()):
                code = cli.main(['dump', 'x', '--json', '--exports', 'usmap', '--out', d])
            self.assertEqual(code, 1)
            doc = json.loads(out_buf.getvalue().strip())
            self.assertFalse(doc['ok'])
            self.assertEqual(doc['error']['exit'], 1)


class PinResolutionDeathTests(unittest.TestCase):
    """M3: an exception while resolving pins still goes through the alive check (exit 4, not 1)."""

    def test_probe_sig_pin_target_died_exits_4(self):
        def factory(target, *, write, remote_calls, cache_bytes):
            info = pipeline.TargetInfo(mode='external', pid=7, exe='x.exe', exe_path='', exe_sha256=None,
                                       module_base=0x400000, size_of_image=0x1000, pe_timestamp=0,
                                       file_version=None, version_info=None)
            return pipeline.OpenedTarget(source=None, info=info, process=None, check_alive=lambda: False,
                                         closer=lambda: None)

        with tempfile.TemporaryDirectory() as d:
            prof_path = os.path.join(d, 'p.toml')
            with open(prof_path, 'w', encoding='utf-8') as f:
                f.write('[match]\nexe = "x.exe"\n')
            with unittest.mock.patch('nylib.ue.pipeline._resolve_pins',
                                     side_effect=errors.MemoryReadError(0, 1, 'dead')):
                code = cli.main(['probe', 'x', '--profile', prof_path, '--out', d], _open_target=factory)
        self.assertEqual(code, 4)


class WriteProfileExistsStillPrintsReportTests(unittest.TestCase):
    """M7: --write-profile onto an existing profile still prints the probe report first."""

    def test_write_profile_exists_still_prints_report(self):
        report = _probe_report()
        err = FileExistsError('x.toml')
        err.profile_text = 'profile text here\n'

        with tempfile.TemporaryDirectory() as d:
            out_buf, err_buf = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out_buf), contextlib.redirect_stderr(err_buf), \
                 unittest.mock.patch('nylib.ue.pipeline.probe', return_value=report), \
                 unittest.mock.patch('nylib.ue.pipeline.write_profile', side_effect=err):
                code = cli.main(['probe', 'x', '--write-profile', '--out', d])
            self.assertEqual(code, 1)
            stdout_text = out_buf.getvalue()
            self.assertIn('values found', stdout_text)
            self.assertIn('profile text here', stdout_text)
            self.assertIn('error:', err_buf.getvalue())


class ListTextAmbiguousTests(unittest.TestCase):
    """M8: `list` text must show an ambiguous profile_status, not just '-'."""

    def test_list_text_shows_ambiguous(self):
        rows = [pipeline.TargetRow(pid=1, exe='x.exe', engine_hint=None, note='', profile=None,
                                   profile_status='ambiguous (2 profiles)')]
        out_buf = io.StringIO()
        with contextlib.redirect_stdout(out_buf), \
             unittest.mock.patch('nylib.ue.pipeline.list_targets', return_value=rows):
            code = cli.main(['list'])
        self.assertEqual(code, 0)
        self.assertIn('ambiguous (2 profiles)', out_buf.getvalue())


class WalkDeathTests(unittest.TestCase):
    """M13: the walk-time dead-target conversion (process exited during the walk, exit 4)."""

    def test_dump_target_exits_during_walk_exits_4(self):
        info = pipeline.TargetInfo(mode='external', pid=9, exe='x.exe', exe_path='', exe_sha256=None,
                                   module_base=0, size_of_image=0, pe_timestamp=0, file_version=None,
                                   version_info=None)

        class _FakeContext:
            def to_meta(self):
                return {'target': {}, 'engine': {}, 'globals': {}}

            def to_offsets(self):
                return {}

        report = _probe_report(target=info, steps=('objects', 'names', 'engine'), context=_FakeContext())

        def factory(target, *, write, remote_calls, cache_bytes):
            return pipeline.OpenedTarget(source=None, info=info, process=None, check_alive=lambda: False,
                                         closer=lambda: None)

        with tempfile.TemporaryDirectory() as d:
            with unittest.mock.patch('nylib.ue.pipeline.probe_opened', return_value=report), \
                 unittest.mock.patch('nylib.ue.reflect.walk', side_effect=errors.MemoryReadError(0, 0, 'dead')):
                # (7-c) --exports idmap: this test's source=None predates the image step, which it does not cover
                code = cli.main(['dump', 'x', '--exports', 'idmap', '--out', d], _open_target=factory)
            self.assertEqual(code, 4)
            partials = [p for base, dirs, _files in os.walk(d) for p in dirs if p.endswith('.partial')]
            self.assertTrue(partials)


if __name__ == '__main__':
    unittest.main()
