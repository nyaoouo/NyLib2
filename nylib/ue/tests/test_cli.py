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

from nylib.ue import cli, errors, pipeline, store


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

        self.assertEqual(logging.getLogger('nylib.ue').handlers, [])


if __name__ == '__main__':
    unittest.main()
