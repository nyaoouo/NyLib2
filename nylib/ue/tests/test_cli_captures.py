"""7-G gate: the CLI's probe/dump path against each capture session's Dumper-7 oracle (I3 Verification).

Skips (setUpClass) when NYLIB_UE_CAPTURES is unset. A target named by NYLIB_UE_REQUIRED_TARGETS
with no complete session fails test_required_targets_present; it never skips.
"""
import contextlib
import io
import json
import os
import pathlib
import tempfile
import unittest

from .. import cli, exports as exports_mod, snapshot as snapshot_mod
from . import real
from .oracle import compare_idmap, parse_gobjects_dump, parse_idmap
from .port import compare_gobjects_capture

_CAPTURES_VAR = 'NYLIB_UE_CAPTURES'


def _run_cli(argv, *, _open_target=None) -> tuple[int, str, str]:
    out_buf, err_buf = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out_buf), contextlib.redirect_stderr(err_buf):
        code = cli.main(argv, _open_target=_open_target)
    return code, out_buf.getvalue(), err_buf.getvalue()


def _one_json_doc(stdout_text: str) -> dict:
    lines = [line for line in stdout_text.splitlines() if line]
    if len(lines) != 1:
        raise AssertionError(f'expected exactly one JSON line on stdout, got {lines!r}')
    return json.loads(lines[0])


def _values_by_name(doc: dict) -> dict:
    return {v['name']: v for v in doc['values']}


def _oracle_dir(session: real.Session) -> pathlib.Path:
    return pathlib.Path(session.dir) / 'oracle' / session.data['oracle']['folder']


class CaptureCliTests(unittest.TestCase):
    """7-G items 1 and 4: probe/dump against each complete session's Dumper-7 oracle."""

    @classmethod
    def setUpClass(cls):
        if real.captures_root() is None:
            raise unittest.SkipTest(f'{_CAPTURES_VAR} not set')
        cls.sessions = real.iter_sessions()

    def test_required_targets_present(self):
        for target in real.required_targets():
            with self.subTest(target=target):
                self.assertTrue(any(s.target == target for s in self.sessions),
                                f'no complete session found for required target {target!r}')

    def test_sessions(self):
        for session in self.sessions:
            with self.subTest(target=session.target, dir=os.path.basename(session.dir)):
                self._check_session(session)

    def _check_session(self, session: real.Session):
        real.check_session(session)
        factory = real.capture_target(session)
        exe = os.path.basename(session.data['target']['shipping_exe'])

        with tempfile.TemporaryDirectory(prefix='nylib-ue-7G-') as out1, \
             tempfile.TemporaryDirectory(prefix='nylib-ue-7G-') as out2:
            code, stdout, _ = _run_cli(['probe', exe, '--json', '--write-profile', '--out', out1], _open_target=factory)
            self.assertEqual(code, 0, stdout)
            doc2 = _one_json_doc(stdout)
            self.assertTrue(doc2['ok'])
            self.assertIsNotNone(doc2['profile_written'])
            self.assertTrue(os.path.isfile(doc2['profile_written']))

            code, stdout, _ = _run_cli(['probe', exe, '--json', '--out', out1], _open_target=factory)
            self.assertEqual(code, 0, stdout)
            doc3 = _one_json_doc(stdout)
            self.assertTrue(doc3['ok'])
            v2, v3 = _values_by_name(doc2), _values_by_name(doc3)
            for name in ('GObjects', 'GNames'):
                self.assertEqual(v3[name]['how'], 'profile: rva')
                self.assertEqual(v3[name]['value'], v2[name]['value'])

            code, stdout, _ = _run_cli(['dump', exe, '--json', '--out', out2], _open_target=factory)
            self.assertEqual(code, 0, stdout)
            doc4 = _one_json_doc(stdout)
            self.assertTrue(doc4['ok'])
            self.assertEqual(doc4['unverified'], doc2['unverified'])
            snapshot_path = doc4['snapshot']

            od = _oracle_dir(session)
            with snapshot_mod.Snapshot.load(snapshot_path) as snap:
                meta = dict(snap.meta)
                u_dump = parse_gobjects_dump(pathlib.Path(snapshot_path, exports_mod.export_path('gobjects', snap)))
                u_props = parse_gobjects_dump(
                    pathlib.Path(snapshot_path, exports_mod.export_path('gobjects-props', snap)), with_properties=True)
                idmap_path = pathlib.Path(snapshot_path, exports_mod.export_path('idmap', snap))

            o_dump = parse_gobjects_dump(od / 'GObjects-Dump.txt')
            o_props = parse_gobjects_dump(od / 'GObjects-Dump-WithProperties.txt', with_properties=True)
            dr = compare_gobjects_capture(u_dump, o_dump, target=session.target, check='gobjects')
            self.assertTrue(dr.ok, f'{dr.reason}; {dr.samples}')
            dr_props = compare_gobjects_capture(u_props, o_props, target=session.target, check='gobjects-props')
            self.assertTrue(dr_props.ok, f'{dr_props.reason}; {dr_props.samples}')

            idmap_files = [rel for rel in session.data['oracle']['files']
                          if rel.startswith('IDAMappings/') and rel.endswith('.idmap')]
            o_idmap = parse_idmap(od.joinpath(*idmap_files[0].split('/')))
            u_idmap = parse_idmap(idmap_path)
            dr_idmap = compare_idmap(u_idmap, o_idmap)
            self.assertTrue(dr_idmap.ok, f'{dr_idmap.reason}; {dr_idmap.samples}')

            target_meta = meta.get('target', {}) if isinstance(meta.get('target'), dict) else {}
            game_name_from = target_meta.get('game_name_from', '')
            engine_version_from = target_meta.get('engine_version_from', '')
            if game_name_from.startswith('auto:') and engine_version_from.startswith('auto:'):
                self.assertEqual(u_dump.stem, session.data['oracle']['stem'])
            else:
                print(f'[{session.target}] stem check skipped: fallback used '
                      f'(game_name_from={game_name_from!r}, engine_version_from={engine_version_from!r})')

            code, stdout, _ = _run_cli(['info', snapshot_path, '--json'])
            self.assertEqual(code, 0, stdout)
            self.assertTrue(_one_json_doc(stdout)['ok'])

            export_out = os.path.join(out2, 'x.idmap')
            code, stdout, _ = _run_cli(['export', snapshot_path, '--format', 'idmap', '--out', export_out])
            self.assertEqual(code, 0, stdout)
            with open(export_out, 'rb') as f:
                exported_bytes = f.read()
            with open(idmap_path, 'rb') as f:
                snap_idmap_bytes = f.read()
            self.assertEqual(exported_bytes, snap_idmap_bytes)


if __name__ == '__main__':
    unittest.main()
