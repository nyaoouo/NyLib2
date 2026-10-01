"""7-G gate: the CLI's probe/dump path against each capture session's Dumper-7 oracle (I3 Verification).

Skips (setUpClass) when NYLIB_UE_CAPTURES is unset. A target named by NYLIB_UE_REQUIRED_TARGETS
with no complete session fails test_required_targets_present; it never skips.
"""
import contextlib
import hashlib
import io
import json
import os
import pathlib
import shutil
import tempfile
import time
import unittest

from .. import cli, exports as exports_mod, image as image_mod, snapshot as snapshot_mod
from . import pe_file, real
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


def _rmtree_with_retry(path: str) -> None:
    """(7-c) shutil.rmtree, retrying a PermissionError the way store.publish retries its rename
    (an antivirus scanner may still hold the freshly written PE image)."""
    delay = 0.1
    for attempt in range(11):
        try:
            shutil.rmtree(path)
            return
        except PermissionError:
            if attempt == 10:
                raise
            time.sleep(delay)
            delay = min(delay * 2, 1.6)


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

        out1, out2 = tempfile.mkdtemp(prefix='nylib-ue-7G-'), tempfile.mkdtemp(prefix='nylib-ue-7G-')
        try:
            self._check_session_in(session, factory, exe, out1, out2)
        finally:
            _rmtree_with_retry(out1)
            _rmtree_with_retry(out2)

    def _check_session_in(self, session: real.Session, factory, exe: str, out1: str, out2: str):
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
        self.assertTrue(doc4['exports'] and doc4['exports'][-1] == 'image')  # (7-c)
        snapshot_path = doc4['snapshot']

        od = _oracle_dir(session)
        with snapshot_mod.Snapshot.load(snapshot_path) as snap:
            meta = dict(snap.meta)
            u_dump = parse_gobjects_dump(pathlib.Path(snapshot_path, exports_mod.export_path('gobjects', snap)))
            u_props = parse_gobjects_dump(
                pathlib.Path(snapshot_path, exports_mod.export_path('gobjects-props', snap)), with_properties=True)
            idmap_path = pathlib.Path(snapshot_path, exports_mod.export_path('idmap', snap))

        image_file = self._check_image(session, meta, snapshot_path, factory)  # (7-c)

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

        code, stdout, _ = _run_cli(['info', snapshot_path, '--json', '--log-file', os.path.join(out2, 'info.log')])
        self.assertEqual(code, 0, stdout)
        info_doc = _one_json_doc(stdout)
        self.assertTrue(info_doc['ok'])
        if image_file is not None:  # (7-c)
            self.assertIn(image_file, info_doc['exports'])

        export_out = os.path.join(out2, 'x.idmap')
        code, stdout, _ = _run_cli(['export', snapshot_path, '--format', 'idmap', '--out', export_out,
                                    '--log-file', os.path.join(out2, 'export.log')])
        self.assertEqual(code, 0, stdout)
        with open(export_out, 'rb') as f:
            exported_bytes = f.read()
        with open(idmap_path, 'rb') as f:
            snap_idmap_bytes = f.read()
        self.assertEqual(exported_bytes, snap_idmap_bytes)

    def _check_image(self, session: real.Session, meta: dict, snapshot_path: str, factory) -> str | None:
        """(7-c) the image checks: the written PE round-trips against the capture it came from."""
        img_meta = meta.get('image')
        self.assertIsInstance(img_meta, dict)
        self.assertIsNone(img_meta.get('skipped'))
        self.assertEqual(img_meta.get('unreadable_pages'), 0)
        image_file = img_meta.get('file')
        self.assertIsInstance(image_file, str)
        image_path = os.path.join(snapshot_path, *image_file.split('/'))
        self.assertTrue(os.path.isfile(image_path))
        with open(image_path, 'rb') as f:
            data = f.read()
        self.assertEqual(len(data), int(img_meta['size'], 16))
        self.assertEqual(hashlib.sha256(data).hexdigest(), img_meta['sha256'])

        target_meta = meta.get('target') if isinstance(meta.get('target'), dict) else {}
        module_meta = target_meta.get('module') if isinstance(target_meta.get('module'), dict) else {}
        image_base = int(img_meta['image_base'], 16)
        self.assertEqual(image_base, int(module_meta['base'], 16))

        opened = factory(None, write=False, remote_calls=False, cache_bytes=None)
        try:
            written = pe_file.map_pe_file(image_path)
            self.assertEqual(written.main_module.base, image_base)

            probe = opened.source.read(image_base, 0x400)
            e_lfanew = int.from_bytes(probe[0x3C:0x40], 'little')
            opt = e_lfanew + 24
            if opt + 0x40 > len(probe):
                probe = opened.source.read(image_base, opt + 0x400)
            size_of_headers = int.from_bytes(probe[opt + 0x3C:opt + 0x40], 'little')
            num_sections = int.from_bytes(probe[e_lfanew + 6:e_lfanew + 8], 'little')
            size_opt = int.from_bytes(probe[e_lfanew + 0x14:e_lfanew + 0x16], 'little')
            sections_offset = opt + size_opt
            if size_of_headers > len(probe):
                probe = opened.source.read(image_base, size_of_headers)
            src_head = bytearray(probe[:size_of_headers])
            dst_head = bytearray(written.read(image_base, size_of_headers))

            sections = []
            for i in range(num_sections):
                sh = sections_offset + i * 40
                virt_size = int.from_bytes(src_head[sh + 8:sh + 12], 'little')
                virt_addr = int.from_bytes(src_head[sh + 12:sh + 16], 'little')
                sections.append((virt_addr, virt_size))
            for virt_addr, virt_size in sections:
                if virt_size <= 0:
                    continue
                for off in range(0, virt_size, image_mod.READ_STEP):
                    n = min(image_mod.READ_STEP, virt_size - off)
                    a = opened.source.read(image_base + virt_addr + off, n)
                    b = written.read(image_base + virt_addr + off, n)
                    self.assertEqual(a, b, f'section at rva {virt_addr:#x} mismatch')

            self.assertEqual(dst_head[opt + 0x90:opt + 0x98], bytes(8))  # DataDirectory[4] is zero
            for buf in (src_head, dst_head):
                for i in range(num_sections):
                    sh = sections_offset + i * 40
                    buf[sh + 16:sh + 24] = bytes(8)  # SizeOfRawData, PointerToRawData: allowed to differ
                buf[opt + 0x18:opt + 0x20] = bytes(8)  # ImageBase: allowed to differ
                buf[opt + 0x90:opt + 0x98] = bytes(8)  # DataDirectory[4]: allowed to differ
            self.assertEqual(src_head, dst_head)
        finally:
            opened.close()

        if target_meta.get('exe_sha256') is not None:
            self.assertEqual(img_meta.get('original_image_base'), '0x140000000')
        else:
            self.assertIsNone(img_meta.get('original_image_base'))
        return image_file


if __name__ == '__main__':
    unittest.main()
