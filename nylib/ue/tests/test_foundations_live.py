"""Stage-1 integration: the separately built units composed over real memory (own process, a child, captures of it)."""
import json
import os
import subprocess
import sys
import tempfile
import unittest
import zipfile

from nylib.ue.capture import ImageSource, RecordingSource, wide_capture_ranges, write_capture
from nylib.ue.errors import MemoryReadError
from nylib.ue.memory import ProcessSource, current_process, open_process
from nylib.ue.pe import PeImage
from nylib.ue.scan import Scanner

_MARKER = b'NYLIBUE' + bytes((i * 37 + 11) & 0xFF for i in range(0x4000))
_MAP_MARKER = b'NYLIBMAP' + bytes((i * 53 + 7) & 0xFF for i in range(0x1000))
# The marker bytes are regenerated in the child from the same formulas (not embedded literally):
# passing 20+ KiB of repr'd bytes as a -c argument overflows Windows' command-line length limit.
_CHILD = (
    'import ctypes, mmap, os, sys\n'
    "buf = ctypes.create_string_buffer(b'NYLIBUE' + bytes((i * 37 + 11) & 0xFF for i in range(0x4000)))\n"
    f'view = mmap.mmap(-1, {len(_MAP_MARKER)})\n'
    "view.write(b'NYLIBMAP' + bytes((i * 53 + 7) & 0xFF for i in range(0x1000)))\n"
    'arr = (ctypes.c_char * len(view)).from_buffer(view)\n'
    "print(f'{os.getpid()} {ctypes.addressof(buf)} {ctypes.addressof(arr)}', flush=True)\n"
    'sys.stdin.read()\n'
)


class _Child:
    """A child python holding _MARKER at .addr and an anonymous mmap view holding _MAP_MARKER at .map_addr.
    Killed and its opened handles closed on exit."""

    def __enter__(self):
        self.handles = []
        self.popen = subprocess.Popen([getattr(sys, '_base_executable', sys.executable), '-c', _CHILD],
                                      stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        try:
            pid, addr, map_addr = self.popen.stdout.readline().split()
        except BaseException:
            self.kill()
            raise
        self.pid, self.addr, self.map_addr = int(pid), int(addr), int(map_addr)
        return self

    def open(self, **kwargs):
        self.handles.append(p := open_process(self.pid, **kwargs))
        return p

    def kill(self):
        if self.popen.poll() is None:
            self.popen.kill()
        self.popen.wait()
        self.popen.stdin.close()
        self.popen.stdout.close()

    def __exit__(self, *exc):
        try:
            self.kill()
        finally:
            for p in self.handles:
                p.close()


class FoundationsLiveTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = self._tmp.name

    def tearDown(self):
        self._tmp.cleanup()

    def _path(self, name):
        return os.path.join(self.dir, name)

    def test_internal_pe(self):
        src = ProcessSource(current_process())
        main = src.main_module
        image = PeImage(src, main.base)
        text = image.section('.text')
        self.assertIsNotNone(text)
        self.assertTrue(text.executable)
        imports = image.imports()
        self.assertTrue(imports)
        for slot in imports:
            self.assertEqual(src.u64(slot.slot), slot.value)

    def test_external_pe_matches_internal(self):
        internal_src = ProcessSource(current_process())
        internal_image = PeImage(internal_src, internal_src.main_module.base)
        with _Child() as child:
            ext_src = ProcessSource(child.open())
            ext_image = PeImage(ext_src, ext_src.main_module.base)
            self.assertTrue(ext_image.sections)
            self.assertEqual(
                [(s.name, ext_image.rva(s.address)) for s in ext_image.sections],
                [(s.name, internal_image.rva(s.address)) for s in internal_image.sections],
            )

    def test_scanner_on_real_image(self):
        src = ProcessSource(current_process())
        image = PeImage(src, src.main_module.base)
        scanner = Scanner(src, image)
        text = image.section('.text')
        first16 = src.read(text.address, 16)
        hits = scanner.find_bytes(first16)
        self.assertIn(text.address, hits)
        slot = image.imports()[0]
        hits2 = scanner.aligned_values(slot.value, executable=False)
        self.assertIn(slot.slot, hits2)

    def test_replay_equals_live(self):
        with _Child() as child:
            rec = RecordingSource(ProcessSource(child.open()))
            image = PeImage(rec, rec.main_module.base)
            sections_before = image.sections
            imports_before = image.imports()
            # a read through the cache-bypassing fresh sibling must be recorded too (shared store, F9)
            fresh_marker = rec.fresh.read(child.addr, len(_MARKER))
            self.assertEqual(fresh_marker, _MARKER)
            path = self._path('replay.zip')
            rec.save(path)
            child.kill()
            with ImageSource.load(path) as loaded:
                image2 = PeImage(loaded, loaded.main_module.base)
                self.assertEqual(image2.sections, sections_before)
                self.assertEqual(image2.imports(), imports_before)
                self.assertEqual(loaded.read(child.addr, len(_MARKER)), _MARKER)

    def test_wide_capture_child(self):
        with _Child() as child:
            src = ProcessSource(child.open())
            ranges, excluded = wide_capture_ranges(src.regions())
            path = self._path('wide.zip')
            result = write_capture(path, src, ranges, excluded=excluded)
            child.kill()
            with zipfile.ZipFile(path) as zf:
                doc = json.loads(zf.read('capture.json'))
            self.assertEqual(result['bytes'], sum(c[1] for c in doc['chunks']))
            with ImageSource.load(path) as image:
                main = image.main_module
                pe = PeImage(image, main.base)
                self.assertTrue(pe.sections)
                self.assertEqual(image.read(child.addr, len(_MARKER)), _MARKER)
                self.assertEqual(result['bytes'], sum(len(image.read(a, n)) for a, n, _ in doc['chunks']))

    def test_wide_capture_child_mapped_view(self):
        with _Child() as child:
            src = ProcessSource(child.open())
            ranges, excluded = wide_capture_ranges(src.regions())
            path = self._path('wide_map.zip')
            write_capture(path, src, ranges, excluded=excluded)
            child.kill()
            with ImageSource.load(path) as image:
                main = image.main_module
                pe = PeImage(image, main.base)
                self.assertTrue(pe.sections)
                hit = next((e for e in image.excluded if e[2] == 'MEM_MAPPED' and e[0] <= child.map_addr < e[0] + e[1]), None)
                self.assertIsNotNone(hit, image.excluded)
                with self.assertRaises(MemoryReadError) as cm:
                    image.read(child.map_addr, 8)
                self.assertTrue(cm.exception.reason.startswith('not captured'), cm.exception.reason)
                self.assertEqual(image.read(child.addr, len(_MARKER)), _MARKER)


if __name__ == '__main__':
    unittest.main()
