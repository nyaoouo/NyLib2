import os
import pathlib
import sys
import tempfile
import unittest
from unittest import mock

try:
    from nylib.winutils import python_loader as pl
except ImportError:
    pl = None


@unittest.skipIf(pl is None, 'nylib.winutils.python_loader cannot import')
class EnsureLoaderDllFrozenTests(unittest.TestCase):
    def run_ensure(self, frozen, exists, **kw):
        """Call ensure_loader_dll on a temp path with build_loader spied (never builds); returns (result, spy)."""
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(pl, 'build_loader') as spy, \
                mock.patch.object(sys, 'frozen', frozen, create=True):
            path = pathlib.Path(tmp) / 'python_loader.dll'
            if exists: path.write_bytes(b'')
            try:
                return pl.ensure_loader_dll(path, **kw), spy, path
            except Exception as exc:
                exc.spy, exc.path = spy, path
                raise

    def test_frozen_missing_dll_raises_without_building(self):
        with self.assertRaises(FileNotFoundError) as cm:
            self.run_ensure(True, False)
        cm.exception.spy.assert_not_called()
        self.assertIn(str(cm.exception.path), str(cm.exception))

    def test_frozen_rebuild_raises_without_building(self):
        for exists in (True, False):
            with self.subTest(exists=exists), self.assertRaises(RuntimeError) as cm:
                self.run_ensure(True, exists, rebuild=True)
            cm.exception.spy.assert_not_called()

    def test_frozen_existing_dll_is_returned(self):
        result, spy, path = self.run_ensure(True, True)
        self.assertEqual(result, path)
        spy.assert_not_called()

    def test_not_frozen_still_builds_on_demand(self):
        for exists, kw, calls in ((False, {}, 1), (True, {'rebuild': True}, 1), (True, {}, 0)):
            with self.subTest(exists=exists, kw=kw):
                _, spy, path = self.run_ensure(False, exists, **kw)
                self.assertEqual(spy.call_count, calls)


if __name__ == '__main__':
    unittest.main()
