"""Port gate 6-G: stages 4-6 on every captured session, compared with that session's Dumper-7 oracle.

Env-gated: skipped when NYLIB_UE_CAPTURES is unset; see port.py for the run and the comparisons.
"""
import os
import sys
import tempfile
import unittest

from . import real


class PortGateTests(unittest.TestCase):
    sessions: list = []
    runs: list = []

    @classmethod
    def setUpClass(cls):
        if real.captures_root() is None:
            raise unittest.SkipTest('NYLIB_UE_CAPTURES not set')
        cls.sessions = real.iter_sessions()
        cls.runs = []
        if not cls.sessions:
            return
        from . import port  # only with a session: imports the port (stages 4-6)
        for session in cls.sessions:
            with tempfile.TemporaryDirectory(prefix='nylib-ue-port-', ignore_cleanup_errors=True) as tmp:
                run = port.run_port(session, tmp)
            print(run.report(), file=sys.stderr)
            cls.runs.append(run)

    def _check(self, name: str, *, bootstrap: bool = False):
        for run in self.runs:
            with self.subTest(session=f'{run.target}/{os.path.basename(run.dir)}'):
                for s in run.steps if bootstrap else ():
                    if s.name == 'walk':
                        break
                    if s.status != 'ok':
                        self.fail(f'step {s.name} {s.status}: {s.detail or run.error}')
                if name in run.skipped:
                    self.skipTest(run.skipped[name])
                if (dr := run.checks.get(name)) is None:
                    self.fail(f'{name} not run: the run stopped at {run.error}')
                lines = '\n'.join(dr.samples)
                self.assertTrue(dr.ok, f'{name}: {dr.reason} (matched={dr.matched} changed={dr.changed} drift={dr.drift:.4f})\n{lines}')

    def test_sessions_present(self):
        if not self.sessions:
            self.fail('no complete capture session')
        for t in real.required_targets():
            if not any(s.target == t for s in self.sessions):
                self.fail(f'required target {t} has no complete session')

    def test_bootstrap_and_offsets(self):
        self._check('offsets', bootstrap=True)

    def test_gobjects(self):
        self._check('gobjects')

    def test_gobjects_with_properties(self):
        self._check('gobjects-props')

    def test_idmap(self):
        self._check('idmap')

    def test_stem(self):
        self._check('stem')

    def test_names(self):
        self._check('names')

    def test_counts(self):
        self._check('counts')

    def test_enums(self):
        self._check('enums')

    def test_props_exact(self):
        self._check('props-exact')

    def test_cdo_types(self):
        self._check('cdo-types')


class PortRegressionTests(unittest.TestCase):
    """Regressions found by 6-G that need no capture; never skipped."""

    def test_gnames_override_rejected(self):
        from ..engine.core import Engine
        from ..errors import DetectionError
        from .pe_file import map_pe_file
        image = map_pe_file(sys._base_executable)
        try:
            base = image.main_module.base
            rva = next(a - base for r in image.regions()[1:] for a in range(r.end - 0x20, r.base - 1, -0x20)
                       if image.read(a, 0x20) == bytes(0x20))
            e = Engine(image)
            with self.assertRaises(DetectionError) as cm:
                e.fname.init_override(rva, 'GNames', True)
            self.assertEqual(cm.exception.step, 'FName::Init')
            self.assertEqual(e.names.GNames, 0)
        finally:
            image.close()


if __name__ == '__main__':
    unittest.main()
