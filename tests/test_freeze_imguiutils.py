import json
import os
import subprocess
import sys
import tempfile
import unittest
from modulefinder import ModuleFinder

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_HEAVY = ('nylib.imguiutils.debug_view', 'capstone', 'keystone', 'nylib.winutils.breakpoint')

_CHILD = r'''
import json, sys
try:
    import nylib.pyimgui
except ImportError:
    sys.exit(3)
import nylib.imguiutils as m
out = {'eager': 'nylib.imguiutils.debug_view' in sys.modules, 'names': [n in dir(m) for n in ('DebugViewState', 'render_debug_view')]}
import nylib.imguiutils.debug_view as dv
out['state'] = m.DebugViewState is dv.DebugViewState
out['render'] = m.render_debug_view is dv.render_debug_view
out['cached'] = 'DebugViewState' in vars(m)
try:
    m.no_such_name
except AttributeError as e:
    out['error'] = str(e)
print(json.dumps(out))
'''


class FreezeImguiutilsTests(unittest.TestCase):
    def test_closure_of_utils_import_excludes_debug_view(self):
        with tempfile.TemporaryDirectory() as tmp:
            script = os.path.join(tmp, 'app.py')
            with open(script, 'w') as f:
                f.write('from nylib.imguiutils.utils import BeginFullScreenBackGround\n')
            finder = ModuleFinder(path=[ROOT] + sys.path)
            finder.run_script(script)
        self.assertIn('nylib.imguiutils.utils', finder.modules)
        bad = sorted(n for n in finder.modules if any(n == h or n.startswith(h + '.') for h in _HEAVY))
        self.assertEqual(bad, [])

    def test_debug_view_loads_on_first_access(self):
        r = subprocess.run([sys.executable, '-c', _CHILD], cwd=ROOT, capture_output=True, text=True, timeout=300)
        if r.returncode == 3:
            self.skipTest('nylib.pyimgui is not built')
        self.assertEqual(r.returncode, 0, r.stderr)
        out = json.loads(r.stdout.splitlines()[-1])
        self.assertFalse(out['eager'])
        self.assertEqual(out['names'], [True, True])
        self.assertTrue(out['state'] and out['render'] and out['cached'])
        self.assertEqual(out['error'], "module 'nylib.imguiutils' has no attribute 'no_such_name'")


if __name__ == '__main__':
    unittest.main()
