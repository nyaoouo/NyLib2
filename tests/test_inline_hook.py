import importlib.util
import os
import subprocess
import sys
import unittest

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_CHILD = '''
import os
import sys
import nylib
from nylib.process import Process
from nylib.winutils.inline_call import InlineCallQueue, PrologueError
from nylib.winutils.inline_hook import read_code

assert os.path.normcase(os.path.dirname(os.path.dirname(os.path.abspath(nylib.__file__)))) == os.path.normcase(os.getcwd()), nylib.__file__
p = Process.current
bad = p.alloc(0x1000)
p.write(bad, b'\\x06' * 32)
partial = p.alloc(0x1000)
p.write(partial, b'\\x90' + b'\\x06' * 31)
for addr, fail_at in ((bad, bad), (partial, partial + 1)):
    try: read_code(p, addr, min_size=5)
    except ValueError as exc: assert f'{fail_at:#x}' in str(exc), str(exc)
    else: raise AssertionError(f'read_code accepted undecodable bytes at {addr:#x}')
    try: InlineCallQueue(p, addr).alloc()
    except PrologueError as exc: assert f'{fail_at:#x}' in str(exc), str(exc)
    else: raise AssertionError(f'alloc accepted undecodable bytes at {addr:#x}')
print('ok')
'''


@unittest.skipUnless(importlib.util.find_spec('capstone') and importlib.util.find_spec('keystone'), 'needs capstone and keystone')
class ReadCodeTests(unittest.TestCase):
    def test_undecodable_bytes_raise_instead_of_looping(self):
        env = {**os.environ, 'PYTHON_PIP_ALL_REQ_INSTALLED': '1'}
        try:
            done = subprocess.run([sys.executable, '-B', '-c', _CHILD], cwd=_ROOT, env=env, capture_output=True, text=True, timeout=60)
        except subprocess.TimeoutExpired:
            self.fail('read_code did not return on undecodable bytes within 60s')
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(done.stdout.strip(), 'ok')


if __name__ == '__main__':
    unittest.main()
