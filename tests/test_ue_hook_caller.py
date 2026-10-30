import importlib.util
import json
import os
import subprocess
import sys
import threading
import time
import unittest
from types import SimpleNamespace

from nylib.process import Process
from nylib.ue import calls
from nylib.ue.errors import CallError, PendingCallsError

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_HAS_HOOK_DEPS = all(importlib.util.find_spec(name) for name in ('capstone', 'keystone'))
_NEEDS_DEPS = unittest.skipUnless(_HAS_HOOK_DEPS, 'HookCaller binds a real inline hook: needs capstone and keystone')
_CODE_SIZE = 22  # mov eax, 42; 16 x nop; ret
_CHILD = '''
import ctypes
import os
import sys
import nylib
from nylib.process import Process
from nylib import winapi

ctypes.CDLL('ucrtbase.dll')
addr = Process.current.alloc(0x1000)
Process.current.write(addr, bytes.fromhex('B82A000000') + bytes([0x90]) * 16 + bytes([0xC3]))
winapi.FlushInstructionCache(Process.current.handle, addr, 22)
slot = Process.current.alloc(0x1000, protect=0x04)
Process.current.write_ptr(slot, addr)
Process.current.virtual_protect(slot, 0x1000, 0x02)
print(os.getpid(), addr, winapi.GetCurrentThreadId(), slot, os.path.dirname(os.path.dirname(os.path.abspath(nylib.__file__))), flush=True)
for line in sys.stdin:
    if line.strip() == 'hit': print(ctypes.CFUNCTYPE(ctypes.c_uint64)(Process.current.read_ptr(slot))(), flush=True)
    if line.strip() == 'exit': break
'''
_NO_CAPSTONE = '''
import json
import sys
from unittest import mock
sys.modules['capstone'] = None
import nylib
from nylib.process import Process
from nylib.ue import calls
from nylib.ue.errors import CallError

caller = calls.HookCaller(thread_id=1, trigger=1)
site = calls.CallSite(Process.current, None, 0, 1, lambda: None, 5.0, 'external')
with mock.patch.object(Process, 'alloc') as alloc:
    try:
        caller.bind(site)
    except CallError as exc:
        out = {'refused': exc.refused, 'state': exc.state, 'closed': caller.closed}
    else:
        out = {'bound': True}
    out['allocs'] = alloc.call_count
out['root'] = __import__('os').path.dirname(__import__('os').path.dirname(__import__('os').path.abspath(nylib.__file__)))
print(json.dumps(out))
'''


def _wait_for(predicate, timeout: float = 30.0) -> None:
    deadline = time.monotonic() + timeout
    while not predicate():
        if time.monotonic() > deadline:
            raise AssertionError('timed out waiting for the condition')
        time.sleep(0.02)


class _ChildCase(unittest.TestCase):
    def setUp(self):
        env = dict(os.environ, PYTHON_PIP_ALL_REQ_INSTALLED='1')
        self.child = subprocess.Popen([sys.executable, '-B', '-u', '-c', _CHILD], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True,
                                      cwd=_ROOT, env=env)
        self.addCleanup(self._reap)
        line = self.child.stdout.readline()
        self.assertTrue(line, 'the child exited before printing its addresses')
        pid, addr, tid, slot, root = line.split(None, 4)
        self.assertEqual(os.path.normcase(root.strip()), os.path.normcase(_ROOT), 'the child imported another nylib')
        self.pid, self.addr, self.tid, self.slot = int(pid), int(addr), int(tid), int(slot)
        self.process = Process(self.pid)
        self.addCleanup(self.process.close)
        self.original = self.code_at(self.addr)

    def _reap(self):
        if self.child.poll() is None:
            self.child.terminate()
        self.child.wait(10)
        self.child.stdin.close()
        self.child.stdout.close()

    def code_at(self, address: int) -> bytes:
        return bytes(self.process.read(address, _CODE_SIZE))

    def hit(self):
        self.child.stdin.write('hit\n')
        self.child.stdin.flush()
        self.assertEqual(self.child.stdout.readline().strip(), '42')

    def site(self, find_game_thread=None):
        find = find_game_thread or (lambda: self.process.get_thread(self.tid))
        return calls.CallSite(self.process, SimpleNamespace(), 0, self.addr, find, 5.0, 'external')

    def hook_caller(self, **kwargs):
        caller = calls.HookCaller(**kwargs)

        def close():
            try:
                caller.close()
            except PendingCallsError:
                pass
        self.addCleanup(close)
        return caller

    def get_tid(self):
        return self.process.get_proc_address('kernel32.dll', 'GetCurrentThreadId')


@_NEEDS_DEPS
class HookCallerChildTests(_ChildCase):
    def test_bind_defaults_and_a_call_returns_the_main_thread_id_after_a_hit(self):
        opened = []

        def find_game_thread():
            opened.append(self.process.get_thread(self.tid))
            return opened[-1]

        caller = self.hook_caller()
        caller.bind(self.site(find_game_thread))
        self.assertEqual((caller.thread_id, caller.trigger, caller.capacity), (self.tid, self.addr, 16))
        self.assertEqual(len(opened), 1)
        out = {}

        def run():
            try:
                out['value'] = caller.call(self.get_tid(), timeout=60)
            except BaseException as exc:
                out['error'] = exc

        worker = threading.Thread(target=run, daemon=True)
        worker.start()
        _wait_for(lambda: caller._tickets or out)
        self.assertEqual(out, {})
        self.hit()
        worker.join(60)
        self.assertFalse(worker.is_alive())
        self.assertEqual(out, {'value': self.tid})
        caller.close()
        self.assertTrue(caller.closed)
        self.assertEqual(self.code_at(self.addr), self.original)

    def test_bind_validation(self):
        cases = (
            ('capacity', dict(thread_id=self.tid, trigger=self.addr, capacity=3), 'capacity must be a power of two'),
            ('trigger 0', dict(thread_id=self.tid, trigger=0, capacity=4), 'trigger must be a nonzero executable address'),
            ('data page', dict(thread_id=self.tid, trigger=self.slot), 'is not in committed executable memory'),
            ('own thread', dict(thread_id=threading.get_native_id(), trigger=self.addr), 'does not belong to process'),
        )
        for label, kwargs, text in cases:
            with self.subTest(label):
                caller = self.hook_caller(**kwargs)
                with self.assertRaises(ValueError) as cm:
                    caller.bind(self.site())
                self.assertIn(text, str(cm.exception))
                self.assertTrue(caller.closed)
                self.assertEqual(self.code_at(self.addr), self.original)

    def test_a_trigger_starting_with_a_jump_is_refused_with_the_hint(self):
        trigger = self.process.alloc(0x1000)
        self.addCleanup(self.process.free, trigger)
        jumpy = b'\xE9\x00\x00\x00\x00' + b'\x90' * 16 + b'\xC3'
        self.process.write(trigger, jumpy)
        caller = self.hook_caller(thread_id=self.tid, trigger=trigger)
        caller.bind(self.site())
        with self.assertRaises(CallError) as cm:
            caller.call(self.get_tid(), timeout=5)
        self.assertEqual(cm.exception.refused, 'prologue')
        self.assertEqual(cm.exception.state, 'not started')
        self.assertIn('the trigger already starts with a jump', str(cm.exception))
        self.assertEqual(self.code_at(trigger), jumpy)
        self.assertEqual(self.code_at(self.addr), self.original)

    def test_a_timed_out_call_keeps_close_pending_until_the_hit(self):
        caller = self.hook_caller(thread_id=self.tid, trigger=self.addr)
        caller.bind(self.site())
        with self.assertRaises(CallError) as cm:
            caller.call(self.get_tid(), timeout=0.3)
        self.assertTrue(cm.exception.timed_out)
        self.assertEqual(cm.exception.state, 'unknown')
        with self.assertRaises(PendingCallsError) as pending:
            caller.close()
        self.assertEqual(pending.exception.pending, 1)
        self.assertFalse(caller.closed)
        self.assertNotEqual(self.code_at(self.addr), self.original, 'the hook must stay while a call is pending')
        self.hit()

        def closed():
            try:
                caller.close()
            except PendingCallsError:
                return False
            return True
        _wait_for(closed)
        self.assertTrue(caller.closed)
        self.assertEqual(self.code_at(self.addr), self.original)


class HookCallerDependencyTests(unittest.TestCase):
    def test_missing_capstone_refuses_the_bind_before_any_allocation(self):
        env = dict(os.environ, PYTHON_PIP_ALL_REQ_INSTALLED='1')
        run = subprocess.run([sys.executable, '-B', '-c', _NO_CAPSTONE], cwd=_ROOT, env=env, capture_output=True, text=True, timeout=120)
        self.assertEqual(run.returncode, 0, run.stderr)
        out = json.loads(run.stdout.strip().splitlines()[-1])
        self.assertEqual(os.path.normcase(out.pop('root')), os.path.normcase(_ROOT), 'the child imported another nylib')
        self.assertEqual(out, {'refused': 'dependencies', 'state': 'not started', 'closed': True, 'allocs': 0})


if __name__ == '__main__':
    unittest.main()
