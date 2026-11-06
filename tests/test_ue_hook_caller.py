import importlib.util
import json
import os
import queue
import struct
import subprocess
import sys
import threading
import time
import unittest
from types import SimpleNamespace
from unittest import mock

from nylib.process import Process
from nylib.ue import calls
from nylib.ue.errors import CallError, PendingCallsError

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_HAS_HOOK_DEPS = all(importlib.util.find_spec(name) for name in ('capstone', 'keystone'))
_NEEDS_DEPS = unittest.skipUnless(_HAS_HOOK_DEPS, 'HookCaller binds a real inline hook: needs capstone and keystone')
_READ_TIMEOUT = 60.0  # seconds to wait for a line from the child
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
import os
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
out['root'] = os.path.dirname(os.path.dirname(os.path.abspath(nylib.__file__)))
print(json.dumps(out))
'''
_STALE_HOOK_HOST = '''
import os
import sys
from unittest import mock
import nylib
from nylib.process import Process
from nylib.ue import calls
from nylib.winutils.inline_call import _find_nylib_hook

assert os.path.normcase(os.path.dirname(os.path.dirname(os.path.abspath(nylib.__file__)))) == os.path.normcase(os.getcwd())
pid, addr, tid = map(int, sys.argv[1:4])
process = Process(pid)
caller = calls.HookCaller(thread_id=tid, trigger=addr)
caller.bind(calls.CallSite(process, None, 0, addr, lambda: None, 5.0, 'external'))
if sys.argv[4] == 'far':
    with mock.patch.object(Process, 'alloc_near', side_effect=ValueError('force far jump')):
        caller._get_queue()
else:
    caller._get_queue()
hook = _find_nylib_hook(process, addr)
assert hook is not None and hook.held
assert bytes(process.read(addr, 1 if sys.argv[4] == 'near' else 6)) == (b'\\xE9' if sys.argv[4] == 'near' else b'\\xFF\\x25\\x00\\x00\\x00\\x00')
print(hook.page, hook.data_at, flush=True)
os._exit(0)
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
        self.lines = queue.Queue()
        self.reader = threading.Thread(target=self._read_lines, daemon=True)
        self.reader.start()
        self.addCleanup(self._reap)
        line = self.next_line('its addresses')
        pid, addr, tid, slot, root = line.split(None, 4)
        self.assertEqual(os.path.normcase(root.strip()), os.path.normcase(_ROOT), 'the child imported another nylib')
        self.pid, self.addr, self.tid, self.slot = int(pid), int(addr), int(tid), int(slot)
        self.process = Process(self.pid)
        self.addCleanup(self.process.close)
        self.original = self.code_at(self.addr)

    def _read_lines(self):
        for line in self.child.stdout:
            self.lines.put(line)
        self.lines.put(None)

    def next_line(self, what: str) -> str:
        try:
            line = self.lines.get(timeout=_READ_TIMEOUT)
        except queue.Empty:
            self.fail(f'the child printed nothing for {what} within {_READ_TIMEOUT:g} s')
        if line is None:
            self.fail(f'the child exited before printing {what}')
        return line

    def _reap(self):
        if self.child.poll() is None:
            self.child.terminate()
        self.child.wait(10)
        self.reader.join(10)
        self.child.stdin.close()
        self.child.stdout.close()

    def code_at(self, address: int) -> bytes:
        return bytes(self.process.read(address, _CODE_SIZE))

    def hit(self):
        self.child.stdin.write('hit\n')
        self.child.stdin.flush()
        self.assertEqual(self.next_line('the result of the hit').strip(), '42')

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

    def test_a_timed_out_call_is_withdrawn_before_a_later_hit(self):
        caller = self.hook_caller(thread_id=self.tid, trigger=self.addr)
        caller.bind(self.site())
        with self.assertRaises(CallError) as cm:
            caller.call(self.get_tid(), timeout=0.3)
        self.assertTrue(cm.exception.timed_out)
        self.assertEqual(cm.exception.state, 'not started')
        self.assertEqual(caller.pending, 0)
        ticket = next(iter(caller._queue._withdrawn.values()))
        self.hit()
        self.assertTrue(ticket.withdrawn)
        self.assertEqual(caller._queue._atomic.load(caller._queue._slot_at(ticket.sequence)), 4)
        caller.close()
        self.assertTrue(caller.closed)
        self.assertEqual(self.code_at(self.addr), self.original)


@_NEEDS_DEPS
class StaleHookHintTests(_ChildCase):
    def refused(self, trigger):
        before = self.code_at(trigger)
        caller = self.hook_caller(thread_id=self.tid, trigger=trigger)
        caller.bind(self.site())
        with self.assertRaises(CallError) as cm:
            caller.call(self.get_tid(), timeout=5)
        self.assertEqual(cm.exception.refused, 'prologue')
        self.assertEqual(cm.exception.state, 'not started')
        self.assertEqual(self.code_at(trigger), before)
        return str(cm.exception)

    def ended_host(self, form):
        env = dict(os.environ, PYTHON_PIP_ALL_REQ_INSTALLED='1')
        host = subprocess.run([sys.executable, '-B', '-u', '-c', _STALE_HOOK_HOST, str(self.pid), str(self.addr), str(self.tid), form],
                              cwd=_ROOT, env=env, capture_output=True, text=True, timeout=60)
        self.assertEqual(host.returncode, 0, host.stderr)
        page, data_at = map(int, host.stdout.split())
        text = self.refused(self.addr)
        self.assertIn(f'this process does not hold (dispatcher page {page:#x}, queue {data_at:#x})', text)
        self.assertIn('a close() of the session that installed it removes it', text)
        self.assertIn('calls.HookCaller(replace_stale=True)', text)
        self.assertNotIn('this version recognises', text)

    def test_ended_host_near_hook(self):
        self.ended_host('near')

    def test_ended_host_far_hook(self):
        self.ended_host('far')

    def test_hook_held_by_this_process(self):
        from nylib.winutils.inline_call import _find_nylib_hook
        owner = self.hook_caller(thread_id=self.tid, trigger=self.addr)
        owner.bind(self.site())
        owner._get_queue()
        hook = _find_nylib_hook(self.process, self.addr)
        self.assertIsNotNone(hook)
        self.assertTrue(hook.held)
        text = self.refused(self.addr)
        self.assertIn(f'this process installed (queue {hook.data_at:#x})', text)
        self.assertIn('is retried at exit', text)
        self.assertIn('retried at the next calls-enabled attach', text)
        self.assertNotIn('does not hold', text)
        owner.close()
        self.assertEqual(self.code_at(self.addr), self.original)

    def test_unrecognised_jump_to_an_aligned_nop_page(self):
        page = self.process.alloc_near(0x1000, self.addr)
        self.addCleanup(self.process.free, page)
        self.assertEqual(page & 0xFFF, 0)
        self.process.write(page, b'\x90' * 0x1000)
        jumpy = b'\xE9' + (page - self.addr - 5).to_bytes(4, 'little', signed=True) + self.original[5:]
        self.process.write(self.addr, jumpy)
        self.addCleanup(self.process.write, self.addr, self.original)
        text = self.refused(self.addr)
        self.assertIn('already starts with a jump that is not a nylib game-thread hook this version recognises', text)
        self.assertIn('only a game restart removes it', text)


_REMOVAL_HOST = _STALE_HOOK_HOST.replace(
    "sys.argv[4] == 'near'", "sys.argv[4] in ('near', 'v1')",
).replace(
    'print(hook.page, hook.data_at, flush=True)\nos._exit(0)',
    """queue = caller._queue
if sys.argv[4] == 'v1':
    from nylib.winutils import inline_call as ic
    code = ic._dispatcher_code_v1(hook.data_at, hook.capacity, hook.thread_id) + hook.original + ic._absolute_jump(addr + hook.size)
    old = process.virtual_protect(hook.page, 0x1000, 0x40)
    process.write(hook.page, code)
    process.virtual_protect(hook.page, 0x1000, old)
    ic.winapi.FlushInstructionCache(process.handle, hook.page, len(code))
    assert ic._find_nylib_hook(process, addr) is not None
queue.submit(process.get_proc_address('kernel32.dll', 'GetCurrentThreadId'))
queue.submit(process.get_proc_address('kernel32.dll', 'GetCurrentThreadId'))
print(hook.page, hook.data_at, flush=True)
for line in sys.stdin:
    if line.strip() == 'unmap':
        import ctypes
        unmap = ctypes.WinDLL('kernel32.dll', use_last_error=True).UnmapViewOfFile
        unmap.argtypes = (ctypes.c_void_p,)
        unmap.restype = ctypes.c_bool
        assert unmap(queue._shared.local_at)
        print('unmapped', flush=True)
    if line.strip() == 'exit': os._exit(0)
os._exit(0)""",
)


@_NEEDS_DEPS
class StaleHookRemovalTests(_ChildCase):
    def start_host(self, form='near'):
        host = subprocess.Popen([sys.executable, '-B', '-u', '-c', _REMOVAL_HOST, str(self.pid), str(self.addr), str(self.tid), form],
                                cwd=_ROOT, env=dict(os.environ, PYTHON_PIP_ALL_REQ_INSTALLED='1'),
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        lines = queue.Queue()

        def read():
            for line in host.stdout: lines.put(line)
            lines.put(None)

        reader = threading.Thread(target=read, daemon=True)
        reader.start()

        def reap():
            if host.poll() is None: host.terminate()
            host.wait(10)
            reader.join(10)
            host.stdin.close()
            host.stdout.close()
            host.stderr.close()

        self.addCleanup(reap)
        line = lines.get(timeout=_READ_TIMEOUT)
        self.assertIsNotNone(line, host.stderr.read() if host.poll() is not None else 'host printed no addresses')
        page, data_at = map(int, line.split())
        host.owner_pid = struct.unpack('<Q', self.process.read(data_at + 0x18, 8, strict=True))[0]
        return host, lines, page, data_at

    def replacing(self):
        caller = self.hook_caller(thread_id=self.tid, trigger=self.addr, replace_stale=True)
        caller.bind(self.site())
        return caller

    def refuse(self, caller, text):
        before = self.code_at(self.addr)
        with self.assertRaises(CallError) as cm:
            caller.call(self.get_tid(), timeout=5)
        self.assertEqual((cm.exception.refused, cm.exception.state), ('prologue', 'not started'))
        self.assertIn(text, str(cm.exception))
        self.assertEqual(self.code_at(self.addr), before)
        self.assertIsNone(caller._queue)

    def replace_and_call(self, caller, page, data_at):
        from nylib.winutils import inline_call as ic
        remove = ic._remove_nylib_hook

        def checked_remove(*args):
            count = remove(*args)
            self.assertEqual(self.process.virtual_query(page).State, 0x10000)
            self.assertEqual(self.process.virtual_query(data_at).State, 0x10000)
            return count

        with mock.patch.object(ic, '_remove_nylib_hook', side_effect=checked_remove), self.assertLogs('nylib.ue.calls', 'WARNING') as logs:
            q = caller._get_queue()
        self.assertEqual(logs.output, [f'WARNING:nylib.ue.calls:removed a stale nylib game-thread hook at {self.addr:#x} in process {self.pid} '
                                      f'(dispatcher page {page:#x}); 2 queued calls of the earlier session were dropped'])
        ticket = q.submit(self.get_tid())
        self.hit()
        self.assertEqual(ticket.wait(5000), self.tid)
        caller.close()
        self.assertEqual(self.code_at(self.addr), self.original)

    def test_ended_hosts_near_far_and_v1(self):
        for form in ('near', 'far', 'v1'):
            with self.subTest(form=form):
                host, lines, page, data_at = self.start_host(form)
                host.stdin.write('exit\n')
                host.stdin.flush()
                self.assertEqual(host.wait(10), 0)
                self.replace_and_call(self.replacing(), page, data_at)

    def test_live_owner_is_refused_then_killed_owner_is_removed(self):
        host, lines, page, data_at = self.start_host()
        caller = self.replacing()
        self.refuse(caller, f'process {host.owner_pid}, which still runs')
        host.terminate()
        host.wait(10)
        self.replace_and_call(caller, page, data_at)

    def test_live_owner_with_unmapped_host_view_is_removed(self):
        host, lines, page, data_at = self.start_host()
        host.stdin.write('unmap\n')
        host.stdin.flush()
        self.assertEqual(lines.get(timeout=_READ_TIMEOUT).strip(), 'unmapped')
        self.assertIsNone(host.poll())
        self.replace_and_call(self.replacing(), page, data_at)

    def test_zero_owner_words_allow_older_host_removal(self):
        host, lines, page, data_at = self.start_host()
        self.process.write(data_at + 0x18, bytes(16))
        self.replace_and_call(self.replacing(), page, data_at)

    def test_default_refuses_and_held_hook_stays(self):
        owner = self.hook_caller(thread_id=self.tid, trigger=self.addr)
        owner.bind(self.site())
        owner._get_queue()
        self.refuse(self.replacing(), 'this process installed')
        owner.close()
        host, lines, page, data_at = self.start_host()
        host.terminate()
        host.wait(10)
        caller = self.hook_caller(thread_id=self.tid, trigger=self.addr)
        caller.bind(self.site())
        self.refuse(caller, 'does not hold')

    def test_unrecognised_jump_is_untouched(self):
        jump = b'\xe9' + bytes(4) + self.original[5:]
        self.process.write(self.addr, jump)
        self.refuse(self.replacing(), 'not a nylib game-thread hook this version recognises')

    def test_unknown_owner_and_unreadable_words_refuse(self):
        from nylib.winutils import inline_call as ic
        host, lines, page, data_at = self.start_host()
        with mock.patch.object(ic, '_owner_running', return_value=None):
            self.refuse(self.replacing(), f'process {host.owner_pid}, which could not be checked')
        read = self.process.read

        def unreadable_owner(addr, *args, **kwargs):
            if addr == data_at + 0x18: raise OSError('owner words unreadable')
            return read(addr, *args, **kwargs)

        with mock.patch.object(self.process, 'read', side_effect=unreadable_owner):
            self.refuse(self.replacing(), 'an unknown process, which could not be checked')

    def test_unmapped_queue_is_not_read_or_removed(self):
        from nylib.winutils import inline_call as ic
        at = self.process.alloc(0x1000, protect=0x04)
        self.process.free(at)
        hook = ic._NylibHook(0, at, 16, self.tid, 5, self.original[:5], False)
        with mock.patch.object(self.process, 'read', side_effect=AssertionError('unmapped read')):
            self.assertIsNone(ic._hook_owner(self.process, hook))
            with self.assertRaisesRegex(RuntimeError, 'queue view .* is not mapped'):
                ic._remove_nylib_hook(self.process, self.addr, hook)
        for error in (OSError('query failed'), ValueError('invalid address')):
            with mock.patch.object(self.process, 'virtual_query', side_effect=error), mock.patch.object(self.process, 'read') as read:
                self.assertIsNone(ic._hook_owner(self.process, hook))
                with self.assertRaisesRegex(RuntimeError, 'queue view .* is not mapped'):
                    ic._remove_nylib_hook(self.process, self.addr, hook)
                read.assert_not_called()
        self.assertEqual(self.code_at(self.addr), self.original)

    def test_owner_running_boundaries_and_real_child_view(self):
        from nylib.winutils import inline_call as ic
        for owner, expected in ((None, None), (ic._HookOwner(0, 0), False), (ic._HookOwner(os.getpid(), 0), False),
                                (ic._HookOwner(2**32, 1), None), (ic._HookOwner(self.pid, 0), None),
                                (ic._HookOwner(self.pid, 0x8000_0000_0000), None)):
            with self.subTest(owner=owner), mock.patch('nylib.process.Process', side_effect=AssertionError('must not open')):
                self.assertIs(ic._owner_running(owner), expected)
        at = self.process.alloc(0x1000, protect=0x04)
        try:
            owner = ic._HookOwner(self.pid, at)
            self.assertIs(ic._owner_running(owner), False)
            self.process.write(at + 0x18, struct.pack('<QQ', self.pid, at))
            self.assertIs(ic._owner_running(owner), True)
        finally:
            self.process.free(at)
        self.assertIs(ic._owner_running(owner), False)

    def test_owner_open_and_liveness_failures(self):
        from nylib.winutils import inline_call as ic
        owner = ic._HookOwner(self.pid, self.addr)
        for code, expected in ((87, False), (5, None)):
            err = OSError('open failed')
            err.winerror = code
            with mock.patch('nylib.process.Process', side_effect=err):
                self.assertIs(ic._owner_running(owner), expected)
        for alive, expected in ((OSError('query failed'), None), (False, False)):
            process = mock.Mock()
            if isinstance(alive, Exception): process.still_alive.side_effect = alive
            else: process.still_alive.return_value = alive
            with mock.patch('nylib.process.Process', return_value=process) as opened:
                self.assertIs(ic._owner_running(owner), expected)
            opened.assert_called_once_with(self.pid, da=0x1010)
            process.close.assert_called_once_with()
            process.read.assert_not_called()

    def test_busy_drain_leaks_page_and_view_but_restores_trigger(self):
        from nylib.winutils import inline_call as ic
        host, lines, page, data_at = self.start_host()
        spin = self.process.alloc(0x1000)
        self.process.write(spin, b'\xeb\xfe')
        self.process.write(data_at + ic._HEADER_SIZE + 8, struct.pack('<Q', spin))
        self.child.stdin.write('hit\n')
        self.child.stdin.flush()
        _wait_for(lambda: bytes(self.process.read(data_at + 0x10, 8, strict=True)) == struct.pack('<Q', 1))
        host.terminate()
        host.wait(10)
        caller = self.replacing()
        with self.assertLogs('nylib.winutils.inline_call', 'WARNING') as logs, self.assertLogs('nylib.ue.calls', 'WARNING') as removed:
            caller._get_queue()
        self.assertIn(f'its dispatcher page {page:#x} and queue view {data_at:#x}', logs.output[0])
        self.assertIn(f'(dispatcher page {page:#x}); 2 queued calls of the earlier session were dropped', removed.output[0])
        self.assertEqual(self.process.virtual_query(page).State, 0x1000)
        self.assertEqual(self.process.virtual_query(data_at).State, 0x1000)
        self.assertNotEqual(ic._find_nylib_hook(self.process, self.addr).page, page)
        caller.close()
        self.assertEqual(self.code_at(self.addr), self.original)

    def test_replace_stale_must_be_bool(self):
        with self.assertRaises(TypeError): calls.HookCaller(replace_stale=1)

    def test_in_process_stale_hook_uses_quiescent_windows(self):
        script = """
import os
from unittest import mock
from nylib.process import Process
from nylib.ue import calls
from nylib.winutils import inline_call as ic
from nylib import winapi
p = Process.current
addr = p.alloc(0x1000)
original = bytes.fromhex('B82A000000') + bytes([0x90]) * 16 + bytes([0xC3])
p.write(addr, original)
q = ic.InlineCallQueue(p, addr, quiescent_patch=True)
q.enabled = True
ic._open_queues.remove(q._registry_key)
caller = calls.HookCaller(thread_id=winapi.GetCurrentThreadId(), trigger=addr, replace_stale=True)
caller.bind(calls.CallSite(p, None, 0, addr, lambda: None, 5.0, 'internal'))
with mock.patch.object(ic, '_run_quiescent', wraps=ic._run_quiescent) as window:
    caller._get_queue()
    assert window.call_count == 3, window.call_count
caller.close()
assert bytes(p.read(addr, len(original))) == original
print('in-process removal OK', flush=True)
os._exit(0)
"""
        run = subprocess.run([sys.executable, '-B', '-u', '-c', script], cwd=_ROOT,
                             env=dict(os.environ, PYTHON_PIP_ALL_REQ_INSTALLED='1'), capture_output=True, text=True, timeout=60)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(run.stdout.strip(), 'in-process removal OK')


@_NEEDS_DEPS
class ExitStateTests(_ChildCase):
    def test_target_killed_with_a_queued_call_never_starts(self):
        caller = self.hook_caller(thread_id=self.tid, trigger=self.addr)
        caller.bind(self.site())
        get_tid = self.get_tid()
        out = {}

        def run():
            try:
                out['value'] = caller.call(get_tid, timeout=60)
            except BaseException as exc:
                out['error'] = exc

        worker = threading.Thread(target=run, daemon=True)
        worker.start()
        self.addCleanup(worker.join, 70)
        try:
            _wait_for(lambda: caller.pending == 1 or 'error' in out)
            self.assertNotIn('error', out)
            self.assertEqual(caller.pending, 1)
        finally:
            self.child.kill()
            self.child.wait(30)
        worker.join(60)
        self.assertFalse(worker.is_alive(), 'the call did not observe target exit')
        self.assertIsInstance(out.get('error'), CallError, out)
        self.assertTrue(out['error'].exited)
        self.assertEqual(out['error'].state, 'not started')

    def test_target_killed_with_a_running_callee_has_unknown_outcome(self):
        caller = self.hook_caller(thread_id=self.tid, trigger=self.addr)
        caller.bind(self.site())
        sleep = self.process.get_proc_address('kernel32.dll', 'Sleep')
        out = {}
        def run():
            try:
                caller.call(sleep, 60000, timeout=60)
            except BaseException as exc:
                out['error'] = exc
        worker = threading.Thread(target=run, daemon=True)
        worker.start()
        self.addCleanup(worker.join, 70)
        _wait_for(lambda: caller.pending == 1 or out)
        self.assertEqual(out, {})
        self.child.stdin.write('hit\n')
        self.child.stdin.flush()
        ticket = caller._tickets[0]
        _wait_for(lambda: caller._queue._atomic.load(caller._queue._slot_at(ticket.sequence)) == 2)
        self.child.kill()
        self.child.wait(30)
        worker.join(60)
        self.assertFalse(worker.is_alive())
        self.assertIsInstance(out.get('error'), CallError, out)
        self.assertEqual((out['error'].exited, out['error'].state), (True, 'unknown'))


@_NEEDS_DEPS
class WithdrawSurfaceTests(_ChildCase):
    def waiting_call(self, caller, function=None, args=(), timeout=60):
        function = self.get_tid() if function is None else function
        out = {}
        def run():
            try:
                out['value'] = caller.call(function, *args, timeout=timeout)
            except BaseException as exc:
                out['error'] = exc
        worker = threading.Thread(target=run, daemon=True)
        worker.start()
        self.addCleanup(worker.join, 70)
        _wait_for(lambda: caller.pending or out)
        self.assertEqual(out, {})
        return worker, out

    def caller(self):
        caller = self.hook_caller(thread_id=self.tid, trigger=self.addr)
        caller.bind(self.site())
        return caller

    def test_bulk_withdraw_wakes_a_waiter_and_counts_only_once(self):
        caller = self.caller()
        worker, out = self.waiting_call(caller)
        self.assertEqual(caller.withdraw_pending(), 1)
        self.assertEqual(caller.withdraw_pending(), 0)
        worker.join(60)
        self.assertFalse(worker.is_alive())
        self.assertIsInstance(out.get('error'), CallError, out)
        exc = out['error']
        self.assertEqual(str(exc), 'the call was withdrawn before it started')
        self.assertEqual(exc.state, 'not started')
        self.assertFalse(exc.timed_out)
        self.assertEqual(caller.pending, 0)
        caller.close()
        self.hit()

    def test_call_finished_at_deadline_returns_its_result(self):
        from nylib.winutils.inline_call import CallTicket
        wait = CallTicket.wait
        def at_deadline(ticket, timeout_ms):
            wait(ticket, timeout_ms)
            raise TimeoutError('the deadline coincided with completion')
        caller = self.caller()
        with mock.patch.object(CallTicket, 'wait', at_deadline):
            worker, out = self.waiting_call(caller)
            self.hit()
            worker.join(60)
        self.assertFalse(worker.is_alive())
        self.assertEqual(out, {'value': self.tid})
        self.assertEqual(caller.pending, 0)

    def test_started_timeout_stays_pending_and_cannot_be_withdrawn(self):
        from nylib.winutils.inline_call import CallTicket
        def after_start(ticket, timeout_ms):
            _wait_for(lambda: caller._queue._atomic.load(caller._queue._slot_at(ticket.sequence)) == 2)
            raise TimeoutError('the deadline passed after the call started')
        caller = self.caller()
        sleep = self.process.get_proc_address('kernel32.dll', 'Sleep')
        with mock.patch.object(CallTicket, 'wait', after_start):
            worker, out = self.waiting_call(caller, sleep, (2000,))
            self.child.stdin.write('hit\n')
            self.child.stdin.flush()
            worker.join(60)
        self.assertFalse(worker.is_alive())
        self.assertIsInstance(out.get('error'), CallError, out)
        self.assertEqual((out['error'].timed_out, out['error'].state), (True, 'unknown'))
        self.assertEqual(caller.pending, 1)
        self.assertEqual(caller.withdraw_pending(), 0)
        with self.assertRaises(PendingCallsError): caller.close()
        self.assertEqual(self.next_line('the sleeping hit').strip(), '42')
        caller.close()

    def test_dead_target_close_and_waiter_report_not_started(self):
        caller = self.caller()
        worker, out = self.waiting_call(caller)
        self.child.kill()
        self.child.wait(30)
        caller.close()
        worker.join(60)
        self.assertFalse(worker.is_alive())
        self.assertIsInstance(out.get('error'), CallError, out)
        self.assertEqual((out['error'].exited, out['error'].state), (True, 'not started'))


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
