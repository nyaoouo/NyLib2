import contextlib
import ctypes
import queue
import struct
import subprocess
import sys
import threading
import time
import unittest
from unittest.mock import patch

from nylib import winapi
from nylib.process import Process
from nylib.winutils import inline_call
from nylib.winutils.inline_call import InlineCallQueue, PrologueError, VTableCallQueue
from nylib.winutils.inline_hook import InlineHook, ks_
from nylib.winutils.vtable_hook import VTableHook


_TARGET_CODE = b'\xB8\x2A\x00\x00\x00' + b'\x90' * 16 + b'\xC3'  # mov eax, 42; ret
_WORKER_LOOP = ('push rbx; sub rsp, 0x20; mov rbx, rcx; top: call qword ptr [rbx+0x18]; cmp rax, 42; je ok; lock inc qword ptr [rbx+0x10]; '
                'ok: lock inc qword ptr [rbx+8]; pause; cmp qword ptr [rbx], 0; je top; add rsp, 0x20; pop rbx; xor eax, eax; ret')  # native thread: no GIL
_kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
_kernel32.CreateThread.restype = ctypes.c_void_p
_kernel32.CreateThread.argtypes = (ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong))
_kernel32.WaitForSingleObject.argtypes = (ctypes.c_void_p, ctypes.c_ulong)
_kernel32.CloseHandle.argtypes = (ctypes.c_void_p,)


class _WorkerControl(ctypes.Structure):
    _fields_ = [('stop', ctypes.c_uint64), ('count', ctypes.c_uint64), ('wrong', ctypes.c_uint64), ('target', ctypes.c_uint64)]


_CHILD = '''
import ctypes
import os
import sys
from nylib.process import Process
from nylib import winapi

ctypes.CDLL('ucrtbase.dll')
addr = Process.current.alloc(0x1000)
Process.current.write(addr, bytes.fromhex('B82A000000') + bytes([0x90]) * 16 + bytes([0xC3]))
winapi.FlushInstructionCache(Process.current.handle, addr, 22)
slot = Process.current.alloc(0x1000, protect=0x04)
Process.current.write_ptr(slot, addr)
Process.current.virtual_protect(slot, 0x1000, 0x02)
print(os.getpid(), addr, winapi.GetCurrentThreadId(), slot, flush=True)
for line in sys.stdin:
    if line.strip() == 'hit': print(ctypes.CFUNCTYPE(ctypes.c_uint64)(Process.current.read_ptr(slot))(), flush=True)
    if line.strip() == 'exit': break
'''


class InlineCallTests(unittest.TestCase):
    def setUp(self):
        self.process = Process.current
        self.addr = self.process.alloc(0x1000)
        self.process.write(self.addr, _TARGET_CODE)
        winapi.FlushInstructionCache(self.process.handle, self.addr, len(_TARGET_CODE))
        self.target = ctypes.CFUNCTYPE(ctypes.c_uint64)(self.addr)

    def tearDown(self):
        self.process.free(self.addr)

    def test_one_hit_drains_batch_and_preserves_original(self):
        get_tid = self.process.get_proc_address('kernel32.dll', 'GetCurrentThreadId')
        muldiv = self.process.get_proc_address('kernel32.dll', 'MulDiv')
        with InlineCallQueue(self.process, self.addr, capacity=4) as hook:
            tickets = [hook.submit(get_tid), hook.submit(muldiv, 7, 9, 3), hook.submit(self.addr)]
            self.assertTrue(all(not ticket.done for ticket in tickets))
            self.assertEqual(self.target(), 42)
            self.assertEqual([ticket.wait(1000) for ticket in tickets], [winapi.GetCurrentThreadId(), 21, 42])
            self.assertEqual(self.target(), 42)

    def test_far_jump_fallback_when_near_allocation_is_unavailable(self):
        get_tid = self.process.get_proc_address('kernel32.dll', 'GetCurrentThreadId')
        original = self.process.read(self.addr, 15)
        with patch.object(self.process, 'alloc_near', side_effect=ValueError('No suitable memory region')):
            with InlineCallQueue(self.process, self.addr) as hook:
                self.assertEqual(hook.hook_code[:6], b'\xFF\x25\x00\x00\x00\x00')
                self.assertEqual(struct.unpack_from('<Q', hook.hook_code, 6)[0], hook.alloc_at)
                self.assertEqual(hook.hook_code[14], 0x90)
                self.assertEqual(len(hook.orig_code), 15)
                ticket = hook.submit(get_tid)
                self.assertEqual(self.target(), 42)
                self.assertEqual(ticket.wait(1000), winapi.GetCurrentThreadId())
                code_at = hook.alloc_at
        self.assertEqual(self.process.read(self.addr, 15), original)
        self.assertEqual(self.process.virtual_query(code_at).State, 0x10000)  # MEM_FREE

    def test_far_jump_checks_extended_prologue(self):
        self.process.write(self.addr, b'\xB8\x2A\x00\x00\x00\x48\x8B\x05\x00\x00\x00\x00' + b'\x90' * 10)
        hook = InlineCallQueue(self.process, self.addr)
        try:
            with patch.object(self.process, 'alloc_near', side_effect=ValueError('No suitable memory region')):
                with self.assertRaisesRegex(PrologueError, 'cannot relocate'):
                    hook.enabled = True
        finally:
            hook.close()

    def test_plain_inline_hook_shares_far_jump_fallback(self):
        original = self.process.read(self.addr, 15)
        with patch.object(self.process, 'alloc_near', side_effect=ValueError('No suitable memory region')):
            hook = InlineHook(self.process, b'\x90', self.addr)
            try:
                hook.enabled = True
                self.assertEqual(len(hook.hook_code), 15)
                self.assertEqual(struct.unpack_from('<Q', hook.hook_code, 6)[0], hook.alloc_at)
                self.assertEqual(self.target(), 42)
            finally:
                hook.free()
        self.assertEqual(self.process.read(self.addr, 15), original)

    def test_plain_inline_hook_rejects_jump_prologue(self):
        self.process.write(self.addr, b'\xE9\x00\x00\x00\x00' + b'\x90' * 16)
        hook = InlineHook(self.process, b'\x90', self.addr)
        try:
            with self.assertRaisesRegex(PrologueError, 'cannot relocate'):
                hook.enabled = True
        finally:
            hook.free()

    def test_timeout_capacity_and_reuse(self):
        get_tid = self.process.get_proc_address('kernel32.dll', 'GetCurrentThreadId')
        with InlineCallQueue(self.process, self.addr, capacity=2) as hook:
            first, second = hook.submit(get_tid), hook.submit(get_tid)
            with self.assertRaises(BufferError): hook.submit(get_tid)
            with self.assertRaises(TimeoutError): first.wait(0)
            self.assertEqual(self.target(), 42)
            self.assertEqual(second.wait(1000), winapi.GetCurrentThreadId())
            with self.assertRaises(BufferError): hook.submit(get_tid)
            self.assertEqual(first.wait(1000), winapi.GetCurrentThreadId())
            third = hook.submit(get_tid)
            self.assertEqual(self.target(), 42)
            self.assertEqual(third.wait(1000), winapi.GetCurrentThreadId())

    def test_mixed_register_and_stack_arguments(self):
        signature = ctypes.CFUNCTYPE(ctypes.c_double, ctypes.c_int, ctypes.c_double, ctypes.c_int,
                                     ctypes.c_float, ctypes.c_int, ctypes.c_double)
        callback = signature(lambda *values: sum(values))
        address = ctypes.cast(callback, ctypes.c_void_p).value
        with InlineCallQueue(self.process, self.addr, capacity=2) as hook:
            ticket = hook.submit(address, 1, 2.5, 3, ctypes.c_float(4), 5, 6.5, result_type=float)
            self.assertEqual(self.target(), 42)
            self.assertEqual(ticket.wait(1000), 22.0)

    def test_original_function_arguments_are_preserved(self):
        code = b'\x48\x89\xC8\x48\x01\xD0' + b'\x90' * 16 + b'\xC3'  # mov rax, rcx; add rax, rdx; ret
        self.process.write(self.addr, code)
        winapi.FlushInstructionCache(self.process.handle, self.addr, len(code))
        target = ctypes.CFUNCTYPE(ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint64)(self.addr)
        get_tid = self.process.get_proc_address('kernel32.dll', 'GetCurrentThreadId')
        with InlineCallQueue(self.process, self.addr) as hook:
            ticket = hook.submit(get_tid)
            self.assertEqual(target(11, 31), 42)
            self.assertEqual(ticket.wait(1000), winapi.GetCurrentThreadId())
            self.assertEqual(target(7, 8), 15)

    def test_close_refuses_pending_call(self):
        get_tid = self.process.get_proc_address('kernel32.dll', 'GetCurrentThreadId')
        hook = InlineCallQueue(self.process, self.addr, capacity=1)
        hook.enabled = True
        try:
            ticket = hook.submit(get_tid)
            with self.assertRaises(RuntimeError): hook.close()
            with self.assertRaises(RuntimeError): ticket.close()
            self.assertEqual(self.target(), 42)
            self.assertEqual(ticket.wait(1000), winapi.GetCurrentThreadId())
        finally:
            hook.close()

    def test_two_waiters_on_one_ticket_receive_same_result(self):
        get_tid = self.process.get_proc_address('kernel32.dll', 'GetCurrentThreadId')
        with InlineCallQueue(self.process, self.addr) as hook:
            ticket = hook.submit(get_tid)
            self.assertEqual(self.target(), 42)
            results = []
            waiters = [threading.Thread(target=lambda: results.append(ticket.wait(1000))) for _ in range(2)]
            for waiter in waiters: waiter.start()
            for waiter in waiters: waiter.join(5)
            self.assertEqual(results, [winapi.GetCurrentThreadId()] * 2)

    def test_mapping_failure_releases_local_resources(self):
        get_count = ctypes.WinDLL('kernel32.dll').GetProcessHandleCount
        get_count.argtypes = (ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulong))
        get_count.restype = ctypes.c_int
        before = ctypes.c_ulong()
        after = ctypes.c_ulong()
        self.assertTrue(get_count(winapi.GetCurrentProcess(), ctypes.byref(before)))
        with patch.object(winapi, 'NtMapViewOfSection', side_effect=OSError('mapping failed')):
            with self.assertRaisesRegex(OSError, 'mapping failed'):
                InlineCallQueue(self.process, self.addr)
        self.assertTrue(get_count(winapi.GetCurrentProcess(), ctypes.byref(after)))
        self.assertEqual(after.value, before.value)

    def test_concurrent_producer_and_single_consumer(self):
        get_tid = self.process.get_proc_address('kernel32.dll', 'GetCurrentThreadId')
        stop = threading.Event()
        ready = threading.Event()
        tids = []

        def target():
            tids.append(winapi.GetCurrentThreadId())
            ready.set()
            while not stop.is_set():
                self.target()
                time.sleep(0.0001)

        hook = InlineCallQueue(self.process, self.addr, capacity=4)
        hook.enabled = True
        worker = threading.Thread(target=target)
        worker.start()
        self.assertTrue(ready.wait(5))
        try:
            for _ in range(25):
                tickets = [hook.submit(get_tid) for _ in range(4)]
                self.assertEqual([ticket.wait(5000) for ticket in tickets], [tids[0]] * 4)
        finally:
            stop.set()
            worker.join(5)
            hook.close()
        self.assertFalse(worker.is_alive())

    def test_multiple_external_producers_publish_complete_requests(self):
        get_tid = self.process.get_proc_address('kernel32.dll', 'GetCurrentThreadId')
        tickets = []
        with InlineCallQueue(self.process, self.addr, capacity=64) as hook:
            def producer():
                for _ in range(25): tickets.append(hook.submit(get_tid))

            producers = [threading.Thread(target=producer) for _ in range(2)]
            for producer_thread in producers: producer_thread.start()
            for producer_thread in producers: producer_thread.join(5)
            self.assertTrue(all(not producer_thread.is_alive() for producer_thread in producers))
            self.assertEqual(len(tickets), 50)
            self.assertEqual(self.target(), 42)
            self.assertEqual([ticket.wait(1000) for ticket in tickets], [winapi.GetCurrentThreadId()] * 50)

    def _patch_while_helpers_exit(self, patch_action):
        stop = threading.Event()
        ready = threading.Barrier(3)
        tids = []

        def helper():
            tids.append(winapi.GetCurrentThreadId())
            ready.wait(5)
            stop.wait(30)

        helpers = [threading.Thread(target=helper) for _ in range(2)]
        for thread in helpers: thread.start()
        ready.wait(5)
        waiters = [winapi.OpenThread(0x100000, False, tid) for tid in tids]  # SYNCHRONIZE
        real_iter_threads = Process.iter_threads

        def iter_threads(process, da=0x1FFFFF):
            yield from real_iter_threads(process, da=da)
            stop.set()
            for thread in helpers: thread.join(5)
            for waiter in waiters: self.assertEqual(winapi.WaitForSingleObject(waiter, 10000), 0)

        try:
            with patch.object(Process, 'iter_threads', iter_threads):
                patch_action()
        finally:
            stop.set()
            for thread in helpers: thread.join(5)
            for waiter in waiters: winapi.CloseHandle(waiter)

    def test_quiescent_patch_skips_thread_exiting_before_suspend(self):
        get_tid = self.process.get_proc_address('kernel32.dll', 'GetCurrentThreadId')
        hook = InlineCallQueue(self.process, self.addr, quiescent_patch=True)
        try:
            ticket = hook.submit(get_tid)
            self._patch_while_helpers_exit(lambda: setattr(hook, 'enabled', True))
            self.assertTrue(hook.enabled)
            self.assertEqual(self.target(), 42)
            self.assertEqual(ticket.wait(1000), winapi.GetCurrentThreadId())
            hook.enabled = False
            with patch.object(inline_call, '_gil_exit_code', return_value=False) as query:
                with self.assertRaises(OSError) as raised:
                    self._patch_while_helpers_exit(lambda: setattr(hook, 'enabled', True))
            self.assertTrue(query.called)
            self.assertIsNotNone(raised.exception.winerror)
            self.assertFalse(hook.enabled)
            self.assertEqual(self.process.read(self.addr, len(hook.orig_code)), hook.orig_code)
        finally:
            hook.close()

    def test_rejects_relative_target_prologue(self):
        self.process.write(self.addr, b'\xE8\x00\x00\x00\x00' + b'\x90' * 16)
        hook = InlineCallQueue(self.process, self.addr)
        try:
            with self.assertRaisesRegex(PrologueError, 'cannot relocate'):
                hook.enabled = True
            self.assertTrue(issubclass(PrologueError, ValueError))
        finally:
            hook.close()

    def test_failed_patch_restores_original_code(self):
        hook = InlineCallQueue(self.process, self.addr)
        hook.alloc()
        original_flush = winapi.FlushInstructionCache
        calls = 0

        def flush(*args):
            nonlocal calls
            calls += 1
            if calls == 1: raise ctypes.WinError(5)
            return original_flush(*args)

        try:
            with patch.object(winapi, 'FlushInstructionCache', side_effect=flush):
                with self.assertRaises(OSError): hook.enabled = True
            self.assertFalse(hook.enabled)
            self.assertEqual(self.process.read(self.addr, len(hook.orig_code)), hook.orig_code)
        finally:
            hook.close()

    def test_close_releases_views_code_and_handles(self):
        get_count = ctypes.WinDLL('kernel32.dll').GetProcessHandleCount
        get_count.argtypes = (ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulong))
        get_count.restype = ctypes.c_int

        def count():
            result = ctypes.c_ulong()
            if not get_count(winapi.GetCurrentProcess(), ctypes.byref(result)): raise ctypes.WinError()
            return result.value

        before = count()
        for _ in range(10):
            hook = InlineCallQueue(self.process, self.addr)
            hook.enabled = True
            code_at, local_at, remote_at = hook.alloc_at, hook._shared.local_at, hook._shared.remote_at
            hook.close()
            self.assertEqual(self.process.virtual_query(code_at).State, 0x10000)  # MEM_FREE
            self.assertEqual(self.process.virtual_query(local_at).State, 0x10000)
            self.assertEqual(self.process.virtual_query(remote_at).State, 0x10000)
        self.assertEqual(count(), before)


class InlineCallThreadTests(unittest.TestCase):
    def setUp(self):
        self.process = Process.current
        self.addr = self.process.alloc(0x1000)
        self.process.write(self.addr, _TARGET_CODE)
        winapi.FlushInstructionCache(self.process.handle, self.addr, len(_TARGET_CODE))
        self.target = ctypes.CFUNCTYPE(ctypes.c_uint64)(self.addr)

    def tearDown(self):
        self.process.free(self.addr)

    def test_thread_filter_runs_calls_only_on_the_chosen_thread(self):
        get_tid = self.process.get_proc_address('kernel32.dll', 'GetCurrentThreadId')
        commands = queue.Queue()
        results = queue.Queue()
        tids = []
        ready = threading.Event()

        def worker():
            tids.append(winapi.GetCurrentThreadId())
            ready.set()
            while commands.get() == 'hit': results.put(self.target())

        thread = threading.Thread(target=worker)
        thread.start()
        hook = ticket = None
        try:
            self.assertTrue(ready.wait(5))
            hook = InlineCallQueue(self.process, self.addr, thread_id=tids[0])
            hook.enabled = True
            ticket = hook.submit(get_tid)
            self.assertEqual(self.target(), 42)
            self.assertFalse(ticket.done)
            with self.assertRaises(TimeoutError): ticket.wait(50)
            commands.put('hit')
            self.assertEqual(results.get(timeout=10), 42)
            self.assertEqual(ticket.wait(5000), tids[0])
            self.assertNotEqual(tids[0], winapi.GetCurrentThreadId())
            self.assertEqual(self.target(), 42)
        finally:
            commands.put('hit')
            commands.put('stop')
            thread.join(10)
            if hook is not None:
                for pending in list(hook._tickets.values()): pending.wait(5000)
                hook.close()
        self.assertFalse(thread.is_alive())

    def test_quiescent_patch_suspends_a_worker_that_keeps_entering(self):
        get_tid = self.process.get_proc_address('kernel32.dll', 'GetCurrentThreadId')
        code_at = self.process.alloc(0x1000)
        self.process.write(code_at, bytes(ks_.asm(_WORKER_LOOP, code_at, True)[0]))
        winapi.FlushInstructionCache(self.process.handle, code_at, 0x1000)
        control = _WorkerControl(0, 0, 0, self.addr)
        tid = ctypes.c_ulong()
        suspended = []
        real_suspend = inline_call._gil_suspend

        def spy(handle):
            suspended.append(winapi.GetThreadId(handle))
            return real_suspend(handle)

        def advance():
            start = control.count
            deadline = time.monotonic() + 20
            while control.count < start + 20 and time.monotonic() < deadline: time.sleep(0.001)
            self.assertGreaterEqual(control.count, start + 20)

        with contextlib.ExitStack() as cleanup:
            hook = InlineCallQueue(self.process, self.addr, quiescent_patch=True)
            handle = _kernel32.CreateThread(None, 0, code_at, ctypes.addressof(control), 0, ctypes.byref(tid))
            if not handle: raise ctypes.WinError(ctypes.get_last_error())

            def stop_worker():
                control.stop = 1
                try:
                    waited = _kernel32.WaitForSingleObject(handle, 10000)
                finally:
                    _kernel32.CloseHandle(handle)
                if waited != 0: raise AssertionError('native worker did not stop')  # its code page stays allocated
                self.process.free(code_at)

            def close_hook():
                try:
                    for pending in list(hook._tickets.values()): pending.wait(5000)
                finally:
                    hook.close()

            cleanup.callback(stop_worker)
            cleanup.callback(close_hook)
            advance()
            with patch.object(inline_call, '_gil_suspend', spy):
                hook.enabled = True
                advance()
                self.assertEqual(hook.submit(get_tid).wait(10000), tid.value)
                hook.enabled = False
                advance()
                hook.enabled = True
                advance()
                hook.close()
                advance()
        self.assertEqual(control.wrong, 0)
        self.assertIn(tid.value, suspended)


class VTableCallTests(unittest.TestCase):
    def setUp(self):
        self.process = Process.current
        self.addr = self.process.alloc(0x1000)
        self.slot = self.process.alloc(0x1000, protect=0x04)
        self.process.write(self.addr, _TARGET_CODE)
        self.process.write_ptr(self.slot, self.addr)
        self.process.virtual_protect(self.slot, 0x1000, 0x02)
        winapi.FlushInstructionCache(self.process.handle, self.addr, len(_TARGET_CODE))

    def tearDown(self):
        self.process.free(self.slot)
        self.process.free(self.addr)

    def target(self):
        return ctypes.CFUNCTYPE(ctypes.c_uint64)(self.process.read_ptr(self.slot))()

    def test_vtable_batch_jumps_to_original_and_restores_pointer(self):
        get_tid = self.process.get_proc_address('kernel32.dll', 'GetCurrentThreadId')
        original = self.process.read_ptr(self.slot)
        with VTableCallQueue(self.process, self.slot, capacity=2) as hook:
            self.assertEqual(hook.original_at, original)
            self.assertEqual(self.process.read_ptr(self.slot), hook.code_at)
            ticket = hook.submit(get_tid)
            self.assertEqual(self.target(), 42)
            self.assertEqual(ticket.wait(1000), winapi.GetCurrentThreadId())
            self.assertEqual(self.target(), 42)
        self.assertEqual(self.process.read_ptr(self.slot), original)
        self.assertEqual(self.process.virtual_query(self.slot).Protect, 0x02)

    def test_plain_vtable_hook_runs_code_then_jumps_to_original(self):
        code = b'\x48\x89\xC8\x48\x01\xD0\xC3'  # mov rax, rcx; add rax, rdx; ret
        self.process.write(self.addr, code)
        winapi.FlushInstructionCache(self.process.handle, self.addr, len(code))
        target = ctypes.CFUNCTYPE(ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint64)
        hook = VTableHook(self.process, 'inc rcx', self.slot)
        try:
            hook.enabled = True
            self.assertEqual(self.process.read_ptr(self.slot), hook.code_at)
            self.assertEqual(target(self.process.read_ptr(self.slot))(11, 30), 42)
        finally:
            hook.free()
        self.assertEqual(self.process.read_ptr(self.slot), self.addr)
        self.assertEqual(target(self.process.read_ptr(self.slot))(11, 30), 41)

    def test_rejects_changed_slot_without_overwriting_it(self):
        hook = VTableCallQueue(self.process, self.slot)
        other = self.process.get_proc_address('kernel32.dll', 'GetCurrentThreadId')
        self.process.virtual_protect(self.slot, 8, 0x04)
        self.process.write_ptr(self.slot, other)
        self.process.virtual_protect(self.slot, 8, 0x02)
        try:
            with self.assertRaisesRegex(RuntimeError, 'vtable slot changed'):
                hook.enabled = True
            self.assertFalse(hook.enabled)
            self.assertEqual(self.process.read_ptr(self.slot), other)
        finally:
            self.process.virtual_protect(self.slot, 8, 0x04)
            self.process.write_ptr(self.slot, self.addr)
            self.process.virtual_protect(self.slot, 8, 0x02)
            hook.close()

    def test_rejects_unaligned_slot(self):
        with self.assertRaisesRegex(ValueError, 'aligned'):
            VTableCallQueue(self.process, self.slot + 1)

    def test_changed_slot_on_disable_keeps_code_allocated(self):
        hook = VTableHook(self.process, b'\x90', self.slot)
        hook.enabled = True
        other = self.process.get_proc_address('kernel32.dll', 'GetCurrentThreadId')
        self.process.virtual_protect(self.slot, 8, 0x04)
        self.process.write_ptr(self.slot, other)
        self.process.virtual_protect(self.slot, 8, 0x02)
        try:
            with self.assertRaisesRegex(RuntimeError, 'vtable slot changed'):
                hook.free()
            self.assertEqual(self.process.virtual_query(hook.alloc_at).State, 0x1000)  # MEM_COMMIT
        finally:
            self.process.virtual_protect(self.slot, 8, 0x04)
            self.process.write_ptr(self.slot, hook.code_at)
            self.process.virtual_protect(self.slot, 8, 0x02)
            hook.free()

    def test_failed_control_call_keeps_installed_code_owned(self):
        hook = VTableHook(self.process, b'\x90', self.slot)
        original_call = self.process.call

        def fail_after_swap(*args):
            original_call(*args)
            raise OSError('control result unavailable')

        try:
            with patch.object(self.process, 'call', side_effect=fail_after_swap):
                with self.assertRaisesRegex(OSError, 'control result unavailable'):
                    hook.enabled = True
            self.assertTrue(hook.enabled)
            self.assertEqual(self.process.read_ptr(self.slot), hook.code_at)
        finally:
            hook.free()
        self.assertEqual(self.process.read_ptr(self.slot), self.addr)


class RemoteInlineCallTests(unittest.TestCase):
    def test_remote_batch_float_returns_and_cleanup(self):
        child = subprocess.Popen([sys.executable, '-B', '-u', '-c', _CHILD], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        process = hook = None
        try:
            pid, addr, tid, _ = map(int, child.stdout.readline().split())
            process = Process(pid)
            hook = InlineCallQueue(process, addr, capacity=4)
            hook.enabled = True
            get_tid = process.get_proc_address('kernel32.dll', 'GetCurrentThreadId')
            sqrt = process.get_proc_address('ucrtbase.dll', 'sqrt')
            sqrtf = process.get_proc_address('ucrtbase.dll', 'sqrtf')
            tickets = [hook.submit(get_tid), hook.submit(sqrt, 9.0, result_type=float),
                       hook.submit(sqrtf, ctypes.c_float(16.0), result_type=ctypes.c_float)]
            child.stdin.write('hit\n')
            child.stdin.flush()
            self.assertEqual(child.stdout.readline().strip(), '42')
            self.assertEqual([ticket.wait(5000) for ticket in tickets], [tid, 3.0, 4.0])
            hook.close()
            hook = None
            child.stdin.write('exit\n')
            child.stdin.flush()
            self.assertEqual(child.wait(5), 0)
        finally:
            if process is not None and process.still_alive():
                winapi.TerminateProcess(process.handle, 0)
            if hook is not None and not hook._tickets: hook.close()
            if process is not None: process.close()
            if child.poll() is None: child.terminate()
            child.wait(5)
            child.stdin.close()
            child.stdout.close()

    def test_target_exit_releases_local_resources_and_fails_ticket(self):
        child = subprocess.Popen([sys.executable, '-B', '-u', '-c', _CHILD], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        process = hook = None
        try:
            pid, addr, _, _ = map(int, child.stdout.readline().split())
            process = Process(pid)
            hook = InlineCallQueue(process, addr)
            hook.enabled = True
            ticket = hook.submit(process.get_proc_address('kernel32.dll', 'GetCurrentThreadId'))
            winapi.TerminateProcess(process.handle, 0)
            with self.assertRaises(ProcessLookupError): ticket.wait(1000)
            hook.close()
            with self.assertRaises(ProcessLookupError): ticket.wait(0)
            self.assertTrue(ticket.done)
        finally:
            if process is not None: process.close()
            if child.poll() is None: child.terminate()
            child.wait(5)
            child.stdin.close()
            child.stdout.close()

    def test_remote_vtable_batch_and_cleanup(self):
        child = subprocess.Popen([sys.executable, '-B', '-u', '-c', _CHILD], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        process = hook = None
        try:
            pid, addr, tid, slot = map(int, child.stdout.readline().split())
            process = Process(pid)
            hook = VTableCallQueue(process, slot, capacity=2)
            hook.enabled = True
            self.assertEqual(process.read_ptr(slot), hook.code_at)
            get_tid = process.get_proc_address('kernel32.dll', 'GetCurrentThreadId')
            sqrt = process.get_proc_address('ucrtbase.dll', 'sqrt')
            ticket, floating = hook.submit(get_tid), hook.submit(sqrt, 9.0, result_type=float)
            child.stdin.write('hit\n')
            child.stdin.flush()
            self.assertEqual(child.stdout.readline().strip(), '42')
            self.assertEqual(ticket.wait(5000), tid)
            self.assertEqual(floating.wait(5000), 3.0)
            hook.close()
            hook = None
            self.assertEqual(process.read_ptr(slot), addr)
        finally:
            if process is not None and process.still_alive():
                winapi.TerminateProcess(process.handle, 0)
            if hook is not None and not hook._tickets: hook.close()
            if process is not None: process.close()
            if child.poll() is None: child.terminate()
            child.wait(5)
            child.stdin.close()
            child.stdout.close()


if __name__ == '__main__':
    unittest.main()
