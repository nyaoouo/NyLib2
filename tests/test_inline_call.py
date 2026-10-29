import ctypes
import subprocess
import sys
import threading
import time
import unittest
from unittest.mock import patch

from nylib import winapi
from nylib.process import Process
from nylib.winutils.inline_call import InlineCallQueue


_TARGET_CODE = b'\xB8\x2A\x00\x00\x00' + b'\x90' * 16 + b'\xC3'  # mov eax, 42; ret
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
target = ctypes.CFUNCTYPE(ctypes.c_uint64)(addr)
print(os.getpid(), addr, winapi.GetCurrentThreadId(), flush=True)
for line in sys.stdin:
    if line.strip() == 'hit': print(target(), flush=True)
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

    def test_rejects_relative_target_prologue(self):
        self.process.write(self.addr, b'\xE8\x00\x00\x00\x00' + b'\x90' * 16)
        hook = InlineCallQueue(self.process, self.addr)
        try:
            with self.assertRaisesRegex(ValueError, 'cannot relocate'):
                hook.enabled = True
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


class RemoteInlineCallTests(unittest.TestCase):
    def test_remote_batch_float_returns_and_cleanup(self):
        child = subprocess.Popen([sys.executable, '-B', '-u', '-c', _CHILD], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        process = hook = None
        try:
            pid, addr, tid = map(int, child.stdout.readline().split())
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
            pid, addr, _ = map(int, child.stdout.readline().split())
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


if __name__ == '__main__':
    unittest.main()
