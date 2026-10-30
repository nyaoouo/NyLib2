import ctypes
import struct
import subprocess
import sys
import threading
import unittest
from unittest.mock import patch

from nylib import winapi
from nylib.process import Process, Thread
from nylib.process import _APCResumeError


_CHILD = '''
import ctypes
kernel32 = ctypes.WinDLL('kernel32.dll')
ctypes.CDLL('ucrtbase.dll')
print(kernel32.GetCurrentProcessId(), kernel32.GetCurrentThreadId(), flush=True)
while True:
    kernel32.SleepEx(1000, True)
'''


class ProcessCallTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.child = subprocess.Popen([sys.executable, '-B', '-u', '-c', _CHILD], stdout=subprocess.PIPE, text=True)
        cls.addClassCleanup(cls.stop_child)
        process_id, cls.thread_id = map(int, cls.child.stdout.readline().split())
        cls.process = Process(process_id)
        cls.thread = cls.process.get_thread(cls.thread_id)

    @classmethod
    def stop_child(cls):
        if getattr(cls, 'thread', None) is not None: cls.thread.close()
        if getattr(cls, 'process', None) is not None:
            winapi.TerminateProcess(cls.process.handle, 0)
            cls.process.close()
        if cls.child.poll() is None: cls.child.terminate()
        cls.child.wait(timeout=5)
        cls.child.stdout.close()

    def call(self, function, *args, **kwargs):
        address = self.process.get_proc_address('kernel32.dll', function)
        return self.process.call(address, *args, queue_apc_thread=self.thread, **kwargs)

    def test_apc_finishes_while_target_thread_stays_alive(self):
        pending = self.call('GetCurrentThreadId', block=False)
        self.assertEqual(pending.wait(5000), self.thread_id)
        self.assertTrue(pending.done)
        self.assertEqual(pending.wait(0), self.thread_id)
        self.assertEqual(winapi.WaitForSingleObject(self.thread.handle, 0), 258)

    def test_apc_blocking_arguments_and_zero_return(self):
        self.assertEqual(self.call('MulDiv', 7, 9, 3), 21)
        self.assertEqual(self.call('lstrlenA', b'hello\0'), 5)
        self.assertEqual(self.call('lstrlenA', b'\0'), 0)

    def test_apc_timeout_preserves_pending_call(self):
        pending = self.call('Sleep', 150, block=False)
        with self.assertRaises(TimeoutError):
            pending.wait(0)
        self.assertFalse(pending.done)
        pending.wait(5000)
        self.assertTrue(pending.done)

    def test_float_argument_marshalling(self):
        address = self.process.get_proc_address('ucrtbase.dll', 'sqrtf')
        for thread in (None, self.thread):
            with self.subTest(apc=thread is not None):
                pending = self.process.call(address, 9.0, queue_apc_thread=thread, block=False, read_xmm=True, get_bytes=True)
                result = pending.wait(5000)
                self.assertEqual(struct.unpack('<f', result[:4])[0], 3.0)

    def test_apc_accepts_raw_thread_handle(self):
        address = self.process.get_proc_address('kernel32.dll', 'GetCurrentThreadId')
        self.assertEqual(self.process.call(address, queue_apc_thread=self.thread.handle), self.thread_id)

    def test_default_remote_thread_calls_still_work(self):
        address = self.process.get_proc_address('kernel32.dll', 'MulDiv')
        self.assertEqual(self.process.call(address, 4, 6, 3), 8)
        pending = self.process.call(address, 5, 6, 3, block=False)
        self.assertEqual(pending.wait(5000), 10)

    def test_raw_call_passes_apc_parameter(self):
        event = winapi.CreateEvent(None, True, False, None)
        remote_event = ctypes.c_void_p()
        try:
            winapi.DuplicateHandle(winapi.GetCurrentProcess(), event, self.process.handle, ctypes.byref(remote_event), 0, False, 2)
            address = self.process.get_proc_address('kernel32.dll', 'SetEvent')
            self.process._call(address, remote_event.value, queue_apc_thread=self.thread)
            self.assertEqual(winapi.WaitForSingleObject(event, 0), 0)
        finally:
            if remote_event.value:
                winapi.DuplicateHandle(self.process.handle, remote_event, None, None, 0, False, 1)
            winapi.CloseHandle(event)

    def test_thread_lookup_and_enumeration(self):
        threads = list(self.process.iter_threads())
        try:
            self.assertIn(self.thread_id, [thread.thread_id for thread in threads])
            self.assertTrue(all(thread.process_id == self.process.process_id for thread in threads))
        finally:
            for thread in threads: thread.close()
        with self.process.get_thread(self.thread_id) as thread:
            self.assertIsInstance(thread, Thread)
        self.assertIsNone(thread.handle)
        thread.close()

    def test_thread_suspend_count_is_preserved(self):
        self.assertEqual(self.thread.suspend(), 0)
        try:
            pending = self.call('GetCurrentThreadId', block=False)
            self.assertFalse(pending.done)
        finally:
            self.assertEqual(self.thread.resume(), 1)
        self.assertEqual(pending.wait(5000), self.thread_id)

    def test_foreign_thread_is_rejected(self):
        with self.assertRaises(ValueError):
            Process.current.get_thread(self.thread_id)
        with self.assertRaises(ValueError):
            Process.current.call(winapi.GetProcAddress(winapi.GetModuleHandle('kernel32.dll'), b'GetCurrentThreadId'), queue_apc_thread=self.thread)

    def test_cannot_suspend_the_calling_thread(self):
        with Process.current.get_thread(winapi.GetCurrentThreadId()) as thread:
            with self.assertRaisesRegex(ValueError, 'calling thread'):
                Process.current.call(0, queue_apc_thread=thread)

    def test_queue_failure_resumes_thread_and_releases_memory(self):
        with patch.object(winapi, 'QueueUserAPC', side_effect=ctypes.WinError(5)), \
                patch.object(winapi, 'SuspendThread', wraps=winapi.SuspendThread) as suspend, \
                patch.object(winapi, 'ResumeThread', wraps=winapi.ResumeThread) as resume, \
                patch.object(self.process, 'free', wraps=self.process.free) as free:
            with self.assertRaises(OSError):
                self.call('GetCurrentThreadId')
            suspend.assert_called_once_with(self.thread.handle)
            resume.assert_called_once_with(self.thread.handle)
            self.assertEqual(free.call_count, 2)
        self.assertEqual(self.call('GetCurrentThreadId'), self.thread_id)

    def test_suspend_failure_does_not_resume_thread(self):
        with patch.object(winapi, 'SuspendThread', side_effect=ctypes.WinError(5)), \
                patch.object(winapi, 'QueueUserAPC') as queue, \
                patch.object(winapi, 'ResumeThread') as resume, \
                patch.object(self.process, 'free', wraps=self.process.free) as free:
            with self.assertRaises(OSError): self.call('GetCurrentThreadId')
            queue.assert_not_called()
            resume.assert_not_called()
            self.assertEqual(free.call_count, 2)

    def test_event_creation_failure_releases_call_memory(self):
        with patch.object(winapi, 'CreateEvent', side_effect=ctypes.WinError(5)), \
                patch.object(winapi, 'SuspendThread') as suspend, \
                patch.object(self.process, 'free', wraps=self.process.free) as free:
            with self.assertRaises(OSError): self.call('GetCurrentThreadId')
            suspend.assert_not_called()
            self.assertEqual(free.call_count, 1)

    def test_completed_calls_release_local_and_remote_handles(self):
        get_count = ctypes.WinDLL('kernel32.dll').GetProcessHandleCount
        get_count.argtypes = (ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulong))
        get_count.restype = ctypes.c_int

        def count(handle):
            result = ctypes.c_ulong()
            if not get_count(handle, ctypes.byref(result)): raise ctypes.WinError()
            return result.value

        self.call('GetCurrentThreadId')
        before = count(winapi.GetCurrentProcess()), count(self.process.handle)
        with patch.object(self.process, 'free', wraps=self.process.free) as free:
            for _ in range(20): self.assertEqual(self.call('GetCurrentThreadId'), self.thread_id)
            self.assertEqual(free.call_count, 40)
        self.assertEqual((count(winapi.GetCurrentProcess()), count(self.process.handle)), before)

    def test_resume_failure_retains_queued_code(self):
        original_alloc = self.process.alloc
        original_free = self.process.free
        original_duplicate = winapi.DuplicateHandle
        allocations, remote_events = [], []

        def allocate(*args, **kwargs):
            address = original_alloc(*args, **kwargs)
            allocations.append(address)
            return address

        def duplicate(*args):
            result = original_duplicate(*args)
            if args[2] == self.process.handle and args[-1] == 2:
                remote_events.append(args[3]._obj.value)
            return result

        with patch.object(winapi, 'ResumeThread', side_effect=ctypes.WinError(5)), \
                patch.object(winapi, 'DuplicateHandle', side_effect=duplicate), \
                patch.object(self.process, 'alloc', side_effect=allocate), \
                patch.object(self.process, 'free', wraps=original_free) as free:
            with self.assertRaises(_APCResumeError):
                self.call('GetCurrentThreadId')
            free.assert_not_called()
        # The callback remains queued on the suspended thread until it is resumed.
        self.thread.resume()
        self.assertEqual(self.call('GetCurrentThreadId'), self.thread_id)
        for event in remote_events:
            winapi.DuplicateHandle(self.process.handle, event, None, None, 0, False, 1)
        for address in allocations: original_free(address)

    def test_thread_snapshot_is_closed_on_early_exit(self):
        with patch.object(winapi, 'CloseHandle', wraps=winapi.CloseHandle) as close:
            iterator = self.process.iter_threads()
            thread = next(iterator)
            iterator.close()
            self.assertEqual(close.call_count, 1)
            thread.close()

    def test_empty_thread_snapshot_is_closed(self):
        with patch.object(winapi, 'Thread32First', side_effect=ctypes.WinError(18)), \
                patch.object(winapi, 'CloseHandle', wraps=winapi.CloseHandle) as close:
            self.assertEqual(list(self.process.iter_threads()), [])
            close.assert_called_once()

    def test_thread_snapshot_errors_are_propagated(self):
        with patch.object(winapi, 'Thread32First', side_effect=ctypes.WinError(5)), \
                patch.object(winapi, 'CloseHandle', wraps=winapi.CloseHandle) as close:
            with self.assertRaises(OSError): list(self.process.iter_threads())
            close.assert_called_once()

    def test_thread_scan_skips_threads_that_exit_after_the_snapshot(self):
        stop = threading.Event()
        helpers = [threading.Thread(target=stop.wait) for _ in range(8)]
        for helper in helpers: helper.start()
        threads = []
        try:
            iterator = Process.current.iter_threads(da=0x0800)  # THREAD_QUERY_LIMITED_INFORMATION
            first = next(iterator)  # the snapshot is taken here and lists the helpers
            threads.append(first)
            stop.set()
            for helper in helpers: helper.join(5)
            threads.extend(iterator)
            self.assertIn(threading.get_native_id(), {thread.thread_id for thread in threads})
        finally:
            stop.set()
            for thread in threads: thread.close()

    def test_thread_scan_skips_reused_thread_ids_but_raises_other_errors(self):
        with patch.object(winapi, 'GetProcessIdOfThread', return_value=0):
            self.assertEqual(list(Process.current.iter_threads(da=0x0800)), [])
        with patch.object(winapi, 'OpenThread', side_effect=ctypes.WinError(5)):
            with self.assertRaises(OSError) as raised: list(Process.current.iter_threads(da=0x0800))
            self.assertEqual(raised.exception.winerror, 5)

    def test_current_process_apc_uses_selected_thread(self):
        stop = threading.Event()
        ready = threading.Event()
        thread_ids = []
        sleep_ex = ctypes.WinDLL('kernel32.dll').SleepEx
        sleep_ex.argtypes = (ctypes.c_ulong, ctypes.c_bool)

        def target():
            thread_ids.append(winapi.GetCurrentThreadId())
            ready.set()
            while not stop.is_set(): sleep_ex(10, True)

        worker = threading.Thread(target=target)
        worker.start()
        self.assertTrue(ready.wait(5))
        try:
            with Process.current.get_thread(thread_ids[0]) as thread:
                address = Process.current.get_proc_address('kernel32.dll', 'GetCurrentThreadId')
                pending = Process.current.call(address, queue_apc_thread=thread, block=False)
                self.assertEqual(pending.wait(5000), thread_ids[0])
                callback = ctypes.CFUNCTYPE(ctypes.c_double)(lambda: 3.5)
                result = Process.current.call(ctypes.cast(callback, ctypes.c_void_p).value,
                                              queue_apc_thread=thread, read_xmm=True, get_bytes=True)
                self.assertEqual(struct.unpack('<d', result)[0], 3.5)
        finally:
            stop.set()
            worker.join(5)
        self.assertFalse(worker.is_alive())


if __name__ == '__main__':
    unittest.main()
