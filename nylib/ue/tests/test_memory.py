import contextlib
import ctypes
import decimal
import fractions
import random
import subprocess
import sys
import threading
import time
import unittest
from unittest import mock

from nylib.process import Process
from nylib.ue import memory as memory_module
from nylib.ue.errors import MemoryReadError, MemoryWriteError, TargetError
from nylib.ue.memory import (
    MEM_COMMIT, MEM_FREE, MEM_PRIVATE, PAGE_EXECUTE_READ, PAGE_GUARD, PAGE_NOACCESS, PAGE_READONLY, PAGE_READWRITE,
    USER_MAX, USER_MIN,
    PROCESS_CREATE_THREAD, PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE,
    ProcessSource, Region, current_process, handle_rights, open_process,
)

PAGE = 0x1000
PAYLOAD = b'NYLIBUE' + bytes((i * 37 + 11) & 0xFF for i in range(0x4000))
CHILD = (
    'import ctypes, os, sys\n'
    "buf = ctypes.create_string_buffer(b'NYLIBUE' + bytes((i * 37 + 11) & 0xFF for i in range(0x4000)))\n"
    "print(f'{os.getpid()} {ctypes.addressof(buf)}', flush=True)\n"
    'sys.stdin.read()\n'
)

_k32 = ctypes.WinDLL('kernel32', use_last_error=True)
_k32.GetHandleInformation.argtypes = (ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulong))
_k32.GetHandleInformation.restype = ctypes.c_int
_k32.CloseHandle.argtypes = (ctypes.c_void_p,)
_k32.CloseHandle.restype = ctypes.c_int
_k32.GetProcessHandleCount.argtypes = (ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulong))
_k32.GetProcessHandleCount.restype = ctypes.c_int
_k32.GetCurrentProcess.restype = ctypes.c_void_p


def _handle_valid(handle) -> bool:
    return bool(_k32.GetHandleInformation(handle, ctypes.byref(ctypes.c_ulong())))


def _own_handle_count() -> int:
    count = ctypes.c_ulong()
    assert _k32.GetProcessHandleCount(_k32.GetCurrentProcess(), ctypes.byref(count))
    return count.value


class _Spy:
    """Counts read / virtual_query calls on one Process object through instance attributes."""

    def __init__(self, process=None):
        self.process = process or Process(Process.current.process_id, Process.current.handle)
        self.reads = []
        self.queries = 0
        read, query = self.process.read, self.process.virtual_query

        def spy_read(address, type_, **kwargs):
            self.reads.append((address, type_))
            return read(address, type_, **kwargs)

        def spy_query(address):
            self.queries += 1
            return query(address)

        self.process.read = spy_read
        self.process.virtual_query = spy_query

    def reads_touching(self, lo, hi):
        return [(a, n) for a, n in self.reads if a < hi and a + n > lo]


class _Child:
    """A child python holding PAYLOAD at .addr; killed and its handles closed on exit."""

    def __enter__(self):
        self.handles = []
        self.popen = subprocess.Popen([getattr(sys, '_base_executable', sys.executable), '-c', CHILD],
                                      stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        try:
            pid, addr = self.popen.stdout.readline().split()
        except BaseException:
            self.kill()
            raise
        self.pid, self.addr = int(pid), int(addr)
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


class _OwnMemory(unittest.TestCase):
    def setUp(self):
        self.cp = current_process()
        self._allocs = []

    def tearDown(self):
        for a in self._allocs:
            with contextlib.suppress(OSError):
                Process.current.free(a)

    def alloc(self, size, protect=PAGE_READWRITE, address=0):
        a = Process.current.alloc(size, protect=protect, address=address)
        self._allocs.append(a)
        return a

    def filled(self, size, seed=0):
        a = self.alloc(size)
        data = random.Random(seed).randbytes(size)
        self.cp.write(a, data)
        return a, data


class OpenProcessTests(unittest.TestCase):
    def test_rights(self):
        self.assertEqual((PROCESS_CREATE_THREAD, PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE, PROCESS_QUERY_INFORMATION),
                         (0x0002, 0x0008, 0x0010, 0x0020, 0x0400))
        self.assertEqual(handle_rights(), 0x0410)
        self.assertEqual(handle_rights(write=True), 0x0438)
        self.assertEqual(handle_rights(remote_calls=True), 0x043A)
        self.assertEqual(handle_rights(write=True, remote_calls=True), 0x043A)
        self.assertEqual(handle_rights(write=0, remote_calls=''), 0x0410)
        with self.assertRaises(TypeError):
            handle_rights(True)

    def test_read_only_handle(self):
        with _Child() as child:
            self.assertEqual(ProcessSource(child.open()).read(child.addr, 7), b'NYLIBUE')
            p = child.open()
            with self.assertRaises(OSError):
                p.write(child.addr, b'X')
            self.assertEqual(p.read(child.addr, 7, strict=True), b'NYLIBUE')

    def test_write_handle(self):
        with _Child() as child:
            p = child.open(write=True)
            p.write(child.addr, b'X')
            self.assertEqual(p.read(child.addr, 7, strict=True), b'XYLIBUE')

    def test_errors(self):
        for pid in (0, -4):
            with self.assertRaises(TargetError) as cm:
                open_process(pid)
            self.assertEqual((cm.exception.target, cm.exception.reason), (pid, 'invalid pid'))
        with self.assertRaises(TargetError) as cm:
            open_process(3)
        self.assertEqual(cm.exception.reason, 'OpenProcess failed: winerror 87')
        for bad in ('1', 1.0, None):
            with self.assertRaises(TypeError):
                open_process(bad)
        with _Child() as child:
            child.kill()
            before = _own_handle_count()
            with self.assertRaises(TargetError) as cm:
                open_process(child.pid)
            self.assertEqual((cm.exception.target, cm.exception.reason), (child.pid, 'process has exited'))
            self.assertEqual(_own_handle_count(), before)  # the handle opened on the dead process was closed

    def test_errors_close_the_handle(self):
        made = []

        class Exited(Process):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                self.da = kwargs.get('da')
                made.append(self)

            def still_alive(self):
                return False

        class Denied(Exited):
            def still_alive(self):
                raise ctypes.WinError(5)

        for cls, reason, kwargs, da in ((Exited, 'process has exited', {}, 0x0410),
                                        (Exited, 'process has exited', {'write': True}, 0x0438),
                                        (Denied, 'cannot query process: winerror 5', {'remote_calls': True}, 0x043A)):
            made.clear()
            with mock.patch.object(memory_module, 'Process', cls):
                with self.assertRaises(TargetError) as cm:
                    open_process(Process.current.process_id, **kwargs)
            self.assertEqual(cm.exception.reason, reason)
            self.assertEqual([(m.da, m.handle) for m in made], [(da, None)])

    def test_current(self):
        cp = current_process()
        self.assertIs(cp, current_process())
        self.assertIsNot(cp, Process.current)
        self.assertEqual((cp.process_id, cp.handle), (Process.current.process_id, Process.current.handle))
        with self.assertRaises(OSError):
            cp.read(0x10, 8, strict=True)
        buf = ctypes.create_string_buffer(b'own bytes')
        self.assertEqual(cp.read(ctypes.addressof(buf), 9, strict=True), b'own bytes')
        g = Process.current.alloc(PAGE, protect=PAGE_READWRITE)
        try:
            s = ProcessSource(cp)
            s.regions()  # the map still says readable when the guard is set
            Process.current.virtual_protect(g, PAGE, PAGE_READWRITE | PAGE_GUARD)
            with self.assertRaises(OSError):
                cp.read(g, 1, strict=True)
            self.assertTrue(Process.current.virtual_query(g).Protect & PAGE_GUARD)  # a string_at read would consume it
            with self.assertRaises(MemoryReadError):
                s.read(g, 1)
            self.assertTrue(Process.current.virtual_query(g).Protect & PAGE_GUARD)
        finally:
            Process.current.free(g)

    def test_current_thread_safety(self):
        # two threads racing current_process(): under the lock, the second must block until the first
        # finishes constructing and observe the cached object, never construct its own.
        orig, memory_module._current = memory_module._current, None
        started, proceed, calls, results = threading.Event(), threading.Event(), [], []

        class SlowProcess(Process):
            def __init__(self, *a, **kw):
                calls.append(1)
                if len(calls) == 1:
                    started.set()
                    proceed.wait(1)
                super().__init__(*a, **kw)

        def worker1():
            results.append(current_process())

        def worker2():
            started.wait(1)
            results.append(current_process())
            proceed.set()

        try:
            with mock.patch.object(memory_module, 'Process', SlowProcess):
                t1, t2 = threading.Thread(target=worker1), threading.Thread(target=worker2)
                t1.start()
                t2.start()
                t1.join()
                t2.join()
        finally:
            memory_module._current = orig
        self.assertEqual(len(calls), 1)  # only one Process was ever constructed
        self.assertIs(results[0], results[1])

    def test_close(self):
        with _Child() as child:
            p = open_process(child.pid)
            h = p.handle
            self.assertTrue(_handle_valid(h))
            p.close()
            self.assertIsNone(p.handle)
            self.assertFalse(_handle_valid(h))
            with self.assertRaises(OSError):
                p.read(child.addr, 7, strict=True)
            p.close()
            self.assertIsNone(p.handle)

            q = child.open()
            h = q.handle
            self.assertTrue(_k32.CloseHandle(h))  # closed behind its back, so Process.close gets an error
            with self.assertRaises(OSError):
                q.close()
            self.assertIsNone(q.handle)

        buf = ctypes.create_string_buffer(b'still here')
        for p in (current_process(), Process.current):
            p.close()
            self.assertEqual(p.handle, 0xFFFFFFFFFFFFFFFF)
        self.assertEqual(current_process().read(ctypes.addressof(buf), 10, strict=True), b'still here')
        self.assertEqual(ProcessSource(current_process()).read(ctypes.addressof(buf), 10), b'still here')


class ProcessSourceTests(_OwnMemory):
    def test_rejects(self):
        with self.assertRaises(ValueError) as cm:
            ProcessSource(Process.current)
        self.assertIn('current_process()', str(cm.exception))

        class IntLike:  # passes the range checks, so only the type check can reject it
            __lt__ = lambda self, other: False
            __and__ = lambda self, other: 0
            __sub__ = lambda self, other: self

        for kwargs, exc in (
                ({'page_size': IntLike()}, TypeError),
                ({'page_size': 0x3000}, ValueError), ({'page_size': 0x800}, ValueError), ({'page_size': 0}, ValueError),
                ({'page_size': 'x'}, TypeError), ({'page_size': 4096.0}, TypeError),
                ({'max_cache_bytes': 0x100}, ValueError), ({'page_size': 0x2000, 'max_cache_bytes': 0x1FFF}, ValueError),
                ({'max_cache_bytes': 'x'}, TypeError), ({'max_cache_bytes': 65536.0}, TypeError),
                ({'requery_interval': -1}, ValueError), ({'requery_interval': -0.001}, ValueError),
                ({'requery_interval': float('nan')}, ValueError), ({'requery_interval': 'x'}, TypeError),
                ({'requery_interval': None}, TypeError), ({'requery_interval': decimal.Decimal('0.25')}, TypeError),
                ({'requery_interval': fractions.Fraction(1, 4)}, TypeError),
        ):
            with self.subTest(kwargs=kwargs), self.assertRaises(exc):
                ProcessSource(self.cp, **kwargs)
        for args, kwargs, exc in (  # checks run in the F3 order
                ((Process.current,), {'page_size': 'x'}, ValueError),
                ((self.cp,), {'page_size': 'x', 'max_cache_bytes': 0x100}, TypeError),
                ((self.cp,), {'page_size': 0x3000, 'max_cache_bytes': 'x'}, ValueError),
                ((self.cp,), {'max_cache_bytes': 'x', 'requery_interval': -1}, TypeError),
                ((self.cp,), {'max_cache_bytes': 0x100, 'requery_interval': 'x'}, ValueError),
        ):
            with self.subTest(kwargs=kwargs), self.assertRaises(exc):
                ProcessSource(*args, **kwargs)
        for kwargs in ({'page_size': 0x1000}, {'page_size': 0x1000, 'max_cache_bytes': 0x1000},
                       {'requery_interval': 0}, {'requery_interval': float('inf')}, {'cache': 0}):
            s = ProcessSource(self.cp, **kwargs)
            self.assertIs(s.process, self.cp)
        self.assertIs(ProcessSource(self.cp, cache='').cache, False)
        self.assertIs(ProcessSource(self.cp, cache=[1]).cache, True)
        self.assertEqual(ProcessSource(self.cp).page_size, 0x10000)
        lazy = ProcessSource(object())  # the constructor never touches the target
        with self.assertRaises(AttributeError):
            lazy.read(USER_MIN, 1)

    def test_ctor_rejects_by_identity_not_equality(self):
        class AlwaysEqual:  # equal to anything by __eq__, but never identical to Process.current
            def __eq__(self, other):
                return True

            def __hash__(self):
                return 0

        impostor = AlwaysEqual()
        self.assertIsNot(impostor, Process.current)
        self.assertEqual(impostor, Process.current)  # sanity: equal, but not the same object
        s = ProcessSource(impostor)  # only identity is checked, so this must not raise
        self.assertIs(s.process, impostor)

    def test_query_span_uses_mbi_region_end(self):
        class _FakeMbi:
            def __init__(self, base, size):
                self.BaseAddress, self.RegionSize = base, size

        class _FakeProcess:
            def __init__(self):
                self.calls = []

            def virtual_query(self, addr):
                self.calls.append(addr)
                # like real VirtualQuery: the region containing addr may start well before it
                return _FakeMbi(addr - 0x1000, 0x3000)

        stub = type('Stub', (), {})()
        stub.process = _FakeProcess()
        mbis = list(ProcessSource._query_span(stub, 0x1000, 0x5000))
        self.assertEqual([(m.BaseAddress, m.RegionSize) for m in mbis], [(0, 0x3000), (0x2000, 0x3000)])
        self.assertEqual(stub.process.calls, [0x1000, 0x3000])  # each step resumes at the mbi's own end

    def test_map_walk_only_suppresses_oserror(self):
        class Boom(Exception):
            pass

        def bad_iter(lo, hi):
            yield from ()
            raise Boom('not an OSError')

        p = Process(Process.current.process_id, Process.current.handle)
        p.iter_memory_region = bad_iter
        with self.assertRaises(Boom):
            ProcessSource(p).regions()

    def test_runs_clips_to_user_max(self):
        s = ProcessSource(self.cp, requery_interval=0)
        s.regions()
        st = s._state
        # Pretend the top of user space is one committed, readable region (an edge case a real host may hit).
        top = Region(USER_MAX - PAGE, PAGE, PAGE_READWRITE, MEM_COMMIT, MEM_PRIVATE)
        st.regions, st.bases, st.stamps = [top], [top.base], [float('inf')]
        for addr in (USER_MAX, USER_MAX + 0x10000, (1 << 64) - 8):
            self.assertEqual(s._runs(addr, addr + 8), [], hex(addr))

    def test_bypass_creates_no_pages(self):
        a, data = self.filled(3 * PAGE, seed=20)
        spy = _Spy()
        s = ProcessSource(spy.process, page_size=PAGE, max_cache_bytes=2 * PAGE)
        self.assertEqual(s.read(a, 3 * PAGE), data)  # touches 3 pages > the 2-page cap: bypass
        self.assertEqual(s._state.pages, {})  # the bypass must not create or use page records
        before = len(spy.reads)
        self.assertEqual(s.read(a, 8), data[:8])
        self.assertEqual(len(spy.reads), before + 1)  # still not cached

    def test_write_oserror_requeries(self):
        a = self.alloc(PAGE)
        spy = _Spy()
        orig_write = spy.process.write
        calls = []

        def fail_once(address, data):
            calls.append((address, data))
            if len(calls) == 1:
                raise ctypes.WinError(5)
            return orig_write(address, data)

        spy.process.write = fail_once
        s = ProcessSource(spy.process)
        s.regions()
        spy.queries = 0
        with self.assertRaises(MemoryWriteError) as cm:
            s.write(a, b'X')
        self.assertEqual(cm.exception.reason, 'winerror 5')
        self.assertEqual(spy.queries, 2)  # the pre-write re-query, plus the post-failure re-query

    def _holes(self):
        a = self.alloc(3 * PAGE)
        data = random.Random(1).randbytes(3 * PAGE)
        self.cp.write(a, data)
        Process.current.virtual_protect(a + PAGE, PAGE, PAGE_NOACCESS)
        Process.current.virtual_protect(a + 2 * PAGE, PAGE, PAGE_READWRITE | PAGE_GUARD)
        return a, data

    def _hole_sources(self, process):
        for cache in (True, False):
            for interval in (0.25, 0):
                yield ProcessSource(process, cache=cache, requery_interval=interval)

    def test_holes(self):
        a, data = self._holes()
        for s in self._hole_sources(self.cp):
            with self.subTest(cache=s.cache):
                self.assertEqual(s.read(a, PAGE), data[:PAGE])
                self.assertEqual(s.read(a + PAGE - 8, 8), data[PAGE - 8:PAGE])
                with self.assertRaises(MemoryReadError) as cm:
                    s.read(a + 0xFF0, 0x20)
                self.assertEqual(cm.exception.reason, f'unreadable at {a + PAGE:#x}')
                self.assertEqual(s.readable_ranges(a, 3 * PAGE), [(a, PAGE)])
                self.assertIsNone(s.try_read(a + 2 * PAGE, 8))
                self.assertIsNone(s.try_read(a + PAGE, 1))
                self.assertTrue(s.readable(a + PAGE - 1, 1))
                self.assertFalse(s.readable(a + PAGE - 1, 2))
                self.assertFalse(s.readable(a + 2 * PAGE, 8))

    def test_no_syscall_into_holes(self):
        a, data = self._holes()
        spy = _Spy()
        for s in self._hole_sources(spy.process):
            s.read(a, PAGE)
            with contextlib.suppress(MemoryReadError):
                s.read(a + 0xFF0, 0x20)
            s.readable_ranges(a, 3 * PAGE)
            s.try_read(a + 2 * PAGE, 8)
            s.try_read(a + PAGE, 1)
            s.readable(a + 2 * PAGE, 8)
        self.assertGreaterEqual(len(spy.reads_touching(a, a + PAGE)), 4)  # the spy does see the reads
        self.assertEqual(spy.reads_touching(a + PAGE, a + 3 * PAGE), [])

    def test_adjacent_protections(self):
        a, data = self.filled(2 * PAGE, seed=2)
        Process.current.virtual_protect(a + PAGE, PAGE, PAGE_READONLY)
        for cache in (False, True):
            s = ProcessSource(self.cp, cache=cache)
            with self.subTest(cache=cache):
                regions = {r.base: r for r in s.regions()}
                self.assertEqual((regions[a].size, regions[a].protect), (PAGE, PAGE_READWRITE))
                self.assertEqual((regions[a + PAGE].size, regions[a + PAGE].protect), (PAGE, PAGE_READONLY))
                self.assertTrue(s.readable(a, 2 * PAGE))
                self.assertTrue(s.valid_ptr(a, 2 * PAGE))
                self.assertEqual(s.readable_ranges(a, 2 * PAGE), [(a, 2 * PAGE)])
                self.assertEqual(s.read(a, 2 * PAGE), data)
                self.assertEqual(s.read(a + PAGE - 4, 8), data[PAGE - 4:PAGE + 4])

    def test_map_covers_user_space(self):
        a, _ = self.filled(PAGE, seed=3)
        regions = ProcessSource(self.cp).regions()
        self.assertEqual(regions[0].base, 0)
        self.assertEqual(regions[-1].end, USER_MAX)
        self.assertTrue(all(r.end == n.base and r.size > 0 for r, n in zip(regions, regions[1:])))
        s = ProcessSource(self.cp)
        self.assertIsNot(s.regions(), s.regions())  # callers get a copy
        own = next(r for r in regions if r.base == a)
        self.assertEqual((own.size, own.protect, own.readable, own.writable), (PAGE, PAGE_READWRITE, True, True))

    def test_cache(self):
        a, data = self.filled(PAGE, seed=4)
        expected = [int.from_bytes(data[i * 4 % PAGE:i * 4 % PAGE + 4], 'little') for i in range(1000)]
        for cache, calls in ((True, 1), (False, 1000)):
            spy = _Spy()
            s = ProcessSource(spy.process, cache=cache)
            self.assertEqual([s.u32(a + i * 4 % PAGE) for i in range(1000)], expected)
            self.assertEqual(len(spy.reads), calls, f'cache={cache}')

    def test_snapshot_semantics(self):
        a = self.alloc(PAGE)
        self.cp.write(a, b'OLDBYTES')
        s = ProcessSource(self.cp)
        self.assertEqual(s.read(a, 8), b'OLDBYTES')
        self.cp.write(a, b'NEWBYTES')
        self.assertEqual(s.read(a, 8), b'OLDBYTES')
        self.assertEqual(s.read(a + 4, 4), b'YTES')
        s.refresh()
        self.assertEqual(s.read(a, 8), b'NEWBYTES')

    def test_fresh_bypasses_cache(self):
        a = self.alloc(PAGE)
        self.cp.write(a, b'OLDBYTES')
        s = ProcessSource(self.cp)
        self.assertEqual(s.read(a, 8), b'OLDBYTES')
        self.cp.write(a, b'NEWBYTES')
        self.assertEqual(s.fresh.read(a, 8), b'NEWBYTES')
        self.assertEqual(s.read(a, 8), b'OLDBYTES')
        fresh = s.fresh
        self.assertIs(s.fresh, fresh)
        self.assertIs(fresh.fresh, fresh)
        self.assertIsNot(fresh, s)
        self.assertIs(fresh.cache, False)
        self.assertIs(fresh.process, s.process)
        fresh.refresh()  # drops the sibling's pages too
        self.assertEqual(s.read(a, 8), b'NEWBYTES')
        u = ProcessSource(self.cp, cache=False)
        self.assertIs(u.fresh, u)

    def test_fresh_shares_the_map(self):
        spy = _Spy()
        s = ProcessSource(spy.process)
        s.regions()
        spy.queries = 0
        s.fresh.regions()
        s.fresh.readable(USER_MIN, 8)
        self.assertEqual(spy.queries, 0)

    def test_self_heal(self):
        s = ProcessSource(self.cp, requery_interval=0)
        stale = ProcessSource(self.cp, requery_interval=float('inf'))
        before = s.regions()
        stale.regions()
        new = self.alloc(PAGE)
        self.cp.write(new, b'HEALTEST')
        self.assertFalse(next(r for r in before if r.base <= new < r.end).readable)
        self.assertFalse(stale.readable(new, 8))  # never re-queried
        self.assertTrue(s.readable(new, 8))
        self.assertEqual(s.read(new, 8), b'HEALTEST')
        self.assertEqual(s.fresh.read(new, 8), b'HEALTEST')
        stale.refresh()  # drops the region map
        self.assertTrue(stale.readable(new, 8))

    def test_self_heal_cached_read_first(self):
        s = ProcessSource(self.cp, requery_interval=0)
        s.regions()
        new = self.alloc(PAGE)
        self.cp.write(new, b'HEALREAD')
        self.assertEqual(s.read(new, 8), b'HEALREAD')

    def test_hole_refill(self):
        a, data = self.filled(3 * PAGE, seed=9)
        Process.current.virtual_protect(a + PAGE, PAGE, PAGE_NOACCESS)
        spy = _Spy()
        s = ProcessSource(spy.process, requery_interval=0)
        self.assertEqual(s.read(a, 8), data[:8])  # the page record now has a hole at a + PAGE
        self.assertIsNone(s.try_read(a + PAGE, 8))
        with self.assertRaises(MemoryReadError) as cm:
            s.read(a + PAGE - 8, PAGE + 16)  # bytes present on both sides of the hole
        self.assertEqual(cm.exception.reason, f'unreadable at {a + PAGE:#x}')
        Process.current.virtual_protect(a + PAGE, PAGE, PAGE_READWRITE)
        before = len(spy.reads)
        self.assertEqual(s.read(a + PAGE + 8, 8), data[PAGE + 8:PAGE + 16])
        self.assertEqual(spy.reads[before:], [(a + PAGE + 8, 8)])  # only the missing bytes of the read are fetched
        self.assertEqual(s.read(a + PAGE + 8, 8), data[PAGE + 8:PAGE + 16])
        self.assertEqual(s.read(a + 2 * PAGE, 8), data[2 * PAGE:2 * PAGE + 8])
        self.assertEqual(len(spy.reads), before + 1)
        self.assertEqual(s.read(a + PAGE, 16), data[PAGE:PAGE + 16])  # [a + PAGE, +8) was never fetched
        self.assertEqual(spy.reads[before + 1:], [(a + PAGE, 8)])

    def test_stale_map_cached(self):
        a, data = self.filled(4 * PAGE, seed=13)
        spy = _Spy()
        s = ProcessSource(spy.process)
        s.regions()  # one RW region in the map
        Process.current.virtual_protect(a + 2 * PAGE, PAGE, PAGE_NOACCESS)
        self.assertEqual(s.try_read(a, 4), data[:4])
        self.assertIsNone(s.try_read(a + 2 * PAGE, 4))
        self.assertEqual(s.read(a + 3 * PAGE, 4), data[3 * PAGE:3 * PAGE + 4])
        with self.assertRaises(MemoryReadError) as cm:
            s.read(a + 2 * PAGE - 4, 8)
        self.assertEqual(cm.exception.reason, f'unreadable at {a + 2 * PAGE:#x}')
        # the stale run fails once, then only the runs the re-query found readable are fetched
        self.assertEqual(spy.reads, [(a, 4 * PAGE), (a, 2 * PAGE), (a + 3 * PAGE, PAGE)])

    def test_read_starting_in_hole(self):
        a, data = self.filled(2 * PAGE, seed=14)
        Process.current.virtual_protect(a, PAGE, PAGE_NOACCESS)
        for cache in (False, True):
            spy = _Spy()
            s = ProcessSource(spy.process, cache=cache)
            with self.subTest(cache=cache):
                with self.assertRaises(MemoryReadError) as cm:
                    s.read(a + PAGE - 1, 2)
                self.assertEqual(cm.exception.reason, f'unreadable at {a + PAGE - 1:#x}')
                self.assertEqual(spy.reads, [(a + PAGE, PAGE)] if cache else [])  # the cached fill fetches only the readable page

    def test_heal_adjacent_regions(self):
        a, data = self.filled(3 * PAGE, seed=11)
        Process.current.virtual_protect(a, PAGE, PAGE_NOACCESS)
        Process.current.virtual_protect(a + PAGE, PAGE, PAGE_READWRITE | PAGE_GUARD)
        s = ProcessSource(self.cp, requery_interval=0)
        self.assertEqual(s.readable_ranges(a, 3 * PAGE), [(a + 2 * PAGE, PAGE)])
        Process.current.virtual_protect(a, 2 * PAGE, PAGE_READWRITE)
        self.assertEqual(s.readable_ranges(a, 3 * PAGE), [(a, 3 * PAGE)])  # both unreadable regions were re-walked
        self.assertEqual(s.read(a, 3 * PAGE), data)

    def test_self_heal_twice(self):
        s = ProcessSource(self.cp, requery_interval=0)
        free = max((r for r in s.regions() if r.state == MEM_FREE and r.base >= USER_MIN), key=lambda r: r.size)
        a = (free.base + free.size // 2) & ~0xFFFF
        b = a + 0x80000
        self.assertLessEqual(b + PAGE, free.end)
        self.assertEqual(self.alloc(PAGE, address=a), a)
        self.assertTrue(s.readable(a, 8))
        self.assertEqual(self.alloc(PAGE, address=b), b)
        self.assertTrue(s.readable(b, 8))
        self.assertTrue(s.readable(a, 8))
        self.assertFalse(s.readable(a + 0x40000, 8))
        self.assertFalse(s.readable(a + PAGE, 8))
        regions = s.regions()
        self.assertTrue(all(r.end == n.base for r, n in zip(regions, regions[1:])))
        self.assertEqual({r.base: r.size for r in regions if r.readable and free.base <= r.base < free.end}, {a: PAGE, b: PAGE})

    def test_requery_throttle(self):
        a, _ = self.filled(PAGE, seed=5)
        spy = _Spy()
        free = next(r for r in ProcessSource(self.cp).regions() if r.state == MEM_FREE and r.base >= USER_MIN and r.size >= 0x10000)
        target = free.base + PAGE
        for interval, check in ((60, lambda n: self.assertEqual(n, 0)), (0, lambda n: self.assertGreaterEqual(n, 100))):
            s = ProcessSource(spy.process, requery_interval=interval)
            s.regions()
            spy.queries = 0
            self.assertFalse(any(s.readable(target, 8) for _ in range(100)))
            check(spy.queries)
        s = ProcessSource(spy.process, requery_interval=0)
        s.regions()
        spy.queries = 0
        for _ in range(100):
            s.readable(a, 8)  # readable regions are never re-queried by the heal
        self.assertEqual(spy.queries, 0)
        s = ProcessSource(spy.process, requery_interval=0.5)
        s.regions()
        time.sleep(0.6)
        spy.queries = 0
        s.readable(target, 8)
        self.assertGreaterEqual(spy.queries, 1)  # the throttle expires
        spy.queries = 0
        s.readable(target, 8)
        self.assertEqual(spy.queries, 0)  # and the healed regions are stamped anew

    def test_above_user_max(self):
        spy = _Spy()
        for cache in (True, False):
            s = ProcessSource(spy.process, cache=cache, requery_interval=0)
            s.regions()
            spy.queries = 0
            for addr in (USER_MAX, USER_MAX + 0x10000, 1 << 63, (1 << 64) - 8):
                with self.assertRaises(MemoryReadError) as cm:
                    s.read(addr, 8)
                self.assertEqual(cm.exception.reason, f'unreadable at {addr:#x}')
                self.assertFalse(s.readable(addr, 8))
            self.assertEqual((spy.queries, spy.reads), (0, []))
            self.assertEqual(s.readable_ranges(USER_MAX - 8, 16), [])

    def test_freed(self):
        a = self.alloc(PAGE)
        self.cp.write(a, b'FREEME!!')
        s = ProcessSource(self.cp, cache=False)
        self.assertEqual(s.read(a, 8), b'FREEME!!')
        self.assertTrue(s.readable(a, 8))
        Process.current.free(a)
        self._allocs.remove(a)
        with self.assertRaises(MemoryReadError) as cm:
            s.read(a, 8)
        self.assertRegex(cm.exception.reason, r'^winerror [1-9]\d*$')
        self.assertFalse(s.readable(a, 8))
        self.assertIsNone(s.try_read(a, 8))
        regions = s.regions()  # the re-queried span is clipped, so the map neither overlaps nor gaps
        self.assertTrue(all(r.end == n.base for r, n in zip(regions, regions[1:])))
        self.assertEqual(regions[-1].end, USER_MAX)

    def test_lru(self):
        a, data = self.filled(3 * PAGE, seed=6)
        spy = _Spy()
        s = ProcessSource(spy.process, page_size=PAGE, max_cache_bytes=2 * PAGE)
        page1 = lambda: len(spy.reads_touching(a, a + PAGE))
        for i in range(3):
            self.assertEqual(s.read(a + i * PAGE, 8), data[i * PAGE:i * PAGE + 8])
        self.assertEqual(page1(), 1)
        self.cp.write(a, b'CHANGED!')
        self.assertEqual(s.read(a, 8), b'CHANGED!')
        self.assertEqual(page1(), 2)

        spy = _Spy()
        s = ProcessSource(spy.process, page_size=PAGE, max_cache_bytes=2 * PAGE)
        touching = lambda i: len(spy.reads_touching(a + i * PAGE, a + (i + 1) * PAGE))
        for i in (0, 1, 0, 2):  # page 0 was used after page 1, so page 1 is the one evicted
            s.read(a + i * PAGE, 8)
        self.assertEqual([touching(i) for i in range(3)], [1, 1, 1])
        s.read(a, 8)
        self.assertEqual(touching(0), 1)
        s.read(a + PAGE, 8)
        self.assertEqual(touching(1), 2)

        spy = _Spy()
        s = ProcessSource(spy.process, page_size=PAGE, max_cache_bytes=2 * PAGE)
        touching = lambda i: len(spy.reads_touching(a + i * PAGE, a + (i + 1) * PAGE))
        s.read(a + PAGE, 8)
        s.read(a, 8)
        self.assertEqual(s.read(a + PAGE - 4, 8), data[PAGE - 4:PAGE + 4])  # a two-page read: page 1 is now the newest
        s.read(a + 2 * PAGE, 8)
        s.read(a + PAGE, 8)
        self.assertEqual([touching(i) for i in range(3)], [1, 1, 1])

    def test_read_larger_than_cap(self):
        a, data = self.filled(3 * PAGE, seed=7)
        spy = _Spy()
        s = ProcessSource(spy.process, page_size=PAGE, max_cache_bytes=2 * PAGE)
        for lo, n in ((0, 3 * PAGE), (PAGE - 8, PAGE + 16)):
            before = len(spy.reads)
            self.assertEqual(s.read(a + lo, n), data[lo:lo + n])
            self.assertEqual(spy.reads[before:], [(a + lo, n)])
        before = len(spy.reads)
        self.assertEqual(s.read(a, 8), data[:8])
        self.assertEqual(len(spy.reads), before + 1)  # nothing became resident
        s.refresh()
        self.assertEqual(s.read(a + PAGE - 8, 16), data[PAGE - 8:PAGE + 8])  # two pages == the cap: cached
        before = len(spy.reads)
        self.assertEqual(s.read(a + PAGE - 8, 16), data[PAGE - 8:PAGE + 8])
        self.assertEqual(s.read(a + 2 * PAGE - 8, 8), data[2 * PAGE - 8:2 * PAGE])
        self.assertEqual(len(spy.reads), before)

    def test_threads(self):
        a, data = self.filled(4 * PAGE, seed=8)
        s = ProcessSource(self.cp, page_size=PAGE, max_cache_bytes=2 * PAGE)
        errors = []

        def worker(seed):
            rng = random.Random(seed)
            try:
                for _ in range(1000):
                    off = rng.randrange(4 * PAGE - 7)
                    if (got := s.u64(a + off)) != int.from_bytes(data[off:off + 8], 'little'):
                        errors.append((off, got))
            except BaseException as e:
                errors.append(e)

        old = sys.getswitchinterval()
        sys.setswitchinterval(1e-6)
        try:
            threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
        finally:
            sys.setswitchinterval(old)
        self.assertEqual(errors, [])

    def test_threads_mixed(self):
        slots = 6 * PAGE // 8
        a = self.alloc(7 * PAGE)
        self.cp.write(a, b''.join((i << 32).to_bytes(8, 'little') for i in range(slots)))
        hole, free = a + 6 * PAGE, a + 8 * PAGE  # a NOACCESS page and the free rest of the allocation granule
        Process.current.virtual_protect(hole, PAGE, PAGE_NOACCESS)
        s = ProcessSource(self.cp, page_size=PAGE, max_cache_bytes=3 * PAGE, requery_interval=0)
        errors, stop = [], threading.Event()

        def guarded(fn):
            def run(*args):
                try:
                    fn(*args)
                except BaseException as e:
                    errors.append(e)
            return run

        @guarded
        def reader(seed):
            rng = random.Random(seed)
            while not stop.is_set():
                i = rng.randrange(slots)
                src = s.fresh if rng.random() < 0.4 else s
                if (v := src.u64(a + i * 8)) >> 32 != i:
                    errors.append(('wrong slot', i, hex(v)))
                if src.readable(hole - 4, 8) or not src.valid_ptr(a + i * 8) or src.try_read(hole + 8, 8) is not None:
                    errors.append(('wrong map answer', i))
                if src.readable_ranges(hole - 8, 16) != [(hole - 8, 8)]:
                    errors.append(('wrong ranges', i))

        @guarded
        def writer(tid):
            rng, gen = random.Random(100 + tid), 0
            mine = range(tid, slots, 4)
            while not stop.is_set():
                gen += 1
                i = rng.choice(mine)
                value = ((i << 32) | gen).to_bytes(8, 'little')
                (s.fresh if gen & 1 else s).write(a + i * 8, value)
                if (got := (s.read(a + i * 8, 8), s.fresh.read(a + i * 8, 8))) != (value, value):
                    errors.append(('stale after write', i, gen, got))

        @guarded
        def refresher():
            k = 0
            while not stop.is_set():
                time.sleep(0.002)
                (s.fresh if (k := k + 1) & 1 else s).refresh()

        @guarded
        def mapper():
            while not stop.is_set():
                regions = s.regions()
                if regions[0].base != 0 or regions[-1].end != USER_MAX or any(r.end != n.base for r, n in zip(regions, regions[1:])):
                    errors.append('map not contiguous')
                if s.fresh.readable(free, 8) or s.readable(hole, 1):
                    errors.append('free or hole readable')

        threads = [threading.Thread(target=reader, args=(k,)) for k in range(6)]
        threads += [threading.Thread(target=writer, args=(k,)) for k in range(4)]
        threads += [threading.Thread(target=refresher), threading.Thread(target=mapper)]
        old = sys.getswitchinterval()
        sys.setswitchinterval(1e-6)
        try:
            for t in threads:
                t.start()
            time.sleep(1.5)
        finally:
            stop.set()
            for t in threads:
                t.join()
            sys.setswitchinterval(old)
        self.assertEqual(errors[:5], [])

    def test_cached_u64_throughput(self):
        n = 200_000
        with _Child() as child:
            spy = _Spy(child.open())
            s = ProcessSource(spy.process)
            lo, hi = child.addr, child.addr + len(PAYLOAD)
            page = max(range(lo & ~0xFFFF, hi, 0x10000), key=lambda p: min(hi, p + 0x10000) - max(lo, p))
            w_lo, w_hi = max(lo, page), min(hi, page + 0x10000)
            addrs = [w_lo + (i * 8) % (w_hi - w_lo - 8) for i in range(n)]
            expected = [int.from_bytes(PAYLOAD[x - lo:x - lo + 8], 'little') for x in addrs]
            s.u64(addrs[0])
            spy.reads.clear()
            spy.queries = 0
            t0 = time.perf_counter()
            values = [s.u64(x) for x in addrs]
            elapsed = time.perf_counter() - t0
        print(f'\ncached u64 reads: {n / elapsed:,.0f} reads/s ({n} reads in {elapsed:.3f} s)')
        self.assertEqual(values, expected)
        self.assertEqual((spy.reads, spy.queries), ([], 0))
        self.assertLess(elapsed, 2.0)

    def test_write_refuses_readonly_region(self):
        with _Child() as child:
            w = child.open(write=True)
            page = (child.addr + 0xFFF) & ~0xFFF
            self.assertLessEqual(page + 2 * PAGE, child.addr + len(PAYLOAD))
            original = w.read(page - 4, 2 * PAGE + 4, strict=True)
            s = ProcessSource(w)
            self.assertEqual(s.read(page - 4, 12), original[:12])  # the map is built before the protection changes
            w.virtual_protect(page, PAGE, PAGE_READONLY)
            w.virtual_protect(page + PAGE, PAGE, PAGE_EXECUTE_READ)
            for addr, data, first in ((page, b'X', page), (page - 4, b'12345678', page), (page + PAGE, b'X', page + PAGE)):
                with self.assertRaises(MemoryWriteError) as cm:
                    s.write(addr, data)
                self.assertEqual(cm.exception.reason, f'not writable at {first:#x}')
                self.assertEqual(w.read(page - 4, 2 * PAGE + 4, strict=True), original)
            w.write(page + PAGE, b'Y')  # WriteProcessMemory lifts EXECUTE_READ, so the refusal above is the source's
            self.assertEqual(w.read(page + PAGE, 1, strict=True), b'Y')

    def test_write_readonly_handle(self):
        with _Child() as child:
            s = ProcessSource(child.open())
            with self.assertRaises(MemoryWriteError) as cm:
                s.write(child.addr, b'X')
            self.assertEqual(cm.exception.reason, 'winerror 5')
            self.assertEqual(s.fresh.read(child.addr, 7), b'NYLIBUE')

    def test_write_invalidates_cache(self):
        with _Child() as child:
            s = ProcessSource(child.open(write=True))
            at = child.addr + 0x100
            self.assertEqual(s.read(at, 3), PAYLOAD[0x100:0x103])
            s.write(at, b'NEW')
            self.assertEqual(s.read(at, 3), b'NEW')
            self.assertEqual(s.read(at - 1, 5), PAYLOAD[0xFF:0x100] + b'NEW' + PAYLOAD[0x103:0x104])
            s.fresh.write(at, b'FRS')
            self.assertEqual(s.read(at, 3), b'FRS')
            self.assertEqual(s.fresh.read(at, 3), b'FRS')

    def test_write_internal(self):
        rw = self.alloc(PAGE)
        s = ProcessSource(self.cp)
        s.write(rw, b'Z')
        self.assertEqual(self.cp.read(rw, 2, strict=True), b'Z\0')
        b, data = self.filled(4 * PAGE, seed=10)
        spy = _Spy()
        s = ProcessSource(spy.process, page_size=PAGE)
        self.assertEqual(s.read(b, 8) + s.read(b + PAGE, 8), data[:8] + data[PAGE:PAGE + 8])
        s.write(b, b'W' * (3 * PAGE))  # three pages written, two resident
        self.assertEqual(s.read(b, 8) + s.read(b + PAGE, 8) + s.read(b + 3 * PAGE, 8), b'W' * 16 + data[3 * PAGE:3 * PAGE + 8])
        before = len(spy.reads)
        s.write(b, b'V')
        self.assertEqual(s.read(b + 3 * PAGE, 8), data[3 * PAGE:3 * PAGE + 8])
        self.assertEqual(len(spy.reads), before)  # an unrelated resident page is not dropped
        self.assertEqual(s.read(b, 2), b'VW')
        for protect in (PAGE_READONLY, PAGE_EXECUTE_READ):  # WriteProcessMemory itself would write the latter
            ro = self.alloc(PAGE, protect=protect)
            with self.assertRaises(MemoryWriteError) as cm:
                s.write(ro, b'Z')
            self.assertEqual(cm.exception.reason, f'not writable at {ro:#x}')
            self.assertEqual(self.cp.read(ro, 1, strict=True), b'\0')

    def test_modules(self):
        s = ProcessSource(self.cp)
        mods = s.modules()
        self.assertTrue(mods[0].name.lower().endswith(('python.exe', 'pythonw.exe')), mods[0].name)
        self.assertEqual(s.main_module, mods[0])
        func = ctypes.cast(ctypes.pythonapi.Py_IsInitialized, ctypes.c_void_p).value
        self.assertFalse(s.main_module.contains(func))
        py = s.module_at(func)
        self.assertEqual(py.base, sys.dllhandle)
        self.assertTrue(py.name.lower().startswith('python3') and py.path.lower().endswith(py.name.lower()), py)
        self.assertGreater(py.size, func - py.base)
        k32 = s.module_at(_k32._handle)
        self.assertEqual((k32.name.lower(), k32.base), ('kernel32.dll', _k32._handle))
        mods.clear()
        self.assertEqual(s.main_module.name, s.modules()[0].name)  # callers get a copy

        p = Process(Process.current.process_id, Process.current.handle)
        walks = []
        enum = p.enum_ldr_data
        p.enum_ldr_data = lambda: walks.append(1) or enum()
        s = ProcessSource(p)
        s.modules(), s.modules(), s.fresh.modules(), s.module_at(0)
        self.assertEqual(len(walks), 1)
        s.fresh.refresh()
        s.modules()
        self.assertEqual(len(walks), 2)

        hole = self.alloc(PAGE, protect=PAGE_NOACCESS)
        for field in ('BaseDllName', 'FullDllName'):  # names are read strictly, never zero-filled
            entries = list(enum())
            getattr(entries[1], field).Buffer = hole
            p.enum_ldr_data = lambda: iter(entries)
            with self.subTest(field=field), self.assertRaises(TargetError) as cm:
                ProcessSource(p).modules()
            self.assertEqual(cm.exception.target, p.process_id)
            self.assertRegex(cm.exception.reason, r'^cannot list modules: winerror [1-9]\d*$')

    def test_closed_process(self):
        with _Child() as child:
            p = child.open()
            p.close()
            s = ProcessSource(p)
            self.assertEqual(s.regions(), [Region(0, USER_MAX, 0, MEM_FREE, 0)])
            with self.assertRaises(MemoryReadError):
                s.read(child.addr, 7)
            self.assertFalse(s.readable(child.addr, 7))
            with self.assertRaises(TargetError):
                s.modules()


if __name__ == '__main__':
    unittest.main()
