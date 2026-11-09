import contextlib
import ctypes
import importlib.util
from pathlib import Path
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
    if line.startswith('exitcall '):
        flag = int(line.split()[1])
        ntdll = ctypes.WinDLL('ntdll')
        ntdll.NtTerminateProcess.argtypes = (ctypes.c_void_p, ctypes.c_long)
        status = ntdll.NtTerminateProcess(None, 7)
        if status: raise OSError(f'NtTerminateProcess failed: {status:#x}')
        while not ctypes.c_uint64.from_address(flag).value: pass
        ctypes.CFUNCTYPE(ctypes.c_uint64)(Process.current.read_ptr(slot))()
        ctypes.c_uint64.from_address(flag + 8).value = 1
        os._exit(7)
    if line.strip() == 'exit': break
'''


@unittest.skipUnless(importlib.util.find_spec('capstone') and importlib.util.find_spec('keystone'), 'requires capstone and keystone')
class NylibHookTests(unittest.TestCase):
    def setUp(self):
        self.process = Process.current
        self.addr = self.process.alloc(0x1000)
        self.process.write(self.addr, _TARGET_CODE)

    def tearDown(self):
        self.process.free(self.addr)

    def test_owned_matrix(self):
        for far in (False, True):
            for tid in (None, winapi.GetCurrentThreadId()):
                for capacity in (1, 16, 64):
                    with self.subTest(far=far, tid=tid, capacity=capacity), contextlib.ExitStack() as cleanup:
                        if far: cleanup.enter_context(patch.object(self.process, 'alloc_near', side_effect=ValueError('no near page')))
                        hook = cleanup.enter_context(InlineCallQueue(self.process, self.addr, capacity=capacity, thread_id=tid))
                        original = hook.orig_code
                        key = (self.process.process_id, hook._shared.remote_at)
                        self.assertGreater(key[1], 0x7FFFFFFF)
                        self.assertEqual(inline_call._find_nylib_hook(self.process, self.addr),
                                         inline_call._NylibHook(hook.alloc_at, key[1], capacity, tid, len(original), original, True))
                        hook.close()
                        self.assertNotIn(key, inline_call._open_queues)
                        self.assertIsNone(inline_call._find_nylib_hook(self.process, self.addr))

    @contextlib.contextmanager
    def plain_hook(self, *, data_at=0x7FFE0000, capacity=16, thread_id=None, original=bytes.fromhex('48 B8 01 00 00 00 00 00 00 00')):
        page = self.process.alloc_near(0x1000, self.addr)
        code = inline_call._dispatcher_code(data_at, capacity, thread_id)
        trigger = b'\xE9' + struct.pack('<i', page - self.addr - 5) + b'\x90' * (len(original) - 5)
        image = code + original + inline_call._absolute_jump(self.addr + len(original))
        self.process.write(page, image)
        self.process.write(self.addr, trigger)
        try:
            yield page, code, original, trigger, image
        finally:
            self.process.virtual_protect(page, 0x1000, 0x40)
            self.process.write(self.addr, _TARGET_CODE)
            self.process.free(page)

    def test_plain_mov_unheld(self):
        import capstone
        with self.plain_hook() as (page, code, original, trigger, image):
            loads = [i for i in capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64).disasm(code, page)
                     if i.op_str.startswith('rbx,')]
            self.assertEqual(loads[0].mnemonic, 'mov')
            self.assertEqual(inline_call._find_nylib_hook(self.process, self.addr),
                             inline_call._NylibHook(page, 0x7FFE0000, 16, None, len(original), original, False))

    def test_corruption(self):
        for part in ('dispatcher', 'original', 'return', 'padding'):
            with self.subTest(part=part), self.plain_hook() as (page, code, original, trigger, image):
                self.assertIsNotNone(inline_call._find_nylib_hook(self.process, self.addr))
                if part == 'dispatcher': self.process.write(page, bytes([image[0] ^ 1]))
                if part == 'original': self.process.write(page + len(code), bytes([original[0] ^ 0x8B]))  # ret
                if part == 'return': self.process.write(page + len(code) + len(original), b'\xFE')
                if part == 'padding': self.process.write(self.addr + 5, b'\x91')
                self.assertIsNone(inline_call._find_nylib_hook(self.process, self.addr))

    def test_invalid_dispatcher_parameters(self):
        for data, capacity, tid in ((0, 16, None), (0x7FFE0000, 3, None), (0x7FFE0000, 128, None), (0x7FFE0000, 16, 0)):
            with self.subTest(data=data, capacity=capacity, tid=tid), self.plain_hook(data_at=data, capacity=capacity, thread_id=tid):
                self.assertIsNone(inline_call._find_nylib_hook(self.process, self.addr))

    def test_unrecognised_pages(self):
        with self.plain_hook() as (page, code, original, trigger, image):
            self.process.write(self.addr, b'\xE9' + struct.pack('<i', page + 1 - self.addr - 5))
            self.assertIsNone(inline_call._find_nylib_hook(self.process, self.addr))
            self.process.write(self.addr, trigger)
            self.process.write(page, b'\x90' * 0x1000)
            self.assertIsNone(inline_call._find_nylib_hook(self.process, self.addr))
            self.process.write(page, image)
            for protect in (0x04, 0x120, 0x01):
                self.process.virtual_protect(page, 0x1000, protect)
                self.assertIsNone(inline_call._find_nylib_hook(self.process, self.addr))
                self.assertEqual(self.process.virtual_query(page).Protect, protect)

    def test_unrelocatable_original_is_refused(self):
        for original in ('E8 00 00 00 00', 'E9 00 00 00 00', 'C3 90 90 90 90', 'CC 90 90 90 90', '48 CF 90 90 90', '48 8B 05 00 00 00 00'):
            with self.subTest(original=original), self.plain_hook(original=bytes.fromhex(original)):
                self.assertIsNone(inline_call._find_nylib_hook(self.process, self.addr))

    def test_relocated_jump_is_refused(self):
        for rel in (0x30 - 5, -5):
            with self.subTest(rel=rel):
                self.process.write(self.addr, b'\xE9' + struct.pack('<i', rel) + b'\x90' * 48)
                with InlineCallQueue(self.process, self.addr, _jmp_support=1):
                    self.assertIsNone(inline_call._find_nylib_hook(self.process, self.addr))

    def test_no_jump_and_page_end(self):
        self.assertIsNone(inline_call._find_nylib_hook(self.process, self.addr))
        process = self.process
        reads = []
        class Reader:
            def read(self, addr, n):
                reads.append((addr, n))
                return process.read(addr, n)
        at = self.addr + 0xFF8
        self.process.write(at, b'\x90' * 8)
        self.assertIsNone(inline_call._find_nylib_hook(Reader(), at))
        self.assertEqual(reads, [(at, 8)])

    def test_invalid_inputs_and_read_failures(self):
        for addr in ('0x1000', True):
            with self.subTest(addr=addr), self.assertRaises(TypeError):
                inline_call._find_nylib_hook(None, addr)
        for addr in (-1, 0, 1 << 64):
            self.assertIsNone(inline_call._find_nylib_hook(None, addr))
        class Reader:
            def read(self, addr, n):
                raise OSError(0, 'x', None, 299)
        self.assertIsNone(inline_call._find_nylib_hook(Reader(), 0x1000))
        far = b'\xFF\x25\0\0\0\0'
        for trigger in (b'\xE9' + struct.pack('<i', -0x2000), b'\xE9' + struct.pack('<i', -0x2005), b'\xE9' + struct.pack('<i', -0x1005),
                        far + struct.pack('<Q', 0x8000_0000_0000) + b'\x90', far + struct.pack('<Q', 0x10000) + b'\x91'):
            calls = []
            class Jump:
                def read(self, addr, n):
                    calls.append((addr, n))
                    return trigger
            with self.subTest(trigger=trigger.hex()):
                self.assertIsNone(inline_call._find_nylib_hook(Jump(), 0x1000))
                self.assertEqual(calls, [(0x1000, 32)])

    def test_init_failure_removes_registry_entry(self):
        keys = set(inline_call._open_queues)
        with patch.object(inline_call, '_dispatcher_code', side_effect=RuntimeError('assembly failed')):
            with self.assertRaisesRegex(RuntimeError, 'assembly failed'):
                InlineCallQueue(self.process, self.addr)
        self.assertEqual(inline_call._open_queues, keys)

    def test_ended_host_hook_is_unheld(self):
        root = str(Path(__file__).resolve().parents[1])
        child_code = "import nylib; print(nylib.__file__, flush=True)\n" + _CHILD
        child = subprocess.Popen([sys.executable, '-B', '-u', '-c', child_code], cwd=root,
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        process = None
        try:
            self.assertEqual(Path(child.stdout.readline().strip()).resolve().parent.parent, Path(root))
            pid, addr, tid, slot = map(int, child.stdout.readline().split())
            process = Process(pid)
            host_code = '''
import os, sys, nylib
from pathlib import Path
from nylib.process import Process
from nylib.winutils.inline_call import InlineCallQueue
assert Path(nylib.__file__).resolve().parent.parent == Path.cwd()
hook = InlineCallQueue(Process(int(sys.argv[1])), int(sys.argv[2]))
hook.enabled = True
print(hook.alloc_at, hook._shared.remote_at, len(hook.orig_code), hook.orig_code.hex(), flush=True)
os._exit(0)
'''
            host = subprocess.run([sys.executable, '-B', '-u', '-c', host_code, str(pid), str(addr)], cwd=root,
                                  capture_output=True, text=True, timeout=30)
            self.assertEqual(host.returncode, 0, host.stderr)
            page, data, size, original = host.stdout.split()
            self.assertEqual(inline_call._find_nylib_hook(process, addr),
                             inline_call._NylibHook(int(page), int(data), 16, None, int(size), bytes.fromhex(original), False))
        finally:
            if child.poll() is None: child.terminate()
            child.wait(10)
            if process is not None: process.close()
            child.stdin.close()
            child.stdout.close()


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

    def test_opt_in_relocates_internal_short_jump_with_far_entry(self):
        code = b'\xEB\x02\x90\x90\xB8\x2A\x00\x00\x00' + b'\x90' * 12 + b'\xC3'
        self.process.write(self.addr, code)
        winapi.FlushInstructionCache(self.process.handle, self.addr, len(code))
        with patch.object(self.process, 'alloc_near', side_effect=ValueError('No suitable memory region')):
            hook = InlineHook(self.process, b'\x90', self.addr, _jmp_support=1)
            try:
                hook.enabled = True
                self.assertEqual(self.target(), 42)
            finally:
                hook.free()
        self.assertEqual(self.process.read(self.addr, len(code)), code)

    def test_opt_in_expands_external_short_jump(self):
        code = b'\xEB\x2E' + b'\x90' * (0x30 - 2) + b'\xB8\x2A\x00\x00\x00\xC3'
        self.process.write(self.addr, code)
        winapi.FlushInstructionCache(self.process.handle, self.addr, len(code))
        hook = InlineHook(self.process, b'\x90', self.addr, _jmp_support=1)
        try:
            hook.enabled = True
            self.assertEqual(self.process.read(hook.alloc_at + 1, 6), b'\xFF\x25\x00\x00\x00\x00')
            self.assertEqual(self.target(), 42)
        finally:
            hook.free()

    def test_opt_in_relocates_external_rel32_jump_and_drains_queue(self):
        get_tid = self.process.get_proc_address('kernel32.dll', 'GetCurrentThreadId')
        code = b'\xE9' + struct.pack('<i', 0x30 - 5) + b'\x90' * (0x30 - 5) + b'\xB8\x2A\x00\x00\x00\xC3'
        self.process.write(self.addr, code)
        winapi.FlushInstructionCache(self.process.handle, self.addr, len(code))
        with patch.object(self.process, 'alloc_near', side_effect=ValueError('No suitable memory region')):
            with InlineCallQueue(self.process, self.addr, _jmp_support=1) as hook:
                ticket = hook.submit(get_tid)
                self.assertEqual(self.target(), 42)
                self.assertEqual(ticket.wait(1000), winapi.GetCurrentThreadId())
        self.assertEqual(self.process.read(self.addr, len(code)), code)

    def test_opt_in_accepts_int3_padding_after_jump(self):
        code = b'\xE9' + struct.pack('<i', 0x30 - 5) + b'\xCC' * (0x30 - 5) + b'\xB8\x2A\x00\x00\x00\xC3'
        self.process.write(self.addr, code)
        winapi.FlushInstructionCache(self.process.handle, self.addr, len(code))
        with patch.object(self.process, 'alloc_near', side_effect=ValueError('No suitable memory region')):
            hook = InlineHook(self.process, b'\x90', self.addr, _jmp_support=1)
            try:
                hook.enabled = True
                self.assertEqual(self.target(), 42)
            finally:
                hook.free()

    def test_opt_in_relocates_internal_jz_after_branch_growth(self):
        code = (b'\x48\x85\xC9\x74\x07\xB8\x07\x00\x00\x00\xEB\x05\xB8\x2A\x00\x00\x00'
                + b'\x90' * (0x20 - 17) + b'\xC3')
        self.process.write(self.addr, code)
        winapi.FlushInstructionCache(self.process.handle, self.addr, len(code))
        target = ctypes.CFUNCTYPE(ctypes.c_uint64, ctypes.c_uint64)(self.addr)
        with patch.object(self.process, 'alloc_near', side_effect=ValueError('No suitable memory region')):
            hook = InlineHook(self.process, b'\x90', self.addr, _jmp_support=1)
            try:
                hook.enabled = True
                self.assertEqual(target(0), 42)
                self.assertEqual(target(1), 7)
            finally:
                hook.free()

    def test_opt_in_preserves_all_external_jcc_conditions(self):
        target = ctypes.CFUNCTYPE(ctypes.c_uint64, ctypes.c_uint64)(self.addr)
        for condition in range(16):
            for wide in (False, True):
                with self.subTest(condition=condition, wide=wide):
                    branch = (b'\x0F' + bytes((0x80 | condition,)) + struct.pack('<i', 0x30 - 10) if wide
                              else bytes((0x70 | condition, 0x30 - 6)))
                    code = (b'\x48\x83\xF9\x05' + branch + b'\xB8\x07\x00\x00\x00'
                            + b'\x90' * (0x20 - 9 - len(branch)) + b'\xC3' + b'\x90' * (0x30 - 0x21) + b'\xB8\x2A\x00\x00\x00\xC3')
                    self.process.write(self.addr, code)
                    winapi.FlushInstructionCache(self.process.handle, self.addr, len(code))
                    expected = [target(value) for value in (4, 5, 6)]
                    with patch.object(self.process, 'alloc_near', side_effect=ValueError('No suitable memory region')):
                        hook = InlineHook(self.process, b'\x90', self.addr, _jmp_support=1)
                        try:
                            hook.enabled = True
                            self.assertEqual([target(value) for value in (4, 5, 6)], expected)
                        finally:
                            hook.free()

    def test_opt_in_rejects_branch_into_instruction_and_default_rejects_jcc(self):
        self.process.write(self.addr, b'\x74\x05' + b'\x90' * 20)
        default = InlineHook(self.process, b'\x90', self.addr)
        try:
            with self.assertRaisesRegex(PrologueError, 'cannot relocate'):
                default.enabled = True
        finally:
            default.free()
        queue = InlineCallQueue(self.process, self.addr)
        try:
            with self.assertRaisesRegex(PrologueError, 'cannot relocate'):
                queue.enabled = True
        finally:
            queue.close()
        self.process.write(self.addr, b'\xEB\x01\xB8\x2A\x00\x00\x00' + b'\x90' * 16)
        opt_in = InlineHook(self.process, b'\x90', self.addr, _jmp_support=1)
        try:
            with self.assertRaisesRegex(PrologueError, 'enters an instruction'):
                opt_in.enabled = True
        finally:
            opt_in.free()

    def test_jmp_support_only_accepts_zero_or_one(self):
        with self.assertRaisesRegex(ValueError, '_jmp_support'):
            InlineHook(self.process, b'\x90', self.addr, _jmp_support=2)
        with self.assertRaisesRegex(ValueError, '_jmp_support'):
            InlineCallQueue(self.process, self.addr, _jmp_support=2)

    def test_opt_in_still_rejects_call_and_rip_indirect_jump(self):
        for code in (b'\xE8\x00\x00\x00\x00', b'\xFF\x25\x00\x00\x00\x00'):
            with self.subTest(code=code):
                self.process.write(self.addr, code + b'\x90' * 16)
                hook = InlineHook(self.process, b'\x90', self.addr, _jmp_support=1)
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
        real_open_threads = inline_call._open_threads

        def open_threads(process, tids, own_tid):
            handles = real_open_threads(process, tids, own_tid)
            stop.set()
            for thread in helpers: thread.join(5)
            for waiter in waiters: self.assertEqual(winapi.WaitForSingleObject(waiter, 10000), 0)
            return handles

        try:
            with patch.object(inline_call, '_open_threads', open_threads):
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

    def test_quiescent_patch_does_not_hang_beside_busy_python_threads(self):
        source = '''
import sys
import threading
from nylib.process import Process
from nylib.winutils.inline_call import InlineCallQueue

process = Process.current
addr = process.alloc(0x1000)
process.write(addr, bytes.fromhex('B82A000000') + b'\\x90' * 16 + b'\\xC3')
hook = InlineCallQueue(process, addr, quiescent_patch=True)
stop = threading.Event()
ready = threading.Barrier(3)
def spin():
    ready.wait(5)
    count = 0
    while not stop.is_set(): count += 1
sys.setswitchinterval(1e-4)
workers = [threading.Thread(target=spin, daemon=True) for _ in range(2)]
for worker in workers: worker.start()
ready.wait(5)
for i in range(200):
    hook.enabled = not hook.enabled
    print(i + 1, flush=True)
stop.set()
for worker in workers:
    worker.join(5)
    assert not worker.is_alive()
hook.close()
process.free(addr)
print('ok', flush=True)
'''
        root = str(Path(__file__).resolve().parents[1])
        try:
            child = subprocess.run([sys.executable, '-B', '-u', '-c', source], cwd=root,
                                   capture_output=True, text=True, timeout=60)
        except subprocess.TimeoutExpired as exc:
            output = exc.stdout or b''
            if isinstance(output, bytes): output = output.decode('utf-8', errors='replace')
            counts = [int(line) for line in output.splitlines() if line.isdecimal()]
            self.fail(f'quiescent patch hung after {counts[-1] if counts else 0} toggles')
        self.assertEqual(child.returncode, 0, child.stderr)
        self.assertEqual(child.stdout.splitlines(), [str(i) for i in range(1, 201)] + ['ok'])

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
        real_window = inline_call._call_window

        def spy(block):
            status = real_window(block)
            handles = (ctypes.c_uint64 * block.count).from_address(block.handles)
            flags = (ctypes.c_ubyte * block.count).from_address(block.flags)
            suspended.extend(winapi.GetThreadId(handle) for handle, flag in zip(handles, flags) if flag == 1)
            return status

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
            with patch.object(inline_call, '_call_window', spy):
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
    def test_remote_opt_in_far_jump_drains_queue(self):
        child = subprocess.Popen([sys.executable, '-B', '-u', '-c', _CHILD], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        process = hook = None
        try:
            pid, addr, tid, _ = map(int, child.stdout.readline().split())
            process = Process(pid)
            code = b'\xE9' + struct.pack('<i', 0x30 - 5) + b'\x90' * (0x30 - 5) + b'\xB8\x2A\x00\x00\x00\xC3'
            process.write(addr, code)
            winapi.FlushInstructionCache(process.handle, addr, len(code))
            with patch.object(process, 'alloc_near', side_effect=ValueError('No suitable memory region')):
                hook = InlineCallQueue(process, addr, _jmp_support=1)
                hook.enabled = True
            ticket = hook.submit(process.get_proc_address('kernel32.dll', 'GetCurrentThreadId'))
            child.stdin.write('hit\n')
            child.stdin.flush()
            self.assertEqual(child.stdout.readline().strip(), '42')
            self.assertEqual(ticket.wait(5000), tid)
            hook.close()
            hook = None
            self.assertEqual(process.read(addr, len(code)), code)
        finally:
            if process is not None and process.still_alive(): winapi.TerminateProcess(process.handle, 0)
            if hook is not None and not hook._tickets: hook.close()
            if process is not None: process.close()
            if child.poll() is None: child.terminate()
            child.wait(5)
            child.stdin.close()
            child.stdout.close()

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


class _WithdrawTarget:
    def __init__(self, *, child=False, vtable=False, capacity=1):
        self.child = None
        self.handle = None
        self.replies = queue.Queue()
        self.vtable = vtable
        if child:
            root = str(Path(__file__).resolve().parents[1])
            source = "import nylib; print(nylib.__file__, flush=True)\n" + _CHILD
            self.child = subprocess.Popen([sys.executable, '-B', '-u', '-c', source], cwd=root,
                                          stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
            assert Path(self.child.stdout.readline().strip()).resolve().parent.parent == Path(root)
            pid, self.addr, _, self.slot = map(int, self.child.stdout.readline().split())
            self.process = Process(pid)
            self.reader = threading.Thread(target=lambda: [self.replies.put(line.strip()) for line in self.child.stdout], daemon=True)
            self.reader.start()
        else:
            self.process = Process.current
            self.addr = self.process.alloc(0x1000)
            self.process.write(self.addr, _TARGET_CODE)
            self.slot = self.process.alloc(0x1000, protect=0x04)
            self.process.write_ptr(self.slot, self.addr)
        self.mapping = self.process.map_shared(0x1000)
        self.words = (ctypes.c_uint64 * 3).from_address(self.mapping.local_at)
        self.words[2] = 1
        self.callee = self.process.alloc(0x1000)
        code = bytes(ks_.asm('lock inc qword ptr [rcx]; mov qword ptr [rcx+8], 1; spin: pause; '
                             'cmp qword ptr [rcx+16], 0; je spin; mov rax, qword ptr [rcx]; ret')[0])
        self.process.write(self.callee, code)
        winapi.FlushInstructionCache(self.process.handle, self.callee, len(code))
        cls = VTableCallQueue if vtable else InlineCallQueue
        self.hook = cls(self.process, self.slot if vtable else self.addr, capacity=capacity)
        self.hook.enabled = True

    def submit(self):
        return self.hook.submit(self.callee, self.mapping.remote_at)

    def hit(self):
        if self.child:
            self.child.stdin.write('hit\n')
            self.child.stdin.flush()
        else:
            addr = self.process.read_ptr(self.slot) if self.vtable else self.addr
            self.handle = _kernel32.CreateThread(None, 0, addr, None, 0, None)
            if not self.handle: raise ctypes.WinError()

    def join(self):
        if self.child:
            assert self.replies.get(timeout=10) == '42'
        elif self.handle:
            assert _kernel32.WaitForSingleObject(self.handle, 10000) == 0
            _kernel32.CloseHandle(self.handle)
            self.handle = None

    def kill(self):
        self.child.terminate()
        self.child.wait(10)

    def close(self):
        self.words[2] = 1
        if self.child:
            if self.child.poll() is None: self.kill()
            self.reader.join(10)
        elif self.handle:
            self.join()
        self.hook.close()
        self.mapping.close()
        if self.child:
            self.process.close()
            self.child.stdin.close()
            self.child.stdout.close()
        else:
            for at in (self.callee, self.slot, self.addr): self.process.free(at)

    def __enter__(self): return self
    def __exit__(self, *args): self.close()


class WithdrawTests(unittest.TestCase):
    def until(self, condition):
        deadline = time.monotonic() + 10
        while not condition():
            if time.monotonic() >= deadline: self.fail('native operation did not finish')
            time.sleep(0.001)

    def test_withdraw_before_entry_and_capacity_one_release(self):
        for child in (False, True):
            for vtable in (False, True):
                with self.subTest(child=child, vtable=vtable), _WithdrawTarget(child=child, vtable=vtable) as target:
                    ticket = target.submit()
                    self.assertTrue(ticket.withdraw())
                    self.assertTrue(ticket.withdraw())
                    self.assertTrue(ticket.withdrawn)
                    self.assertTrue(ticket.done)
                    self.assertIsNone(ticket.exit_slot)
                    self.assertFalse(target.hook._tickets)
                    with self.assertRaises(BufferError): target.submit()
                    for method in (ticket.wait, ticket.close):
                        with self.assertRaisesRegex(RuntimeError, '^inline call was withdrawn$'): method()
                    target.hit()
                    target.join()
                    self.assertEqual(target.words[0], 0)
                    self.assertEqual(target.hook._atomic.load(target.hook._shared.local_at + 8), 1)
                    self.assertEqual(target.hook._atomic.load(target.hook._slot_at(0)), 4)
                    next_ticket = target.submit()
                    self.assertEqual(target.hook._reclaim, 1)
                    target.hit()
                    target.join()
                    self.assertEqual(next_ticket.wait(1000), 1)
                    self.assertFalse(next_ticket.withdraw())
                    self.assertIsNone(next_ticket.exit_slot)

    def test_running_and_done_are_not_withdrawn(self):
        for child in (False, True):
            for vtable in (False, True):
                with self.subTest(child=child, vtable=vtable), _WithdrawTarget(child=child, vtable=vtable) as target:
                    target.words[2] = 0
                    ticket = target.submit()
                    target.hit()
                    try:
                        self.until(lambda: target.words[1] == 1)
                        self.assertFalse(ticket.withdraw())
                        self.assertFalse(ticket.done)
                        self.assertIsNone(ticket.exit_slot)
                    finally:
                        target.words[2] = 1
                        target.join()
                    self.assertFalse(ticket.withdraw())
                    self.assertEqual(ticket.wait(1000), 1)

    def test_waiter_wakes_on_withdraw(self):
        with _WithdrawTarget() as target:
            ticket = target.submit()
            started = threading.Event()
            outcome = queue.Queue()
            def wait():
                started.set()
                try: ticket.wait(5000)
                except RuntimeError as exc: outcome.put(str(exc))
            worker = threading.Thread(target=wait)
            worker.start()
            self.assertTrue(started.wait(5))
            self.assertTrue(ticket.withdraw())
            worker.join(10)
            self.assertFalse(worker.is_alive())
            self.assertEqual(outcome.get_nowait(), 'inline call was withdrawn')

    def test_close_with_only_withdrawn_restores_trigger(self):
        for vtable in (False, True):
            with self.subTest(vtable=vtable), _WithdrawTarget(vtable=vtable) as target:
                ticket = target.submit()
                self.assertTrue(ticket.withdraw())
                target.hook.enabled = False
                target.hook.free()
                target.hook.close()
                self.assertEqual(target.process.read(target.addr, len(_TARGET_CODE)), _TARGET_CODE)
                self.assertEqual(target.process.read_ptr(target.slot), target.addr)
                with patch.object(target.hook._atomic, 'load', side_effect=AssertionError('freed view read')):
                    self.assertTrue(ticket.done)
                    self.assertTrue(ticket.withdraw())
                    for method in (ticket.wait, ticket.close):
                        with self.assertRaisesRegex(RuntimeError, 'inline call was withdrawn'): method()

    def test_dead_target_exit_slots_and_closed_queue_guard(self):
        for vtable in (False, True):
            for state in (1, 2, 3):
                for close_first in (False, True):
                    with self.subTest(vtable=vtable, state=state, close_first=close_first), _WithdrawTarget(child=True, vtable=vtable) as target:
                        target.words[2] = int(state != 2)
                        ticket = target.submit()
                        if state != 1:
                            target.hit()
                            self.until(lambda: target.words[1] == 1)
                            if state == 3: target.join()
                        target.kill()
                        if close_first or state == 3: target.hook.close()
                        with self.assertRaises(ProcessLookupError): ticket.wait(1000)
                        self.assertEqual(ticket.exit_slot, state)
                        with self.assertRaises(ProcessLookupError): ticket.withdraw()
                        target.hook.close()
                        self.assertEqual(ticket.exit_slot, state)
                        ticket._error = None
                        with patch.object(target.hook._atomic, 'load', side_effect=AssertionError('freed view read')):
                            self.assertTrue(ticket.done)
                            with self.assertRaisesRegex(RuntimeError, '^inline call queue is closed$'): ticket.close()

    def test_timeout_has_no_exit_slot(self):
        with _WithdrawTarget() as target:
            ticket = target.submit()
            with self.assertRaises(TimeoutError): ticket.wait(0)
            self.assertIsNone(ticket.exit_slot)
            self.assertTrue(ticket.withdraw())

    def test_exit_wait_withdraws_before_exiting_thread_enters_trigger(self):
        self._exit_before_entry(close_first=False)

    def test_exit_close_keeps_target_view_for_exiting_thread(self):
        self._exit_before_entry(close_first=True)

    def _exit_before_entry(self, *, close_first):
        for vtable in (False, True):
            with self.subTest(vtable=vtable), _WithdrawTarget(child=True, vtable=vtable) as target:
                flag = target.process.map_shared(0x1000)
                words = (ctypes.c_uint64 * 2).from_address(flag.local_at)
                try:
                    ticket = target.submit()
                    local_at, remote_at = target.hook._shared.local_at, target.hook._shared.remote_at
                    trigger_at = target.slot if vtable else target.addr
                    hooked = target.process.read(trigger_at, 8)
                    target.child.stdin.write(f'exitcall {flag.remote_at}\n')
                    target.child.stdin.flush()
                    self.until(lambda: not target.process.still_alive())
                    try:
                        if close_first:
                            target.hook.close()
                            local_state = Process.current.virtual_query(local_at).State
                            remote_state = target.process.virtual_query(remote_at).State
                            trigger = target.process.read(trigger_at, 8)
                        else:
                            with self.assertRaises(ProcessLookupError): ticket.wait(1000)
                            slot_word = target.hook._atomic.load(target.hook._slot_at(ticket.sequence))
                    finally:
                        words[0] = 1
                    target.child.wait(10)
                    self.assertEqual(target.child.returncode, 7)
                    self.assertEqual(words[1], 1)
                    self.assertEqual(target.words[0], 0)
                    self.assertEqual(ticket.exit_slot, 1)
                    self.assertFalse(ticket.withdrawn)
                    if close_first:
                        self.assertEqual(local_state, 0x10000)  # MEM_FREE
                        self.assertEqual(remote_state, 0x1000)  # MEM_COMMIT
                        self.assertEqual(trigger, hooked)
                    else:
                        self.assertEqual(slot_word, 4)
                        self.assertEqual(target.hook._atomic.load(target.hook._shared.local_at + 8), 1)
                        self.assertIn(ticket.sequence, target.hook._tickets)
                        self.assertFalse(target.hook._withdrawn)
                    for method in (ticket.wait, ticket.close, ticket.withdraw):
                        with self.assertRaises(ProcessLookupError): method()
                    target.hook.close()
                    self.assertEqual(ticket.exit_slot, 1)
                finally:
                    words[0] = 1
                    if target.child.poll() is None: target.kill()
                    flag.close()

    def test_compare_exchange_and_unexpected_slot(self):
        with _WithdrawTarget() as target:
            ticket = target.submit()
            atomic = target.hook._atomic
            at = target.hook._slot_at(ticket.sequence)
            self.assertEqual(atomic.compare_exchange(at, 2, 4), 1)
            self.assertEqual(atomic.load(at), 1)
            atomic.exchange(at, 7)
            with self.assertRaisesRegex(RuntimeError, 'unexpected state 7'): ticket.withdraw()
            atomic.exchange(at, 1)
            self.assertTrue(ticket.withdraw())

    def test_v1_page_is_recognised(self):
        for far in (False, True):
            for tid in (None, winapi.GetCurrentThreadId()):
                with self.subTest(far=far, tid=tid), contextlib.ExitStack() as cleanup:
                    process = Process.current
                    addr = process.alloc(0x1000)
                    cleanup.callback(process.free, addr)
                    process.write(addr, _TARGET_CODE)
                    if far: cleanup.enter_context(patch.object(process, 'alloc_near', side_effect=ValueError('no near page')))
                    with patch.object(inline_call, '_dispatcher_code', inline_call._dispatcher_code_v1):
                        hook = InlineCallQueue(process, addr, thread_id=tid, _jmp_support=0)
                        hook.enabled = True
                    cleanup.callback(hook.close)
                    found = inline_call._find_nylib_hook(process, addr)
                    self.assertIsNotNone(found)
                    self.assertEqual(found.page, hook.alloc_at)
                    self.assertEqual(found.thread_id, tid)


if __name__ == '__main__':
    unittest.main()
