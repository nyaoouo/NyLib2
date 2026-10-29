import ctypes
import struct
import threading
import time

import capstone

from .. import winapi
from .inline_hook import InlineHook, asm, read_code


_HEADER_SIZE = 64
_SLOT_SIZE = 128
_MAX_ARGS = 8
_WAITING = 1
_DONE = 3
_UNSET = object()


class _AtomicWord:
    def __init__(self):
        self.at = winapi.VirtualAllocEx(winapi.GetCurrentProcess(), 0, 0x1000, 0x3000, 0x04)
        try:
            code = b'\x48\x89\xd0\x48\x87\x01\xc3' + b'\x48\x31\xc0\xf0\x48\x0f\xb1\x01\xc3'
            ctypes.memmove(self.at, code, len(code))
            winapi.VirtualProtectEx(winapi.GetCurrentProcess(), self.at, 0x1000, 0x20, ctypes.byref(ctypes.c_ulong()))
            winapi.FlushInstructionCache(winapi.GetCurrentProcess(), self.at, len(code))
            fn = ctypes.CFUNCTYPE(ctypes.c_uint64, ctypes.c_void_p, ctypes.c_uint64)
            self.exchange = fn(self.at)
            self.load = ctypes.CFUNCTYPE(ctypes.c_uint64, ctypes.c_void_p)(self.at + 7)
        except BaseException:
            self.close()
            raise

    def close(self):
        if self.at:
            winapi.VirtualFreeEx(winapi.GetCurrentProcess(), self.at, 0, 0x8000)
            self.at = 0


class _SharedQueue:
    def __init__(self, process, capacity):
        self.process = process
        self.size = (_HEADER_SIZE + capacity * _SLOT_SIZE + 0xFFF) & ~0xFFF
        self.section = self.local_at = self.remote_at = 0
        try:
            self.section = winapi.CreateFileMapping(winapi.INVALID_HANDLE_VALUE, None, 0x04, 0, self.size, None)  # PAGE_READWRITE
            self.local_at = winapi.MapViewOfFile(self.section, 0x06, 0, 0, self.size)  # FILE_MAP_READ|FILE_MAP_WRITE
            base = ctypes.c_void_p()
            size = ctypes.c_size_t(self.size)
            winapi.NtMapViewOfSection(self.section, process.handle, ctypes.byref(base), 0, 0, None, ctypes.byref(size), 1, 0, 0x04)
            self.remote_at = base.value
            winapi.CloseHandle(self.section)
            self.section = 0
        except BaseException:
            self.close()
            raise

    def close(self):
        if self.remote_at:
            try:
                winapi.NtUnmapViewOfSection(self.process.handle, self.remote_at)
            except OSError:
                if self.process.still_alive(): raise
            self.remote_at = 0
        if self.local_at:
            winapi.UnmapViewOfFile(self.local_at)
            self.local_at = 0
        if self.section:
            winapi.CloseHandle(self.section)
            self.section = 0


def _dispatcher_code(data_at: int, capacity: int, thread_id=None) -> bytes:
    only_thread = '' if thread_id is None else f'''
        mov rax, qword ptr gs:[0x48]
        cmp eax, {thread_id}
        jne passthrough
    '''  # TEB ClientId.UniqueThread
    code = f'''
        pushfq
        push rax
        {only_thread}
        push rcx
        push rdx
        push r8
        push r9
        push r10
        push r11
        push rbx
        push rsi
        push rdi
        push r12
        push r13
        push r14
        push r15
        sub rsp, 0x60
        movdqu xmmword ptr [rsp], xmm0
        movdqu xmmword ptr [rsp+0x10], xmm1
        movdqu xmmword ptr [rsp+0x20], xmm2
        movdqu xmmword ptr [rsp+0x30], xmm3
        movdqu xmmword ptr [rsp+0x40], xmm4
        movdqu xmmword ptr [rsp+0x50], xmm5
        mov rbx, {data_at}
        mov rax, 1
        xchg qword ptr [rbx+0x10], rax
        test rax, rax
        jnz restore
        mov r12, qword ptr [rbx+8]
        xor r14, r14
    loop_head:
        cmp r14, {capacity}
        jae drained
        mov r13, qword ptr [rbx]
        cmp r12, r13
        jae drained
        mov r15, r12
        and r15, {capacity - 1}
        shl r15, 7
        lea rsi, [rbx+r15+0x40]
        mov rax, 2
        xchg qword ptr [rsi], rax
        sub rsp, 0x40
        mov rax, qword ptr [rsi+0x40]
        mov qword ptr [rsp+0x20], rax
        mov rax, qword ptr [rsi+0x48]
        mov qword ptr [rsp+0x28], rax
        mov rax, qword ptr [rsi+0x50]
        mov qword ptr [rsp+0x30], rax
        mov rax, qword ptr [rsi+0x58]
        mov qword ptr [rsp+0x38], rax
        mov rcx, qword ptr [rsi+0x20]
        mov rdx, qword ptr [rsi+0x28]
        mov r8, qword ptr [rsi+0x30]
        mov r9, qword ptr [rsi+0x38]
        movq xmm0, rcx
        movq xmm1, rdx
        movq xmm2, r8
        movq xmm3, r9
        mov r11, qword ptr [rsi+8]
        call r11
        add rsp, 0x40
        mov qword ptr [rsi+0x10], rax
        movq qword ptr [rsi+0x18], xmm0
        mov rax, {_DONE}
        xchg qword ptr [rsi], rax
        inc r12
        mov qword ptr [rbx+8], r12
        inc r14
        jmp loop_head
    drained:
        mov qword ptr [rbx+0x10], 0
    restore:
        movdqu xmm0, xmmword ptr [rsp]
        movdqu xmm1, xmmword ptr [rsp+0x10]
        movdqu xmm2, xmmword ptr [rsp+0x20]
        movdqu xmm3, xmmword ptr [rsp+0x30]
        movdqu xmm4, xmmword ptr [rsp+0x40]
        movdqu xmm5, xmmword ptr [rsp+0x50]
        add rsp, 0x60
        pop r15
        pop r14
        pop r13
        pop r12
        pop rdi
        pop rsi
        pop rbx
        pop r11
        pop r10
        pop r9
        pop r8
        pop rdx
        pop rcx
    passthrough:
        pop rax
        popfq
    '''
    return bytes(asm(code)[0])


def _argument_bits(value) -> int:
    if isinstance(value, (int, bool)):
        if not -(1 << 63) <= value < (1 << 64): raise OverflowError(f'argument {value!r} does not fit in 64 bits')
        return value & 0xFFFFFFFFFFFFFFFF
    if isinstance(value, ctypes.c_float):
        return struct.unpack('<I', struct.pack('<f', value.value))[0]
    if isinstance(value, (float, ctypes.c_double)):
        return struct.unpack('<Q', struct.pack('<d', value if isinstance(value, float) else value.value))[0]
    raise TypeError(f'unsupported call argument {type(value)!r}')


class CallTicket:
    """A submitted call; wait or close after completion to release its slot."""

    def __init__(self, owner: 'InlineCallQueue', sequence: int, result_type):
        self.owner = owner
        self.sequence = sequence
        self.result_type = result_type
        self._result = _UNSET
        self._error = None

    @property
    def done(self) -> bool:
        return self._error is not None or self._result is not _UNSET or self.owner._atomic.load(self.owner._slot_at(self.sequence)) == _DONE

    def wait(self, timeout_ms=-1):
        if self._result is not _UNSET: return self._result
        if timeout_ms < -1: raise ValueError('timeout_ms must be -1 or nonnegative')
        deadline = None if timeout_ms == -1 else time.monotonic() + timeout_ms / 1000
        polls = 0
        while not self.done:
            if polls % 100 == 0 and not self.owner.process.still_alive():
                raise ProcessLookupError('target exited before inline call completed')
            if deadline is not None and (remaining := deadline - time.monotonic()) <= 0:
                raise TimeoutError(f'inline call not finished in {timeout_ms} ms')
            time.sleep(0.001 if deadline is None else min(0.001, remaining))
            polls += 1
        return self.close()

    def close(self):
        if self._error is not None: raise self._error
        if self._result is not _UNSET: return self._result
        with self.owner._lock:
            if self._result is not _UNSET: return self._result
            at = self.owner._slot_at(self.sequence)
            if self.owner._atomic.load(at) != _DONE: raise RuntimeError('inline call is still pending')
            raw = ctypes.string_at(at + 0x10, 16)
            if self.result_type is int:
                result = struct.unpack_from('<Q', raw)[0]
            elif self.result_type in (float, ctypes.c_double):
                result = struct.unpack_from('<d', raw, 8)[0]
            elif self.result_type is ctypes.c_float:
                result = struct.unpack_from('<f', raw, 8)[0]
            elif self.result_type is None:
                result = None
            else:
                raise TypeError(f'unsupported result type {self.result_type!r}')
            self._result = result
            self.owner._atomic.exchange(at, 0)
            del self.owner._tickets[self.sequence]
            while self.owner._reclaim < self.owner._next and self.owner._reclaim not in self.owner._tickets:
                self.owner._reclaim += 1
            return result


class InlineCallQueue(InlineHook):
    """Call functions on the next entry to a chosen x64 function."""

    def __init__(self, process, addr: int, capacity=16, thread_id=None):
        if not winapi.IS_64BIT: raise OSError('InlineCallQueue requires a 64-bit host')
        if capacity < 1 or capacity > 64 or capacity & (capacity - 1):
            raise ValueError('capacity must be a power of two from 1 to 64')
        if thread_id is not None and not (isinstance(thread_id, int) and 0 < thread_id <= 0xFFFFFFFF):
            raise ValueError(f'thread_id {thread_id!r} is not a thread id')
        wow64 = ctypes.c_long()
        winapi.IsWow64Process(process.handle, ctypes.byref(wow64))
        if wow64.value: raise OSError('InlineCallQueue requires a 64-bit target')
        mbi = process.virtual_query(addr)
        if mbi.State != 0x1000 or not mbi.Protect & 0xF0 or mbi.Protect & 0x100:
            raise ValueError(f'target address {addr:#x} is not executable')
        self.thread_id = thread_id
        self._closed = False
        self._lock = threading.Lock()
        self._tickets = {}
        self._next = self._reclaim = 0
        self._atomic = _AtomicWord()
        try:
            self._shared = _SharedQueue(process, capacity)
            code = _dispatcher_code(self._shared.remote_at, capacity, thread_id)
            super().__init__(process, code, addr)
            self.capacity = capacity
        except BaseException:
            if hasattr(self, '_shared'): self._shared.close()
            self._atomic.close()
            raise

    def _slot_at(self, sequence: int) -> int:
        return self._shared.local_at + _HEADER_SIZE + (sequence & (self.capacity - 1)) * _SLOT_SIZE

    def submit(self, func: int, *args, result_type=int) -> CallTicket:
        if not isinstance(func, int) or not func: raise ValueError('func must be a nonzero address')
        if len(args) > _MAX_ARGS: raise ValueError(f'at most {_MAX_ARGS} arguments are supported')
        if result_type not in (int, float, ctypes.c_float, ctypes.c_double, None):
            raise TypeError(f'unsupported result type {result_type!r}')
        mbi = self.process.virtual_query(func)
        if mbi.State != 0x1000 or not mbi.Protect & 0xF0 or mbi.Protect & 0x100:
            raise ValueError(f'function address {func:#x} is not executable')
        bits = [_argument_bits(value) for value in args]
        bits.extend([0] * (_MAX_ARGS - len(bits)))
        with self._lock:
            if self._closed: raise RuntimeError('inline call queue is closed')
            if self._next - self._reclaim >= self.capacity: raise BufferError('inline call queue is full; wait for completed tickets')
            sequence = self._next
            at = self._slot_at(sequence)
            if self._atomic.load(at): raise RuntimeError('inline call slot is still owned by the target')
            data = struct.pack('<4Q8Q', _WAITING, func, 0, 0, *bits)
            ctypes.memmove(at, data, len(data))
            ticket = self._tickets[sequence] = CallTicket(self, sequence, result_type)
            self._next += 1
            self._atomic.exchange(self._shared.local_at, self._next)
            return ticket

    def call(self, func: int, *args, result_type=int, timeout_ms=-1):
        return self.submit(func, *args, result_type=result_type).wait(timeout_ms)

    def alloc(self):
        if self.alloc_at: return
        cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        cs.detail = True
        instructions, size = read_code(self.process, self.addr, min_size=5, cs=cs)
        for insn in instructions:
            if any(insn.group(group) for group in (capstone.CS_GRP_JUMP, capstone.CS_GRP_CALL, capstone.CS_GRP_RET,
                                                   capstone.CS_GRP_INT, capstone.CS_GRP_IRET)) or any(
                    op.type == capstone.x86.X86_OP_MEM and op.mem.base == capstone.x86.X86_REG_RIP for op in insn.operands):
                raise ValueError(f'cannot relocate instruction at {insn.address:#x}')
        if (self.addr & ~0xFFF) != ((self.addr + size - 1) & ~0xFFF):
            raise ValueError('hook prologue crosses a page boundary')
        if len(self.code) + size + 14 > 0x1000: raise ValueError('hook code exceeds one page')
        alloc_at = self.process.alloc_near(0x1000, self.addr, protect=0x04)
        try:
            orig_code = b''.join(insn.bytes for insn in instructions)
            jump = b'\xE9' + struct.pack('<i', alloc_at - self.addr - 5)
            hook_code = jump + b'\x90' * (size - 5)
            trampoline = self.code + orig_code + b'\xFF\x25\x00\x00\x00\x00' + struct.pack('<Q', self.addr + size)
            self.process.write(alloc_at, trampoline)
            self.process.virtual_protect(alloc_at, 0x1000, 0x20)
            winapi.FlushInstructionCache(self.process.handle, alloc_at, len(trampoline))
        except BaseException:
            self.process.free(alloc_at)
            raise
        self.alloc_at, self.hook_code, self.orig_code = alloc_at, hook_code, orig_code

    @property
    def enabled(self):
        return self._enabled

    @enabled.setter
    def enabled(self, value):
        if self._closed: raise RuntimeError('inline call queue is closed')
        value = bool(value)
        if value == self._enabled: return
        if value:
            self.alloc()
        elif self._tickets or self._atomic.load(self._shared.local_at + 0x10):
            raise RuntimeError('inline calls are still pending or running')
        expected = self.orig_code if value else self.hook_code
        if self.process.read(self.addr, len(expected)) != expected:
            raise RuntimeError('target prologue changed since hook allocation')
        old = self.process.virtual_protect(self.addr, len(expected), 0x40)
        try:
            try:
                self.process.write(self.addr, self.hook_code if value else self.orig_code)
                winapi.FlushInstructionCache(self.process.handle, self.addr, len(expected))
            except BaseException:
                try:
                    if self.process.read(self.addr, len(expected)) != expected:
                        self.process.write(self.addr, expected)
                        winapi.FlushInstructionCache(self.process.handle, self.addr, len(expected))
                except BaseException:
                    self._enabled = value  # retain the trampoline if patch state is uncertain
                    raise RuntimeError('could not restore target prologue after failed hook patch')
                raise
            self._enabled = value
        finally:
            self.process.virtual_protect(self.addr, len(expected), old)

    def free(self):
        if self._closed: return
        if self._enabled: raise RuntimeError('disable the inline call queue first')
        if self._tickets or self._atomic.load(self._shared.local_at + 0x10):
            raise RuntimeError('inline calls are still pending or running')
        if self.alloc_at:
            self.process.free(self.alloc_at)
            self.alloc_at = 0
            self.hook_code = self.orig_code = b''

    def close(self):
        with self._lock:
            if self._closed: return
            if not self.process.still_alive():
                for ticket in self._tickets.values():
                    ticket._error = ProcessLookupError('target exited before inline call completed')
                self._tickets.clear()
                self._shared.close()
                self._atomic.close()
                self.alloc_at = 0
                self._enabled = False
                self._closed = True
                return
            self.enabled = False
            self.free()
            self._shared.close()
            self._atomic.close()
            self._closed = True

    def __enter__(self):
        self.enabled = True
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def __del__(self):
        pass
