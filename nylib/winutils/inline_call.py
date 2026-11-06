import ctypes
import logging
import os
import struct
import threading
import time
import typing

from .. import winapi
from .inline_hook import InlineHook, PrologueError, _absolute_jump, _allocate_jump, _read_prologue, _relocate_prologue, asm, capstone
from .vtable_hook import VTableHook


logger = logging.getLogger(__name__)

_HEADER_SIZE = 64
_SLOT_SIZE = 128
_MAX_ARGS = 8
_WAITING = 1
_RUNNING = 2
_DONE = 3
_WITHDRAWN = 4
_UNSET = object()
_THREAD_PATCH_ACCESS = 0x080A  # THREAD_QUERY_LIMITED_INFORMATION|GET_CONTEXT|SUSPEND_RESUME
_PATCH_RETRIES = 32
_open_queues = set()
_open_queues_lock = threading.Lock()

_gil_kernel32 = ctypes.PyDLL('kernel32.dll')
_gil_suspend = _gil_kernel32.SuspendThread
_gil_suspend.argtypes = (ctypes.c_void_p,)
_gil_suspend.restype = ctypes.c_ulong
_gil_resume = _gil_kernel32.ResumeThread
_gil_resume.argtypes = (ctypes.c_void_p,)
_gil_resume.restype = ctypes.c_ulong
_gil_get_context = _gil_kernel32.GetThreadContext
_gil_get_context.argtypes = (ctypes.c_void_p, ctypes.c_void_p)
_gil_get_context.restype = ctypes.c_bool
_gil_exit_code = _gil_kernel32.GetExitCodeThread
_gil_exit_code.argtypes = (ctypes.c_void_p, ctypes.c_void_p)
_gil_exit_code.restype = ctypes.c_bool


def is_executable(process, addr: int) -> bool:
    """Whether addr lies in committed, executable, non-guard memory of the process."""
    mbi = process.virtual_query(addr)
    return mbi.State == 0x1000 and bool(mbi.Protect & 0xF0) and not mbi.Protect & 0x100


def _thread_call(func, handle):
    result = func(handle)
    if result == 0xFFFFFFFF: raise ctypes.WinError()
    return result


def _thread_exited(handle):
    code = ctypes.c_ulong()
    return bool(_gil_exit_code(handle, ctypes.byref(code))) and code.value != 259  # STILL_ACTIVE


def _run_quiescent(process, ranges, action, *, busy=None):
    own_tid = winapi.GetCurrentThreadId() if process.process_id == winapi.GetCurrentProcessId() else None
    storage = ctypes.create_string_buffer(ctypes.sizeof(winapi.CONTEXT) + 15)
    context = winapi.CONTEXT.from_address((ctypes.addressof(storage) + 15) & ~15)
    for _ in range(_PATCH_RETRIES):
        threads = []
        try:
            for thread in process.iter_threads(da=_THREAD_PATCH_ACCESS): threads.append(thread)
        except BaseException:
            for thread in threads: thread.close()
            raise
        suspended = []
        occupied = False
        try:
            for thread in threads:
                if thread.thread_id == own_tid: continue
                try:
                    _thread_call(_gil_suspend, thread.handle)
                except OSError:
                    if _thread_exited(thread.handle): continue
                    raise
                suspended.append(thread)
            for thread in suspended:
                context.ContextFlags = winapi.CONTEXT_CONTROL
                if not _gil_get_context(thread.handle, ctypes.addressof(context)): raise ctypes.WinError()
                rip = context.Rip
                if any(start <= rip < end for start, end in ranges):
                    occupied = True
                    break
            if busy is not None and busy(): occupied = True
            if not occupied:
                action()
                return
        finally:
            resume_error = None
            for thread in reversed(suspended):
                try:
                    _thread_call(_gil_resume, thread.handle)
                except OSError as exc:
                    if resume_error is None: resume_error = exc
            for thread in threads: thread.close()
            if resume_error is not None: raise resume_error
        time.sleep(0.002)
    raise RuntimeError('could not find a quiescent interval to patch the inline hook')


class _AtomicWord:
    def __init__(self):
        self.at = winapi.VirtualAllocEx(winapi.GetCurrentProcess(), 0, 0x1000, 0x3000, 0x04)
        try:
            code = (b'\x48\x89\xd0\x48\x87\x01\xc3' + b'\x48\x31\xc0\xf0\x48\x0f\xb1\x01\xc3'
                    + b'\x48\x89\xd0\xf0\x4c\x0f\xb1\x01\xc3')
            ctypes.memmove(self.at, code, len(code))
            winapi.VirtualProtectEx(winapi.GetCurrentProcess(), self.at, 0x1000, 0x20, ctypes.byref(ctypes.c_ulong()))
            winapi.FlushInstructionCache(winapi.GetCurrentProcess(), self.at, len(code))
            fn = ctypes.CFUNCTYPE(ctypes.c_uint64, ctypes.c_void_p, ctypes.c_uint64)
            self.exchange = fn(self.at)
            self.load = ctypes.CFUNCTYPE(ctypes.c_uint64, ctypes.c_void_p)(self.at + 7)
            self.compare_exchange = ctypes.CFUNCTYPE(ctypes.c_uint64, ctypes.c_void_p, ctypes.c_uint64, ctypes.c_uint64)(self.at + 16)
        except BaseException:
            self.close()
            raise

    def close(self):
        if self.at:
            winapi.VirtualFreeEx(winapi.GetCurrentProcess(), self.at, 0, 0x8000)
            self.at = 0


class _SharedQueue:
    def __init__(self, process, capacity):
        self.size = (_HEADER_SIZE + capacity * _SLOT_SIZE + 0xFFF) & ~0xFFF
        self.mapping = process.map_shared(self.size)
        self.local_at = self.mapping.local_at
        self.remote_at = self.mapping.remote_at

    def close(self, *, keep_target_view: bool = False):
        if keep_target_view: self.mapping.remote_at = 0
        self.mapping.close()
        self.local_at = self.remote_at = 0


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
        mov rax, {_WAITING}
        mov rcx, {_RUNNING}
        lock cmpxchg qword ptr [rsi], rcx
        jne next_slot
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
    next_slot:
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


def _dispatcher_code_v1(data_at: int, capacity: int, thread_id=None) -> bytes:
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


class _NylibHook(typing.NamedTuple):
    page: int
    data_at: int
    capacity: int
    thread_id: int | None
    size: int
    original: bytes
    held: bool


def _find_nylib_hook(process, addr: int) -> _NylibHook | None:
    """The call-queue hook nylib installed at addr, matched byte for byte, or None."""
    if not isinstance(addr, int) or isinstance(addr, bool): raise TypeError('addr must be an int')
    if not 0 < addr < 1 << 64: return None
    n = min(32, 0x1000 - (addr & 0xFFF))
    try:
        trigger = process.read(addr, n)
        if trigger[:1] == b'\xE9' and len(trigger) >= 5:
            jlen = 5
            target = addr + 5 + int.from_bytes(trigger[1:5], 'little', signed=True)
        elif trigger[:6] == b'\xFF\x25\0\0\0\0' and len(trigger) >= 15 and trigger[14] == 0x90:
            jlen = 15
            target = int.from_bytes(trigger[6:14], 'little')
        else:
            return None
        if not 0 < target < 0x8000_0000_0000 or target & 0xFFF: return None
        mbi = process.virtual_query(target)
        if (mbi.State != 0x1000 or mbi.Protect & 0xFF not in (0x20, 0x40) or mbi.Protect & 0x100
                or mbi.BaseAddress + mbi.RegionSize < target + 0x1000): return None
        page = process.read(target, 0x1000)
    except (OSError, ValueError):
        return None
    cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    cs.detail = True
    data_at = capacity = thread_id = None
    teb = False
    for insn in cs.disasm(page, target, count=64):
        ops = insn.operands
        if len(ops) != 2 or ops[0].type != capstone.x86.X86_OP_REG: continue
        reg = ops[0].reg
        if insn.mnemonic in ('mov', 'movabs'):
            if reg == capstone.x86.X86_REG_RBX and ops[1].type == capstone.x86.X86_OP_IMM and data_at is None:
                data_at = ops[1].imm
            if (reg == capstone.x86.X86_REG_RAX and ops[1].type == capstone.x86.X86_OP_MEM
                    and ops[1].mem.segment == capstone.x86.X86_REG_GS and ops[1].mem.disp == 0x48): teb = True
        elif insn.mnemonic == 'cmp' and ops[1].type == capstone.x86.X86_OP_IMM:
            if reg == capstone.x86.X86_REG_R14 and capacity is None: capacity = ops[1].imm
            if reg == capstone.x86.X86_REG_EAX and teb and thread_id is None: thread_id = ops[1].imm & 0xFFFFFFFF
    if not data_at or capacity is None or not 1 <= capacity <= 64 or capacity & (capacity - 1) or thread_id == 0: return None
    for generator in (_dispatcher_code, _dispatcher_code_v1):
        code = generator(data_at, capacity, thread_id)
        if page[:len(code)] == code: break
    else:
        return None
    start = len(code)
    size = 0
    for insn in cs.disasm(page[start:], target + start):
        if any(insn.group(group) for group in (capstone.CS_GRP_JUMP, capstone.CS_GRP_CALL, capstone.CS_GRP_RET,
                                               capstone.CS_GRP_INT, capstone.CS_GRP_IRET)) or any(
                op.type == capstone.x86.X86_OP_MEM and op.mem.base == capstone.x86.X86_REG_RIP for op in insn.operands): return None
        size += insn.size
        if size >= jlen: break
    if size < jlen or size > n or trigger[jlen:size] != b'\x90' * (size - jlen): return None
    if page[start + size:start + size + 14] != _absolute_jump(addr + size): return None
    with _open_queues_lock:
        held = (process.process_id, data_at) in _open_queues
    return _NylibHook(target, data_at, capacity, thread_id, size, page[start:start + size], held)


class _HookOwner(typing.NamedTuple):
    pid: int
    view_at: int


def _queue_view_mapped(process, data_at):
    try:
        mbi = process.virtual_query(data_at)
    except (OSError, ValueError):
        return False
    return (mbi.State == 0x1000 and mbi.Protect & 0xFF == 0x04 and not mbi.Protect & 0x100
            and mbi.BaseAddress + mbi.RegionSize >= data_at + _HEADER_SIZE)


def _hook_owner(process, hook) -> _HookOwner | None:
    try:
        if not _queue_view_mapped(process, hook.data_at): return None
        return _HookOwner(*struct.unpack('<QQ', process.read(hook.data_at + 0x18, 16, strict=True)))
    except (OSError, ValueError):
        return None


def _owner_running(owner) -> bool | None:
    if owner is None: return None
    pid, view_at = owner
    if pid == 0 or pid == os.getpid(): return False
    if pid > 0xFFFF_FFFF or view_at == 0 or view_at >= 0x8000_0000_0000: return None
    from ..process import Process
    try:
        process = Process(pid, da=0x1010)
    except OSError as exc:
        return False if getattr(exc, 'winerror', None) == 87 else None
    try:
        try:
            if not process.still_alive(): return False
        except OSError:
            return None
        try:
            return process.read(view_at + 0x18, 16, strict=True) == struct.pack('<QQ', pid, view_at)
        except OSError:
            return False
    finally:
        process.close()


def _replace_bytes(process, addr, expected, new) -> None:
    n = len(expected)
    if process.read(addr, n, strict=True) != expected:
        raise RuntimeError('the stale hook changed before it could be removed')
    old = process.virtual_protect(addr, n, 0x40)
    try:
        try:
            process.write(addr, new)
            winapi.FlushInstructionCache(process.handle, addr, n)
        except BaseException:
            try:
                if process.read(addr, n, strict=True) != expected:
                    process.write(addr, expected)
                    winapi.FlushInstructionCache(process.handle, addr, n)
            except BaseException as exc:
                raise RuntimeError('could not restore the stale hook after a failed write or flush; the trigger may hold either') from exc
            raise
    finally:
        process.virtual_protect(addr, n, old)


def _remove_nylib_hook(process, addr, hook) -> int:
    from ..process import SharedMemoryMapping
    if not _queue_view_mapped(process, hook.data_at):
        raise RuntimeError(f"the stale hook's queue view at {hook.data_at:#x} is not mapped")
    producer, consumer = struct.unpack('<QQ', process.read(hook.data_at, 16, strict=True))
    count = max(0, min(hook.capacity, producer - consumer))
    expected = process.read(addr, hook.size, strict=True)
    jumps = [b'\xff\x25\x00\x00\x00\x00' + struct.pack('<Q', hook.page) + b'\x90']
    relative = hook.page - addr - 5
    if -(1 << 31) <= relative < 1 << 31: jumps.append(b'\xe9' + struct.pack('<i', relative))
    if not any(len(jump) <= hook.size and expected == jump + b'\x90' * (hook.size - len(jump)) for jump in jumps):
        raise RuntimeError('the stale hook changed before it could be removed')
    _run_quiescent(process, ((addr, addr + hook.size),), lambda: _replace_bytes(process, addr, expected, hook.original))
    what = f'its dispatcher page {hook.page:#x} and queue view {hook.data_at:#x}'
    try:
        _run_quiescent(process, ((hook.page, hook.page + 0x1000),), lambda: process.free(hook.page),
                       busy=lambda: struct.unpack('<Q', process.read(hook.data_at + 0x10, 8, strict=True))[0] != 0)
        what = f'its queue view {hook.data_at:#x}'
        SharedMemoryMapping(process, remote_at=hook.data_at).close()
    except (OSError, RuntimeError) as err:
        logger.warning(f'removed the stale hook at {addr:#x} but could not release {what}: {err}')
    return count


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

    def __init__(self, owner: '_CallQueue', sequence: int, result_type):
        self.owner = owner
        self.sequence = sequence
        self.result_type = result_type
        self._result = _UNSET
        self._error = None
        self._withdrawn = False
        self._exit_slot = None

    @property
    def withdrawn(self) -> bool:
        return self._withdrawn

    @property
    def exit_slot(self) -> int | None:
        """The slot word read when the target's exit ended this ticket; None otherwise."""
        return self._exit_slot

    def withdraw(self) -> bool:
        """Stop a call that has not started; True when it will never run."""
        with self.owner._lock:
            if self._result is not _UNSET: return False
            if self._error is not None: raise self._error
            if self._withdrawn: return True
            if self.owner._closed: raise RuntimeError('inline call queue is closed')
            previous = self.owner._atomic.compare_exchange(self.owner._slot_at(self.sequence), _WAITING, _WITHDRAWN)
            if previous == _WAITING:
                self._withdrawn = True
                del self.owner._tickets[self.sequence]
                self.owner._withdrawn[self.sequence] = self
                self.owner._release_withdrawn()
                return True
            if previous in (_RUNNING, _DONE): return False
            raise RuntimeError(f'inline call slot is in an unexpected state {previous}')

    @property
    def done(self) -> bool:
        if self._error is not None or self._result is not _UNSET or self._withdrawn: return True
        with self.owner._lock:
            if self._error is not None or self._result is not _UNSET or self._withdrawn or self.owner._closed: return True
            return self.owner._atomic.load(self.owner._slot_at(self.sequence)) == _DONE

    def wait(self, timeout_ms=-1):
        if self._result is not _UNSET: return self._result
        if timeout_ms < -1: raise ValueError('timeout_ms must be -1 or nonnegative')
        deadline = None if timeout_ms == -1 else time.monotonic() + timeout_ms / 1000
        polls = 0
        while not self.done:
            if polls % 100 == 0 and not self.owner.process.still_alive():
                with self.owner._lock:
                    if self._withdrawn: raise RuntimeError('inline call was withdrawn')
                    if self._result is not _UNSET: return self._result
                    if not self.owner._closed and self._exit_slot is None:
                        self._exit_slot = self.owner._atomic.compare_exchange(self.owner._slot_at(self.sequence), _WAITING, _WITHDRAWN)
                    if self._error is None:
                        self._error = ProcessLookupError('target exited before inline call completed')
                    raise self._error
            if deadline is not None and (remaining := deadline - time.monotonic()) <= 0:
                raise TimeoutError(f'inline call not finished in {timeout_ms} ms')
            time.sleep(0.001 if deadline is None else min(0.001, remaining))
            polls += 1
        return self.close()

    def close(self):
        if self._error is not None: raise self._error
        if self._result is not _UNSET: return self._result
        with self.owner._lock:
            if self._error is not None: raise self._error
            if self._result is not _UNSET: return self._result
            if self._withdrawn: raise RuntimeError('inline call was withdrawn')
            if self.owner._closed: raise RuntimeError('inline call queue is closed')
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
            self.owner._release_withdrawn()
            return result


class _CallQueue:
    """Share a bounded call queue with a function entry dispatcher."""

    def __init__(self, process, addr: int, capacity=16, thread_id=None):
        if not winapi.IS_64BIT: raise OSError('call queue requires a 64-bit host')
        if capacity < 1 or capacity > 64 or capacity & (capacity - 1):
            raise ValueError('capacity must be a power of two from 1 to 64')
        if thread_id is not None and not (isinstance(thread_id, int) and 0 < thread_id <= 0xFFFFFFFF):
            raise ValueError(f'thread_id {thread_id!r} is not a thread id')
        wow64 = ctypes.c_long()
        winapi.IsWow64Process(process.handle, ctypes.byref(wow64))
        if wow64.value: raise OSError('call queue requires a 64-bit target')
        self.thread_id = thread_id
        self._closed = False
        self._lock = threading.Lock()
        self._tickets = {}
        self._withdrawn = {}
        self._next = self._reclaim = 0
        self._registry_key = None
        self._atomic = _AtomicWord()
        try:
            self._shared = _SharedQueue(process, capacity)
            ctypes.memmove(self._shared.local_at + 0x18, struct.pack('<QQ', os.getpid(), self._shared.local_at), 16)
            self._registry_key = (process.process_id, self._shared.remote_at)
            with _open_queues_lock:
                _open_queues.add(self._registry_key)
            code = _dispatcher_code(self._shared.remote_at, capacity, thread_id)
            super().__init__(process, code, addr)
            self.capacity = capacity
        except BaseException:
            with _open_queues_lock:
                _open_queues.discard(self._registry_key)
            if hasattr(self, '_shared'): self._shared.close()
            self._atomic.close()
            raise

    def _slot_at(self, sequence: int) -> int:
        return self._shared.local_at + _HEADER_SIZE + (sequence & (self.capacity - 1)) * _SLOT_SIZE

    def _release_withdrawn(self):
        consumer = self._atomic.load(self._shared.local_at + 8)
        for sequence in list(self._withdrawn):
            if sequence < consumer:
                self._atomic.exchange(self._slot_at(sequence), 0)
                del self._withdrawn[sequence]
        while self._reclaim < self._next and self._reclaim not in self._tickets and self._reclaim not in self._withdrawn:
            self._reclaim += 1

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
            self._release_withdrawn()
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

    def free(self):
        if self._closed: return
        if self._enabled: raise RuntimeError('disable the call queue first')
        if self._tickets: raise RuntimeError('inline calls are still pending or running')
        self._free_hook()

    def close(self):
        with self._lock:
            if self._closed: return
            if not self.process.still_alive():
                for ticket in self._tickets.values():
                    if ticket._exit_slot is None:
                        ticket._exit_slot = self._atomic.compare_exchange(self._slot_at(ticket.sequence), _WAITING, _WITHDRAWN)
                    ticket._error = ProcessLookupError('target exited before inline call completed')
                self._tickets.clear()
                self._withdrawn.clear()
                self._shared.close(keep_target_view=True)
                self._atomic.close()
                self.alloc_at = 0
                self._enabled = False
                self._closed = True
                with _open_queues_lock:
                    _open_queues.discard(self._registry_key)
                return
            self.enabled = False
            self.free()
            self._withdrawn.clear()
            self._shared.close()
            self._atomic.close()
            self._closed = True
            with _open_queues_lock:
                _open_queues.discard(self._registry_key)

    def __enter__(self):
        self.enabled = True
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def __del__(self):
        pass


class InlineCallQueue(_CallQueue, InlineHook):
    """Call functions on the next entry to a chosen x64 function."""

    def __init__(self, process, addr: int, capacity=16, thread_id=None, *, quiescent_patch=False, _jmp_support=0):
        if _jmp_support not in (0, 1): raise ValueError('_jmp_support must be 0 or 1')
        if not is_executable(process, addr):
            raise ValueError(f'target address {addr:#x} is not executable')
        super().__init__(process, addr, capacity, thread_id)
        self.quiescent_patch = bool(quiescent_patch)
        self._jmp_support = _jmp_support

    def alloc(self):
        if self.alloc_at: return
        alloc_at, jump = _allocate_jump(self.process, self.addr, protect=0x04)
        try:
            instructions, size = _read_prologue(self.process, self.addr, len(jump), _jmp_support=self._jmp_support)
            orig_code = b''.join(insn.bytes for insn in instructions)
            hook_code = jump + b'\x90' * (size - len(jump))
            relocated = _relocate_prologue(instructions, self.addr, size, alloc_at + len(self.code), _jmp_support=self._jmp_support)
            trampoline = self.code + relocated + _absolute_jump(self.addr + size)
            if len(trampoline) > 0x1000: raise ValueError('hook code exceeds one page')
            self.process.write(alloc_at, trampoline)
            self.process.virtual_protect(alloc_at, 0x1000, 0x20)
            winapi.FlushInstructionCache(self.process.handle, alloc_at, len(trampoline))
        except BaseException:
            self.process.free(alloc_at)
            raise
        self.alloc_at, self.hook_code, self.orig_code = alloc_at, hook_code, orig_code

    def _free_hook(self):
        if self.alloc_at:
            if self.quiescent_patch:
                self._run_quiescent(((self.alloc_at, self.alloc_at + 0x1000),), self._release_code, idle=True)
            else:
                if self._atomic.load(self._shared.local_at + 0x10):
                    raise RuntimeError('inline calls are still pending or running')
                self._release_code()

    def _release_code(self):
        self.process.free(self.alloc_at)
        self.alloc_at = 0
        self.hook_code = self.orig_code = b''

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
        elif self._tickets or (not self.quiescent_patch and self._atomic.load(self._shared.local_at + 0x10)):
            raise RuntimeError('inline calls are still pending or running')
        expected = self.orig_code if value else self.hook_code
        if self.quiescent_patch:
            self._patch_quiescent(value, expected)
        else:
            self._patch_bytes(value, expected)

    def _patch_quiescent(self, value, expected):
        self._run_quiescent(((self.addr, self.addr + len(expected)),), lambda: self._patch_bytes(value, expected))

    def _run_quiescent(self, ranges, action, *, idle=False):
        busy = (lambda: self._atomic.load(self._shared.local_at + 0x10)) if idle else None
        _run_quiescent(self.process, ranges, action, busy=busy)

    def _patch_bytes(self, value, expected):
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

class VTableCallQueue(_CallQueue, VTableHook):
    """Call functions before a virtual function, then jump to its original pointer."""

    @property
    def enabled(self):
        return VTableHook.enabled.fget(self)

    @enabled.setter
    def enabled(self, value):
        if self._closed: raise RuntimeError('vtable call queue is closed')
        if not value and self._enabled and (self._tickets or self._atomic.load(self._shared.local_at + 0x10)):
            raise RuntimeError('inline calls are still pending or running')
        VTableHook.enabled.fset(self, value)

    def _free_hook(self):
        if self._atomic.load(self._shared.local_at + 0x10):
            raise RuntimeError('inline calls are still pending or running')
        VTableHook.free(self)
