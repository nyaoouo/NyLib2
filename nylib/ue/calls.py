"""UFunction call plumbing (C10): parameter roles and layout, call memory, ProcessEvent callers, strict target reads."""
import abc
import atexit
import bisect
import logging
import math
import struct
import sys
import threading
import time
from typing import Callable, NamedTuple

from ..process import Process
from .errors import CallError, MemoryReadError, PendingCallsError
from .flags import EPropertyFlags
from .memory import MemorySource
from .model import FunctionRecord, PropertyRecord

logger = logging.getLogger('nylib.ue.calls')

DEFAULT_TIMEOUT = 10.0  # seconds; Unreal.call_timeout's default
ROLES = ('in', 'const-ref', 'ref', 'out', 'return', 'local')
STATES = ('not started', 'finished', 'unknown')  # CallError.state

_NO_PROCESS = 'calls need a live process; a capture cannot run code'
_STRING_KINDS = {'StrProperty': ('utf-16-le', 2), 'AnsiStrProperty': ('latin-1', 1), 'Utf8StrProperty': ('utf-8', 1)}
_INPUT_ROLES = ('in', 'const-ref', 'ref')
_ARG_LIMIT = 1 << 63
_SLICE_MS = 100
_EXECUTABLE_PROTECT = (0x10, 0x20, 0x40, 0x80)  # PAGE_EXECUTE*
_DRY_BASE = 0x10000


def _is_int(x) -> bool:
    return isinstance(x, int) and not isinstance(x, bool)


def _int(name: str, value) -> int:
    if not _is_int(value):
        raise TypeError(f'{name} must be an int, got {type(value).__name__}')
    return value


def _align_up(value: int, align: int) -> int:
    return (value + align - 1) & -align


def _call_error(message: str, *, state: str, refused=None, timed_out=None, exited=None, exception=None, partial=None) -> CallError:
    return CallError(message, refused=refused, timed_out=timed_out, exited=exited, exception=exception, partial=partial, state=state)


def _starts_with_jump(code: bytes) -> bool:
    """Whether code opens with an unconditional near jump (E9, EB, FF /4), allowing bnd and REX prefixes."""
    i = 0
    while i < len(code) and (code[i] == 0xF2 or 0x40 <= code[i] <= 0x4F):
        i += 1
    return i < len(code) and (code[i] in (0xE9, 0xEB) or code[i] == 0xFF and i + 1 < len(code) and code[i + 1] >> 3 & 7 == 4)


def _closed_error() -> CallError:
    return _call_error('calls are closed in this session', state='not started')


def _check_timeout(timeout) -> None:
    if timeout is None:
        return
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
        raise TypeError(f'timeout must be None or a number, got {type(timeout).__name__}')
    if not math.isfinite(timeout) or timeout <= 0:
        raise ValueError(f'timeout must be greater than 0 and finite, got {timeout!r}')


def _check_call_args(function, args, timeout) -> None:
    if not 1 <= _int('function', function) < _ARG_LIMIT:
        raise ValueError(f'function {function:#x} is outside [1, 2**63)')
    for i, a in enumerate(args):
        if not 0 <= _int(f'argument {i}', a) < _ARG_LIMIT:
            raise ValueError(f'argument {i} ({a:#x}) is outside [0, 2**63)')
    _check_timeout(timeout)


def _string_kind(kind) -> tuple[str, int]:
    if (enc := _STRING_KINDS.get(kind) if isinstance(kind, str) else None) is None:
        raise ValueError(f'kind must be one of {", ".join(_STRING_KINDS)}, got {kind!r}')
    return enc


def param_role(p: PropertyRecord) -> str:
    """The role of a function's property entry: one of ROLES."""
    if not isinstance(p, PropertyRecord):
        raise TypeError(f'expected a PropertyRecord, got {type(p).__name__}')
    f = p.flags
    if not f & EPropertyFlags.Parm:
        return 'local'
    if f & EPropertyFlags.ReturnParm:
        return 'return'
    if f & EPropertyFlags.OutParm:
        return ('const-ref' if f & EPropertyFlags.ConstParm else 'ref') if f & EPropertyFlags.ReferenceParm else 'out'
    return 'in'


class CallLayout(NamedTuple):
    inputs: tuple[PropertyRecord, ...]  # the positional order
    outputs: tuple[PropertyRecord, ...]  # the result order: return value first
    size: int  # bytes of the parameter block: max(fn.params_size, 1)


def layout(fn: FunctionRecord) -> CallLayout:
    """Inputs, outputs and parameter-block size of a function; a parameter outside params_size raises ValueError."""
    if not isinstance(fn, FunctionRecord):
        raise TypeError(f'expected a FunctionRecord, got {type(fn).__name__}')
    inputs, returns, outs = [], [], []
    for p in fn.params:
        if (role := param_role(p)) == 'local':
            continue
        if not (p.offset >= 0 and p.size >= 1 and p.array_dim >= 1 and p.offset + p.size * p.array_dim <= fn.params_size):
            raise ValueError(f'{fn.path}: parameter {p.name!r} at {p.offset:#x} (+{p.size:#x} x {p.array_dim}) does not fit params_size {fn.params_size:#x}')
        if role in _INPUT_ROLES:
            inputs.append(p)
        if role == 'return':
            returns.append(p)
        elif role in ('out', 'ref'):
            outs.append(p)
    return CallLayout(tuple(inputs), tuple(returns + outs), max(fn.params_size, 1))


class _Chunk:
    __slots__ = ('base', 'size', 'executable', 'used', 'mirror')

    def __init__(self, base: int, size: int, executable: bool):
        self.base, self.size, self.executable, self.used, self.mirror = base, size, executable, 0, bytearray()


class CallArena:
    """The call memory of one call: blocks bump-allocated in target chunks, mirrored locally and written once by flush().
    Not a context manager: free() only when the call is known not started or finished, else leak()."""

    CHUNK = 0x10000

    def __init__(self, process):
        self._process = process
        self.dry = process is None
        self._chunks: list[_Chunk] = []
        self._blocks: list[tuple[int, int, bool]] = []
        self._starts: list[int] = []  # sorted block starts
        self._spans: list[tuple[int, int, _Chunk]] = []  # (start, end, chunk), sorted like _starts
        self._released = False
        self._leaked = 0
        self._dry_next = _DRY_BASE

    @property
    def size(self) -> int:
        return 0 if self._released or self.dry else sum(c.size for c in self._chunks)

    @property
    def blocks(self) -> tuple[tuple[int, int, bool], ...]:
        return () if self._released else tuple(self._blocks)

    @property
    def leaked(self) -> int:
        return self._leaked

    def _live(self) -> None:
        if self._released:
            raise ValueError('the call arena is released')

    def _target(self) -> None:
        self._live()
        if self.dry:
            raise ValueError('a dry call arena has no target memory')

    def _new_chunk(self, n: int, executable: bool) -> _Chunk:
        if self.dry:
            base, self._dry_next = self._dry_next, _align_up(self._dry_next + n, 0x10000)
        else:
            protect = 0x40 if executable else 0x04  # PAGE_EXECUTE_READWRITE / PAGE_READWRITE
            try:
                base = self._process.alloc(n, protect)
            except OSError as exc:
                raise _call_error(f'cannot reserve {n:#x} bytes of call memory in the target: {exc}', state='not started') from exc
            if not base:
                raise _call_error(f'cannot reserve {n:#x} bytes of call memory in the target: the allocation returned 0', state='not started')
            logger.debug('reserved %#x bytes of call memory at %#x (%s)', n, base, 'code' if executable else 'data')
        self._chunks.append(chunk := _Chunk(base, n, executable))
        return chunk

    def alloc(self, size: int, *, align: int = 16, executable: bool = False) -> int:
        """Reserve a zeroed block of size bytes aligned to align; returns its address."""
        self._live()
        if _int('size', size) < 1:
            raise ValueError(f'size must be >= 1, got {size}')
        if not 1 <= _int('align', align) <= 0x1000 or align & (align - 1):
            raise ValueError(f'align must be a power of two in 1..0x1000, got {align:#x}')
        executable = bool(executable)
        for c in self._chunks:
            if c.executable == executable and (offset := _align_up(c.base + c.used, align) - c.base) + size <= c.size:
                break
        else:
            c = self._new_chunk(max(self.CHUNK, _align_up(size + align, 0x1000)), executable)
            offset = _align_up(c.base, align) - c.base
        c.used = offset + size
        c.mirror.extend(bytes(c.used - len(c.mirror)))
        address = c.base + offset
        self._blocks.append((address, size, executable))
        i = bisect.bisect_right(self._starts, address)
        self._starts.insert(i, address)
        self._spans.insert(i, (address, address + size, c))
        return address

    def _span(self, address: int, size: int) -> _Chunk:
        _int('address', address)
        if (i := bisect.bisect_right(self._starts, address) - 1) >= 0:
            start, end, c = self._spans[i]
            if address + size <= end:
                return c
        raise ValueError(f'{size:#x} bytes at {address:#x} are outside the call memory')

    def write(self, address: int, data: bytes) -> None:
        """Copy data into the local mirror of one block; the target sees it at flush()."""
        self._live()
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise TypeError(f'data must be bytes-like, got {type(data).__name__}')
        data = bytes(data)
        if not data:
            return
        c = self._span(address, len(data))
        off = address - c.base
        c.mirror[off:off + len(data)] = data

    def peek(self, address: int, size: int) -> bytes:
        """The mirror's bytes of one block."""
        self._live()
        if _int('size', size) < 0:
            raise ValueError(f'size must be >= 0, got {size}')
        if size == 0:
            return b''
        c = self._span(address, size)
        off = address - c.base
        return bytes(c.mirror[off:off + size])

    def fstring(self, text: str, *, kind: str = 'StrProperty') -> bytes:
        """An FString header (16 bytes) whose buffer is a new block holding text and a NUL; '' needs no block."""
        self._live()
        encoding, unit = _string_kind(kind)
        if not isinstance(text, str):
            raise TypeError(f'text must be a str, got {type(text).__name__}')
        try:
            encoded = text.encode(encoding, 'surrogatepass' if unit == 2 else 'strict')
        except UnicodeEncodeError as exc:
            raise ValueError(f'cannot encode {text!r} as {kind}: {exc}') from exc
        if not encoded:
            return bytes(16)
        n = len(encoded) // unit
        block = self.alloc((n + 1) * unit, align=8)
        self.write(block, encoded + bytes(unit))
        return struct.pack('<Qii', block, n + 1, n + 1)

    def flush(self) -> None:
        """Write every chunk's used bytes to the target, in reservation order."""
        self._target()
        for c in self._chunks:
            if c.used:
                try:
                    self._process.write(c.base, bytes(c.mirror[:c.used]))
                except OSError as exc:
                    raise _call_error(f'cannot write call memory at {c.base:#x}: {exc}', state='not started') from exc

    def read(self, address: int, size: int) -> bytes:
        """A strict read of the target inside one block."""
        self._target()
        if _int('size', size) < 0:
            raise ValueError(f'size must be >= 0, got {size}')
        if size == 0:
            return b''
        self._span(address, size)
        try:
            return bytes(self._process.read(address, size, strict=True))
        except OSError as exc:
            raise _call_error(f'cannot read call memory at {address:#x}: {exc}', state='finished') from exc

    def _release(self) -> None:
        self._released = True
        self._chunks, self._blocks, self._starts, self._spans = [], [], [], []

    def free(self) -> None:
        """Free every chunk in the target and release the arena; idempotent, a no-op after leak() and on a dry arena."""
        if self._released or self.dry:
            return
        for c in self._chunks:
            try:
                self._process.free(c.base)
            except OSError as exc:
                logger.warning('cannot free %#x bytes of call memory at %#x: %s', c.size, c.base, exc)
        self._release()

    def leak(self) -> int:
        """Release the arena without freeing its chunks; returns the bytes left in the target (0 when already released)."""
        if self._released:
            return 0
        n = self.size
        self._leaked = n
        self._release()
        return n


class _Transport:
    policy = ''

    def __init__(self, process):
        if process is None:
            raise ValueError(_NO_PROCESS)
        self.process = process
        self.closed = False

    def arena(self) -> CallArena:
        """A new call arena in the target."""
        if self.closed:
            raise _closed_error()
        return CallArena(self.process)

    def call(self, function: int, *args: int, timeout: float | None) -> int:
        """Run function(*args) in the target and return rax; failures raise CallError with a state of STATES."""
        _check_call_args(function, args, timeout)
        if self.closed:
            raise _closed_error()
        t0 = time.perf_counter()
        try:
            return self._call(function, args, timeout)
        finally:
            logger.debug('call %#x via %s: %.2f ms', function, self.policy, (time.perf_counter() - t0) * 1000)

    def _call(self, function: int, args: tuple, timeout: float | None) -> int:
        raise NotImplementedError

    def close(self) -> None:
        """Refuse new calls; calls in flight on other threads are not waited for."""
        self.closed = True


def _exited_error() -> CallError:
    return _call_error('the target exited during the call (it probably crashed)', exited=True, state='finished')


class RemoteThreadTransport(_Transport):
    """ProcessEvent calls on a new thread in an external target (CreateRemoteThread)."""

    policy = 'remote-thread'

    def _start_call(self, function: int, args: tuple):
        return self.process.call(function, *args, block=False)

    def _call(self, function: int, args: tuple, timeout: float | None) -> int:
        process = self.process
        try:
            pending = self._start_call(function, args)
        except OSError as exc:
            raise _call_error(f'the call could not start: {exc}', state='not started') from exc
        deadline = None if timeout is None else time.monotonic() + timeout
        while True:
            wait_ms = _SLICE_MS if deadline is None else max(0, min(_SLICE_MS, math.ceil((deadline - time.monotonic()) * 1000)))
            try:
                result = pending.wait(wait_ms)
                break
            except TimeoutError:
                pass
            except OSError as exc:
                raise self._wait_failed(pending, exc) from exc
            try:
                alive = process.still_alive()
            except OSError:
                alive = True
            if not alive:
                raise _exited_error()
            if deadline is not None and time.monotonic() >= deadline:
                raise _call_error(f'the call did not return within {timeout} s', timed_out=True, state='unknown')
        try:
            alive = process.still_alive()
        except OSError:
            return result
        if not alive:
            raise _exited_error()
        return result

    def _wait_failed(self, pending, exc: OSError) -> CallError:
        try:
            state = 'finished' if pending.done else 'unknown'
        except Exception:
            state = 'unknown'
        try:
            gone = not self.process.still_alive()
        except Exception:
            gone = None
        if self.closed:
            return _call_error(f'the session was closed during the call: {exc}', exited=gone, state=state)
        return _call_error(f'the call failed: {exc}', exited=gone, state=state)


class AnyThreadTransport(_Transport):
    """ProcessEvent calls on the calling thread of the current process; timeouts are ignored."""

    policy = 'any-thread'

    def __init__(self, process):
        super().__init__(process)
        if process.process_id != Process.current.process_id:
            raise ValueError("calls='any-thread' runs ProcessEvent on the calling thread, so it needs the current process")

    def _call(self, function: int, args: tuple, timeout: float | None) -> int:
        try:
            return Process.current.call(function, *args)
        except OSError as exc:
            raise _call_error(f'the call raised {exc} in this process; the game may be unstable', exception=str(exc), state='finished') from exc


def open_transport(policy: str | None, process) -> RemoteThreadTransport | AnyThreadTransport | None:
    """The transport of a calls policy; None for None."""
    if policy is None:
        return None
    if policy == 'remote-thread':
        return RemoteThreadTransport(process)
    if policy == 'any-thread':
        return AnyThreadTransport(process)
    raise ValueError(f'unknown calls policy {policy!r}')


class CallSite(NamedTuple):
    """Live target information supplied once when a session binds a Caller."""
    process: Process
    mem: MemorySource
    process_event_index: int
    process_event_address: int
    find_game_thread: Callable
    default_timeout: float | None
    mode: str = 'external'


class Caller(abc.ABC):
    policy = ''

    def __init__(self):
        self._site = None
        self.closed = False

    @property
    def process(self) -> Process:
        if self._site is None:
            raise RuntimeError('caller is not bound to a session')
        return self._site.process

    def bind(self, site: CallSite) -> None:
        if self.closed or self._site is not None:
            raise ValueError('caller is closed or already bound')
        if site.process is None:
            raise ValueError(_NO_PROCESS)
        self._site = site

    @property
    def pending(self) -> int:
        """Calls that keep close() from finishing; 0 for a caller that tracks none."""
        return 0

    @abc.abstractmethod
    def arena(self) -> CallArena: ...

    @abc.abstractmethod
    def call(self, function: int, *args: int, timeout: float | None) -> int: ...

    def close(self) -> None:
        self.closed = True


class RemoteThreadCaller(Caller):
    policy = 'remote-thread'

    def bind(self, site: CallSite) -> None:
        if site.mode != 'external':
            raise ValueError('RemoteThreadCaller requires an external session')
        super().bind(site)
        self._transport = RemoteThreadTransport(site.process)

    def arena(self) -> CallArena:
        return self._transport.arena()

    def call(self, function: int, *args: int, timeout: float | None) -> int:
        return self._transport.call(function, *args, timeout=timeout)

    def close(self) -> None:
        if hasattr(self, '_transport'):
            self._transport.close()
        super().close()


class AnyThreadCaller(RemoteThreadCaller):
    policy = 'any-thread'

    def bind(self, site: CallSite) -> None:
        if site.mode != 'internal':
            raise ValueError('AnyThreadCaller requires an internal session')
        Caller.bind(self, site)
        self._transport = AnyThreadTransport(site.process)


class _ApcTransport(RemoteThreadTransport):
    policy = 'apc'

    def __init__(self, process, thread):
        super().__init__(process)
        self.thread = thread

    def _start_call(self, function: int, args: tuple):
        return self.process.call(function, *args, block=False, queue_apc_thread=self.thread)


class ApcCaller(RemoteThreadCaller):
    """Queue a call on a target thread when it enters an alertable wait."""
    policy = 'apc'

    def __init__(self, thread=None):
        super().__init__()
        self.thread = thread
        self._owned_thread = None

    def bind(self, site: CallSite) -> None:
        Caller.bind(self, site)
        try:
            if self.thread is None:
                self._owned_thread = site.find_game_thread()
                self.thread = self._owned_thread
            elif _is_int(self.thread):
                self._owned_thread = site.process.get_thread(self.thread)
                self.thread = self._owned_thread
            if getattr(self.thread, 'process_id', None) != site.process.process_id:
                raise ValueError('APC thread is not in the target process')
            self._transport = _ApcTransport(site.process, self.thread)
        except OSError as exc:
            self.close()
            raise ValueError('APC thread cannot be opened or queried') from exc
        except BaseException:
            self.close()
            raise

    def close(self) -> None:
        super().close()
        if self._owned_thread is not None:
            self._owned_thread.close()
            self._owned_thread = None


def check_hook_dependencies():
    """Import nylib.winutils.inline_call (keystone-engine, capstone) and return it, or raise CallError(refused='dependencies')."""
    try:
        from ..winutils import inline_call
    except Exception as exc:  # the import runs nylib.utils.pip.required, which can fail with any type
        cause = f'{type(exc).__name__}: {exc}'
        if getattr(sys, 'frozen', False):
            text = (f"calls='game-thread' needs keystone-engine and capstone ({cause}); this bundle lacks the packages or their DLLs (keystone.dll, capstone.dll); "
                    'freeze with the nylib PyInstaller hooks (nylib/__pyinstaller: hook-keystone.py, hook-capstone.py), as the pyinstaller40 entry point or '
                    'through --additional-hooks-dir, with both packages installed in the build environment (pip install ".[asm]") and not excluded')
        else:
            text = (f"calls='game-thread' needs keystone-engine and capstone ({cause}); install them beforehand (pip install \".[asm]\"); "
                    'nylib.utils.pip installs missing packages on first use unless PYTHON_PIP_ALL_REQ_INSTALLED is set')
        raise _call_error(text, refused='dependencies', state='not started') from exc
    return inline_call


class HookCaller(Caller):
    """Run calls through ProcessEvent from a thread-filtered detour on the trigger (ProcessEvent unless trigger= is set)."""
    policy = 'game-thread'

    def __init__(self, thread_id=None, trigger=None, capacity=16):
        super().__init__()
        self.thread_id, self.trigger, self.capacity = thread_id, trigger, capacity
        self._lock = threading.Lock()
        self._queue = None
        self._tickets = []
        self._broken = False

    def bind(self, site: CallSite) -> None:
        Caller.bind(self, site)
        try:
            inline_call = check_hook_dependencies()
            if self.thread_id is None:
                with site.find_game_thread() as thread:
                    self.thread_id = thread.thread_id
            if not _is_int(self.thread_id) or self.thread_id <= 0:
                raise ValueError('thread_id must be a positive thread id')
            try:
                with site.process.get_thread(self.thread_id, da=0x0800) as thread:
                    if thread.process_id != site.process.process_id:
                        raise ValueError('hook thread is not in the target process')
            except OSError as exc:
                raise ValueError(f'hook thread {self.thread_id} cannot be opened') from exc
            if self.trigger is None:
                self.trigger = site.process_event_address
            if not _is_int(self.trigger) or self.trigger <= 0:
                raise ValueError('trigger must be a nonzero executable address')
            try:
                code = inline_call.is_executable(site.process, self.trigger)
            except OSError:
                code = False
            if not code:
                raise ValueError(f'trigger {self.trigger:#x} is not in committed executable memory')
            if not _is_int(self.capacity) or self.capacity < 1 or self.capacity > 64 or self.capacity & (self.capacity - 1):
                raise ValueError('capacity must be a power of two from 1 to 64')
        except BaseException:
            self.close()
            raise

    @property
    def pending(self) -> int:
        with self._lock:
            return sum(1 for ticket in self._tickets if not ticket.done)

    def arena(self) -> CallArena:
        if self.closed:
            raise _closed_error()
        return CallArena(self.process)

    def _sweep_done_tickets(self) -> None:
        for ticket in tuple(self._tickets):
            if ticket.done:
                self._tickets.remove(ticket)
                try:
                    ticket.close()
                except (OSError, RuntimeError):  # a ticket the dead target failed keeps its error; its slot is gone with the target
                    pass

    def _get_queue(self):
        if self._broken:
            raise RuntimeError('hook installation failed and cleanup is pending')
        if self._queue is None:
            from ..winutils.inline_call import InlineCallQueue
            queue = InlineCallQueue(self.process, self.trigger, self.capacity, self.thread_id, quiescent_patch=True)
            self._queue = queue
            _track(self)
            try:
                queue.enabled = True
            except BaseException:
                try:
                    queue.close()
                    self._queue = None
                    _untrack(self)
                except Exception:
                    self._broken = True
                raise
        return self._queue

    def _jump_hint(self) -> str:
        try:
            jump = _starts_with_jump(read_target(self.process, self.trigger, 16))
        except (MemoryReadError, ValueError):
            return ''
        return ('; the trigger already starts with a jump (another hook?); if it is a hook left by an earlier nylib session that was not closed, '
                'only a game restart removes it') if jump else ''

    def call(self, function: int, *args: int, timeout: float | None) -> int:
        _check_call_args(function, args, timeout)
        if self.process.process_id == Process.current.process_id and threading.get_native_id() == self.thread_id:
            raise _call_error('a HookCaller cannot wait for a call on its own trigger thread', state='not started')
        with self._lock:
            if self.closed:
                raise _closed_error()
            from ..winutils.inline_call import PrologueError
            try:
                queue = self._get_queue()
            except PrologueError as exc:
                raise _call_error(f'the hook refused the trigger prologue: {exc}{self._jump_hint()}', refused='prologue', state='not started') from exc
            except (ValueError, OSError, BufferError, RuntimeError) as exc:
                raise _call_error(f'the hook could not install: {exc}', state='not started') from exc
            self._sweep_done_tickets()
            try:
                ticket = queue.submit(function, *args)
            except (ValueError, OSError, BufferError, RuntimeError) as exc:
                raise _call_error(f'the hook could not queue the call: {exc}', state='not started') from exc
            self._tickets.append(ticket)
        try:
            return ticket.wait(-1 if timeout is None else math.ceil(timeout * 1000))
        except TimeoutError as exc:
            raise _call_error(f'the call did not return within {timeout} s', timed_out=True, state='unknown') from exc
        except ProcessLookupError as exc:
            raise _call_error(f'the target exited during the call: {exc}', exited=True, state='finished') from exc
        except (OSError, RuntimeError) as exc:
            raise _call_error(f'the hook call failed: {exc}', state='unknown') from exc
        finally:
            with self._lock:
                if ticket in self._tickets and ticket.done:
                    ticket.close()
                    self._tickets.remove(ticket)

    def close(self) -> None:
        with self._lock:
            self._close_locked()

    def _close_locked(self) -> None:
        if self.closed:
            return
        if self._queue is not None:
            for ticket in tuple(self._tickets):
                if ticket.done:
                    ticket.close()
                    self._tickets.remove(ticket)
            if self._tickets and self.process.still_alive():
                raise PendingCallsError('inline calls are still pending; retry close after they finish', pending=len(self._tickets))
            self._queue.close()
            _untrack(self)
        super().close()


_hook_callers = set()  # HookCallers holding an installed queue; the exit handler removes their hooks
_hook_callers_lock = threading.Lock()


def _track(caller: HookCaller) -> None:
    with _hook_callers_lock:
        _hook_callers.add(caller)


def _untrack(caller: HookCaller) -> None:
    with _hook_callers_lock:
        _hook_callers.discard(caller)


def _hook_where(caller: HookCaller) -> str:
    trigger = getattr(caller, 'trigger', None)
    pid = getattr(getattr(getattr(caller, '_site', None), 'process', None), 'process_id', None)
    trigger = trigger if _is_int(trigger) else 0
    return f'the game-thread hook at {trigger:#x} in process {pid}'


def _close_hooks_at_exit() -> None:
    """Remove the hooks of the HookCallers still holding one; never waits for pending calls and never raises."""
    try:
        with _hook_callers_lock:
            callers = tuple(_hook_callers)
        for caller in callers:
            try:
                if not caller._lock.acquire(timeout=1):
                    logger.warning('at exit: %s stays installed: it is in use', _hook_where(caller))
                    continue
                try:
                    caller._close_locked()
                finally:
                    caller._lock.release()
            except PendingCallsError as exc:
                logger.warning('at exit: %s stays installed: %s calls pending', _hook_where(caller), getattr(exc, 'pending', '?'))
            except Exception as exc:
                logger.warning('at exit: %s could not be removed: %s', _hook_where(caller), exc)
    except Exception:
        logger.exception('at exit: removing the game-thread hooks failed')


atexit.register(_close_hooks_at_exit)


def resolve_caller(value) -> Caller | None:
    if value is None:
        return value
    if isinstance(value, Caller):
        if not isinstance(value.policy, str) or not value.policy:
            raise ValueError('Caller.policy must be a nonempty string')
        return value
    if isinstance(value, str):
        constructors = {'remote-thread': RemoteThreadCaller, 'any-thread': AnyThreadCaller, 'game-thread': HookCaller}
        if value in constructors:
            return constructors[value]()
        raise ValueError(f"calls must be 'remote-thread', 'any-thread', 'game-thread', or a Caller instance, got {value!r}")
    raise TypeError(f'calls must be None, a string, or a Caller instance, got {type(value).__name__}')


def process_event_address(process, mem: MemorySource, obj: int, pe_index: int) -> int:
    """The object's own vtable entry pe_index, refused with CallError unless it lies in committed executable memory."""
    if _int('obj', obj) <= 0:
        raise ValueError(f'obj must be > 0, got {obj}')
    if _int('pe_index', pe_index) < 1:
        raise ValueError(f'pe_index must be >= 1, got {pe_index}')
    vft = mem.ptr(obj)
    pe = mem.ptr(vft + 8 * pe_index)
    try:
        mbi = process.virtual_query(pe)
        protect = int(mbi.Protect)
        code = int(mbi.State) == 0x1000 and protect & 0xFF in _EXECUTABLE_PROTECT and not protect & 0x100  # MEM_COMMIT, no PAGE_GUARD
    except OSError:
        code = False
    if not code:
        raise _call_error(f'vtable entry {pe_index} of the object at {obj:#x} is {pe:#x}, which is not executable code; nothing was called',
                          refused='vtable', state='not started')
    return pe


def process_event(transport, obj: int, function: int, pe: int, params: int, *, timeout: float | None) -> None:
    """Run pe(obj, function, params) through the transport."""
    for name, value in (('obj', obj), ('function', function), ('pe', pe), ('params', params)):
        if _int(name, value) <= 0:
            raise ValueError(f'{name} must be > 0, got {value}')
    transport.call(pe, obj, function, params, timeout=timeout)


def read_target(process, address: int, size: int) -> bytes:
    """A strict read of the target that no region map stands between."""
    if _int('address', address) < 0 or _int('size', size) < 0 or address + size > 1 << 64:
        raise ValueError(f'invalid range: {size:#x} bytes at {address:#x}')
    if size == 0:
        return b''
    try:
        return bytes(process.read(address, size, strict=True))
    except OSError as exc:
        raise MemoryReadError(address, size, f'winerror {exc.winerror}') from exc


def read_fstring(mem: MemorySource, header: bytes, *, kind: str = 'StrProperty', max_units: int = 1 << 20) -> str:
    """The text of a 16-byte FString header, read through mem (any object with read(address, size))."""
    if not isinstance(header, (bytes, bytearray, memoryview)):
        raise TypeError(f'header must be bytes-like, got {type(header).__name__}')
    if len(header := bytes(header)) != 16:
        raise ValueError(f'an FString header is 16 bytes, got {len(header)}')
    encoding, unit = _string_kind(kind)
    _int('max_units', max_units)
    data, num, mx = struct.unpack('<Qii', header)
    if not (0 <= num <= mx and (num == 0 or data != 0)):
        raise ValueError(f'corrupt FString header (Data {data:#x}, Num {num}, Max {mx})')
    if num > max_units:
        raise ValueError(f'FString of {num} units exceeds max_units {max_units}')
    if num <= 1:
        return ''
    raw = mem.read(data, (num - 1) * unit)
    if unit == 2:
        return raw.decode(encoding, 'surrogatepass').split('\0', 1)[0]
    return raw.split(b'\0', 1)[0].decode(encoding)
