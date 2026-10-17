import contextlib
import ctypes
import sys
import threading
import typing
import weakref
from ._buf import int_arg, pinned, view
from ._data import _with_views
from ._lib import OodleError, current

_MAX_WINDOW = 1 << 24  # OODLENETWORK1_MAX_DICTIONARY_SIZE
_OVERREAD = 5  # OODLENETWORK1_DECOMP_BUF_OVERREAD_LEN
_S32_MAX = 0x7FFFFFFF

_PAGE = 0x1000
_MEM_COMMIT_RESERVE, _MEM_RELEASE = 0x3000, 0x8000  # MEM_COMMIT|MEM_RESERVE, MEM_RELEASE
_PAGE_RW, _PAGE_NOACCESS = 0x04, 0x01

_k32 = None


def _kernel32():
    """kernel32's VirtualAlloc/Free/Protect, bound on first use."""
    global _k32
    if _k32 is None:
        k = ctypes.WinDLL('kernel32', use_last_error=True)
        k.VirtualAlloc.restype = ctypes.c_void_p
        k.VirtualAlloc.argtypes = (ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint32, ctypes.c_uint32)
        k.VirtualFree.argtypes = (ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint32)
        k.VirtualProtect.argtypes = (ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint32))
        _k32 = k
    return _k32


class _GuardedBuffer:
    """`capacity` writable bytes ending at a PAGE_NOACCESS guard page; `slot(n)` ends an n-byte access exactly at the guard.

    Allocation fails closed: a failed VirtualAlloc or guard VirtualProtect frees what it got and raises before any use.
    """
    __slots__ = ('base', 'guard', 'capacity')

    def __init__(self):
        self.base = self.guard = self.capacity = 0

    def _alloc(self, n: int):
        span = (n + _PAGE - 1) // _PAGE * _PAGE
        k = _kernel32()
        if not (base := k.VirtualAlloc(None, span + _PAGE, _MEM_COMMIT_RESERVE, _PAGE_RW)):
            raise MemoryError(f'VirtualAlloc of {span + _PAGE} bytes failed (WinError {ctypes.get_last_error()})')
        if not k.VirtualProtect(base + span, _PAGE, _PAGE_NOACCESS, ctypes.byref(ctypes.c_uint32())):
            err = ctypes.get_last_error()
            k.VirtualFree(base, 0, _MEM_RELEASE)
            raise OSError(0, f'VirtualProtect could not arm the guard page (WinError {err})', None, err)
        self.base, self.guard, self.capacity = base, base + span, span

    def slot(self, n: int) -> int:
        """Address where an n-byte access ends at the guard page; grows the region when needed (caller holds the lock)."""
        if n > self.capacity:
            self.free()
            self._alloc(n)
        return self.guard - n

    def free(self):
        if self.base:
            _k32.VirtualFree(self.base, 0, _MEM_RELEASE)
            self.base = self.guard = self.capacity = 0


def _release(*guards: _GuardedBuffer):
    for g in guards:
        g.free()


def _checked_size(lib, name: str, v: int, raw: int | None = None) -> int:
    if v < (1 if raw is None else raw):
        raise OodleError(f'{name} returned {v}' + ('' if raw is None else f' ({raw} raw bytes)'), func=name, result=v, path=lib.path)
    return v


def _copy_into(buf, mv: memoryview):
    with memoryview(buf) as m, m.cast('B') as b:
        b[:mv.nbytes] = mv


def _training_views(training, views: list):
    """Append a validated byte view of every training packet to `views`; the caller releases them."""
    try:
        it = iter(training)
    except TypeError:
        raise TypeError(f'training must be an iterable of bytes-like objects, not {type(training).__name__}') from None
    for i, item in enumerate(it):
        if i >= _S32_MAX:
            raise ValueError(f'training has more than {_S32_MAX} packets')
        views.append(mv := view(item, f'training[{i}]'))
        if mv.nbytes > _S32_MAX:
            raise ValueError(f'training[{i}] is {mv.nbytes} bytes, at most {_S32_MAX}')


class _Codec:
    _proto = ''  # 'UDP' or 'TCP'
    _name = ''  # public name used in missing-export errors

    def __init__(self, window, hash_bits: int = 19, training: typing.Iterable = ()):
        """Copy `window` (at most 16 MiB), build its hash table of 2**hash_bits entries (8..24) and train on `training`.

        Binds the net DLL that is the default now; `training` is read only during this call.
        """
        hash_bits = int_arg(hash_bits, 'hash_bits', 8, 24)
        with view(window, 'window') as mv:
            if (n_window := mv.nbytes) > _MAX_WINDOW:
                raise ValueError(f'window is {n_window} bytes, at most {_MAX_WINDOW}')
            self._window = ctypes.create_string_buffer(max(n_window, 1))  # Shared keeps pointers into it
            _copy_into(self._window, mv)
        packets = []
        try:
            _training_views(training, packets)
            self._lib = lib = current('net')
            p, needed_by = self._proto, self._name
            state_size = lib.require(f'OodleNetwork1{p}_State_Size', needed_by)
            train = lib.require(f'OodleNetwork1{p}_Train', needed_by)
            shared_size = lib.require('OodleNetwork1_Shared_Size', needed_by)
            set_window = lib.require('OodleNetwork1_Shared_SetWindow', needed_by)
            self._shared = ctypes.create_string_buffer(_checked_size(lib, 'OodleNetwork1_Shared_Size', shared_size(hash_bits)))
            set_window(self._shared, hash_bits, self._window, n_window)
            self._state = ctypes.create_string_buffer(_checked_size(lib, f'OodleNetwork1{p}_State_Size', state_size()))
            with contextlib.ExitStack() as stack:
                if n := len(packets):
                    ptrs = (ctypes.c_void_p * n)(*(stack.enter_context(pinned(mv)) for mv in packets))
                    sizes = (ctypes.c_int32 * n)(*(mv.nbytes for mv in packets))
                else:
                    ptrs = sizes = None
                train(self._state, self._shared, ptrs, sizes, n)
        finally:
            for mv in packets: mv.release()

    def compress(self, src) -> bytes:
        """Encode one packet; a result of `len(src)` bytes is the packet stored as is."""
        with view(src, 'src') as mv:
            if not (n_src := mv.nbytes):
                return b''
            return self._encode(mv, n_src)

    def _encode(self, mv: memoryview, n_src: int) -> bytes:
        lib, func = self._lib, f'OodleNetwork1{self._proto}_Encode'
        encode = lib.require(func, f'{self._name}.compress')
        size_needed = lib.require('OodleNetwork1_CompressedBufferSizeNeeded', f'{self._name}.compress')
        comp = ctypes.create_string_buffer(_checked_size(lib, 'OodleNetwork1_CompressedBufferSizeNeeded', size_needed(n_src), n_src))
        with pinned(mv) as p_src:
            n = encode(self._state, self._shared, p_src, n_src, comp)
        if not 0 <= n <= n_src:
            raise OodleError(f'{func} returned {n} ({n_src} raw bytes)', func=func, result=n, path=lib.path)
        return bytes(memoryview(comp)[:n])

    def decompress(self, src, raw_size: int, *, out=None) -> bytes | memoryview:
        """Decode one packet to exactly `raw_size` bytes; with `out`, write into it and return the view `out[:raw_size]`.

        `raw_size` must be the packet's original length. Never writes `out[raw_size:]`; `src` may overlap `out`.
        """
        raw_size = int_arg(raw_size, 'raw_size', 0, sys.maxsize)
        return _with_views(self._decompress, src, out, raw_size)

    def _decode_error(self, func: str, ok: int, raw_size: int, n_src: int) -> OodleError:
        return OodleError(f'{func} returned {ok}, expected {raw_size} ({n_src} compressed bytes; '
                          f'wrong raw_size, corrupt data, or a window, hash_bits or training mismatch)',
                          func=func, result=ok, expected=raw_size, path=self._lib.path)

    def __reduce_ex__(self, protocol):
        raise TypeError(f'{type(self).__name__} objects cannot be pickled or copied')


class UdpCodec(_Codec):
    """Oodle Network 1 UDP codec: packets are independent and the state is const, so one instance may serve many threads."""
    _proto, _name = 'UDP', 'oodle.UdpCodec'

    def _decompress(self, src: memoryview, out: memoryview | None, raw_size: int):
        if out is not None and out.nbytes < raw_size:
            raise ValueError(f'out is {out.nbytes} bytes, raw_size is {raw_size}')
        if not raw_size:
            return b'' if out is None else out[:0]
        func, n_src = 'OodleNetwork1UDP_Decode', src.nbytes
        decode = self._lib.require(func, 'oodle.UdpCodec.decompress')
        comp = ctypes.create_string_buffer(n_src + _OVERREAD)  # zero-padded: Decode may read past compLen
        _copy_into(comp, src)
        with pinned(out, writable=True) as p_out:
            if out is None:
                p_out = buf = ctypes.create_string_buffer(raw_size)
            ok = decode(self._state, self._shared, comp, n_src, p_out, raw_size)
        if not ok:
            raise self._decode_error(func, ok, raw_size, n_src)
        return buf.raw if out is None else out[:raw_size]


class TcpCodec(_Codec):
    """Oodle Network 1 TCP codec: an adaptive state for one stream direction; decode is guarded and any failure poisons the instance.

    Serves packets of one direction in order; rebuild a desynced stream from an earlier copy(). The lock gives memory safety, not ordering.
    """
    _proto, _name = 'TCP', 'oodle.TcpCodec'

    def __init__(self, window, hash_bits: int = 19, training: typing.Iterable = ()):
        self._poisoned = False
        self._lock = threading.Lock()
        self._out, self._comp = _GuardedBuffer(), _GuardedBuffer()
        super().__init__(window, hash_bits, training)
        self._arm_finalizer()

    def _arm_finalizer(self):
        fin = weakref.finalize(self, _release, self._out, self._comp)
        fin.atexit = False

    def _check_poison(self):
        if self._poisoned:
            raise OodleError('this TcpCodec is poisoned by an earlier failure; rebuild the stream from an earlier copy()',
                             path=self._lib.path)

    def _encode(self, mv: memoryview, n_src: int) -> bytes:
        with self._lock:
            self._check_poison()
            try:
                return super()._encode(mv, n_src)
            except BaseException:
                self._poisoned = True
                raise

    def _decompress(self, src: memoryview, out: memoryview | None, raw_size: int):
        if out is not None and out.nbytes < raw_size:
            raise ValueError(f'out is {out.nbytes} bytes, raw_size is {raw_size}')
        with self._lock:
            self._check_poison()
            if not raw_size:
                return b'' if out is None else out[:0]
            func, n_src = 'OodleNetwork1TCP_Decode', src.nbytes
            decode = self._lib.require(func, 'oodle.TcpCodec.decompress')
            comp = self._comp.slot(n_src + _OVERREAD)
            with pinned(src) as p_src:
                ctypes.memmove(comp, p_src, n_src)
            ctypes.memset(comp + n_src, 0, _OVERREAD)
            dst = self._out.slot(raw_size)
            try:
                ok = decode(self._state, self._shared, comp, n_src, dst, raw_size)
                if not ok:
                    raise self._decode_error(func, ok, raw_size, n_src)
                return self._copy_out(dst, raw_size, out)
            except OSError as e:
                self._poisoned = True
                raise OodleError(f'{func} faulted on a mismatched packet (out-of-bounds access); the TCP stream is '
                                 f'desynchronised and this codec is now unusable (rebuild it from an earlier copy())',
                                 func=func, expected=raw_size, path=self._lib.path) from e
            except BaseException:
                self._poisoned = True
                raise

    def _copy_out(self, dst: int, raw_size: int, out):
        with memoryview((ctypes.c_char * raw_size).from_address(dst)).cast('B') as b:
            if out is None:
                return bytes(b)
            out[:raw_size] = b
        return out[:raw_size]

    def copy(self) -> 'TcpCodec':
        """A new codec with a copy of the current state; the window, hash table and bound DLL are shared, not copied."""
        with self._lock:
            self._check_poison()
            lib = self._lib
            init_as_copy = lib.require('OodleNetwork1TCP_State_InitAsCopy', 'oodle.TcpCodec.copy')
            state_size = lib.require('OodleNetwork1TCP_State_Size', 'oodle.TcpCodec.copy')
            new = TcpCodec.__new__(TcpCodec)
            new._poisoned, new._lock = False, threading.Lock()
            new._out, new._comp = _GuardedBuffer(), _GuardedBuffer()
            new._lib, new._window, new._shared = lib, self._window, self._shared
            new._state = ctypes.create_string_buffer(_checked_size(lib, 'OodleNetwork1TCP_State_Size', state_size()))
            init_as_copy(new._state, self._state)
            new._arm_finalizer()
        return new
