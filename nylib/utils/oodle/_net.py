import contextlib
import ctypes
import sys
import typing
from ._buf import int_arg, pinned, view
from ._data import _with_views
from ._lib import OodleError, current

_MAX_WINDOW = 1 << 24  # OODLENETWORK1_MAX_DICTIONARY_SIZE
_OVERREAD = 5  # OODLENETWORK1_DECOMP_BUF_OVERREAD_LEN
_S32_MAX = 0x7FFFFFFF


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
