import ctypes
import os
import struct
import sys
import sysconfig
import threading
import typing

_DIR = os.path.dirname(os.path.abspath(__file__))
_NAMES = {'core': 'oo2core_9_win64.dll', 'net': 'oo2net_9_win64.dll'}
_MINIMAL = {'core': ('OodleLZ_Decompress',), 'net': ('OodleNetwork1_Shared_Size', 'OodleNetwork1_Shared_SetWindow')}

_p, _s, _i = ctypes.c_void_p, ctypes.c_ssize_t, ctypes.c_int32
_PROTOTYPES = {  # name: (restype, argtypes)
    'core': {
        'OodleLZ_Decompress': (_s, (_p, _s, _p, _s, _i, _i, _i, _p, _s, _p, _p, _p, _s, _i)),
        'OodleLZ_Compress': (_s, (_i, _p, _s, _p, _i, _p, _p, _p, _p, _s)),
        'OodleLZ_GetCompressedBufferSizeNeeded': (_s, (_i, _s)),
        'Oodle_GetConfigValues': (None, (_p,)),
    },
    'net': {
        'OodleNetwork1_Shared_Size': (_s, (_i,)),
        'OodleNetwork1_Shared_SetWindow': (None, (_p, _i, _p, _i)),
        'OodleNetwork1_CompressedBufferSizeNeeded': (_s, (_s,)),
        'OodleNetwork1UDP_State_Size': (_s, ()),
        'OodleNetwork1TCP_State_Size': (_s, ()),
        'OodleNetwork1UDP_Train': (None, (_p, _p, _p, _p, _i)),
        'OodleNetwork1TCP_Train': (None, (_p, _p, _p, _p, _i)),
        'OodleNetwork1UDP_Encode': (_s, (_p, _p, _p, _s, _p)),
        'OodleNetwork1TCP_Encode': (_s, (_p, _p, _p, _s, _p)),
        'OodleNetwork1UDP_Decode': (_i, (_p, _p, _p, _s, _p, _s)),
        'OodleNetwork1TCP_Decode': (_i, (_p, _p, _p, _s, _p, _s)),
        'OodleNetwork1TCP_State_InitAsCopy': (None, (_p, _p)),
    },
}


class OodleError(Exception):
    """A DLL load failure or a failed native Oodle call; the full DLL path is only in `path`."""
    func: str | None
    result: int | None
    expected: int | None
    path: str | None

    def __init__(self, message, *, func=None, result=None, expected=None, path=None):
        super().__init__(message)
        self.func, self.result, self.expected, self.path = func, result, expected, path


def _reason(e: OSError) -> str:
    if isinstance(code := getattr(e, 'winerror', None), int):
        return f'[WinError {code}] {ctypes.FormatError(code)}'
    if isinstance(e, FileNotFoundError):
        return f'[WinError 126] {ctypes.FormatError(126)}'
    return type(e).__name__


class _Lib:
    """One loaded Oodle DLL with its bound exports; never unloaded."""

    def __init__(self, kind: str, path: str, bundled: bool):
        self.kind, self.path, self.bundled = kind, path, bundled
        try:
            self.cdll = ctypes.CDLL(path)
        except OSError as e:
            raise OodleError(f'cannot load {self.describe()}: {_reason(e)}', path=path) from e
        self._funcs = {}
        for name, (restype, argtypes) in _PROTOTYPES[kind].items():
            if (f := getattr(self.cdll, name, None)) is None: continue
            f.restype, f.argtypes = restype, argtypes  # for dll() users
            self._funcs[name] = ctypes.CFUNCTYPE(restype, *argtypes)((name, self.cdll))  # private: immune to dll() edits
        for name in _MINIMAL[kind]:
            self.require(name, 'oodle.load')

    def describe(self) -> str:
        file = os.path.basename(self.path)
        return f'the bundled Oodle {self.kind} DLL ({file})' if self.bundled else f'the Oodle {self.kind} DLL given to oodle.load() ({file})'

    def require(self, name: str, needed_by: str):
        if (f := self._funcs.get(name)) is None:
            raise OodleError(f'{self.describe()} does not export {name}, needed by {needed_by}', func=name, path=self.path) from None
        return f


_lock = threading.Lock()
_cache: dict[tuple, _Lib] = {}
_defaults: dict[str, _Lib | None] = {'core': None, 'net': None}


def _kind_arg(kind) -> str:
    if not (isinstance(kind, str) and kind in _NAMES):
        raise ValueError(f"kind must be 'core' or 'net' (got a {type(kind).__name__})")
    return 'core' if kind == 'core' else 'net'


def _open(kind: str, path: str | None) -> _Lib:
    """Load (or reuse) a DLL; caller holds `_lock`."""
    if not (sys.platform == 'win32' and sysconfig.get_platform() == 'win-amd64'):
        raise OodleError('Oodle DLLs are Windows x64 only')
    bundled = path is None
    if bundled: path = os.path.join(_DIR, _NAMES[kind])
    key = (kind, os.path.normcase(path), bundled)
    if (lib := _cache.get(key)) is None:
        lib = _cache[key] = _Lib(kind, path, bundled)
    return lib


def current(kind: str) -> _Lib:
    """The process default for `kind`, lazy-loading the bundled DLL."""
    if (lib := _defaults[kind]) is None:
        with _lock:
            if (lib := _defaults[kind]) is None:
                lib = _defaults[kind] = _open(kind, None)
    return lib


def load(kind: typing.Literal['core', 'net'], path: str | os.PathLike | None = None) -> None:
    """Load a DLL now and make it the process default for `kind`; on failure the previous default stays."""
    kind = _kind_arg(kind)
    if path is not None:
        if not isinstance(path := os.fspath(path), str):
            raise TypeError(f'path must be str or os.PathLike[str], not {type(path).__name__}')
        path = os.path.abspath(path)
    with _lock:
        _defaults[kind] = _open(kind, path)


def dll(kind: typing.Literal['core', 'net']) -> ctypes.CDLL:
    """The current default DLL's raw ctypes handle; `._name` is its absolute path."""
    return current(_kind_arg(kind)).cdll


def version() -> str:
    """The Oodle version of the current core DLL, e.g. '2.9.14'."""
    get_config = current('core').require('Oodle_GetConfigValues', 'oodle.version')
    get_config(buf := ctypes.create_string_buffer(256))  # zeroed and larger than any known config struct
    v = struct.unpack_from('<I', buf, 24)[0]
    return f'2.{(v >> 16) & 0xFF}.{(v >> 8) & 0xFF}'
