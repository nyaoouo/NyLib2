"""AES-256-ECB decryption over Windows BCrypt; the only ctypes loader in nylib/ue."""
import ctypes
import threading
import weakref
from ctypes import wintypes

from ._keys import AesKey

_bcrypt = ctypes.WinDLL('bcrypt')
_bcrypt.BCryptOpenAlgorithmProvider.argtypes = [ctypes.POINTER(ctypes.c_void_p), wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.ULONG]
_bcrypt.BCryptOpenAlgorithmProvider.restype = ctypes.c_long
_bcrypt.BCryptSetProperty.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR, ctypes.c_void_p, wintypes.ULONG, wintypes.ULONG]
_bcrypt.BCryptSetProperty.restype = ctypes.c_long
_bcrypt.BCryptGenerateSymmetricKey.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p, wintypes.ULONG,
                                               ctypes.c_void_p, wintypes.ULONG, wintypes.ULONG]
_bcrypt.BCryptGenerateSymmetricKey.restype = ctypes.c_long
_bcrypt.BCryptDecrypt.argtypes = [ctypes.c_void_p, ctypes.c_void_p, wintypes.ULONG, ctypes.c_void_p, ctypes.c_void_p, wintypes.ULONG,
                                  ctypes.c_void_p, wintypes.ULONG, ctypes.POINTER(wintypes.ULONG), wintypes.ULONG]
_bcrypt.BCryptDecrypt.restype = ctypes.c_long
_bcrypt.BCryptDestroyKey.argtypes = [ctypes.c_void_p]
_bcrypt.BCryptDestroyKey.restype = ctypes.c_long
_bcrypt.BCryptCloseAlgorithmProvider.argtypes = [ctypes.c_void_p, wintypes.ULONG]
_bcrypt.BCryptCloseAlgorithmProvider.restype = ctypes.c_long


def _release(lock, alg, hkey) -> None:
    with lock:
        if hkey:
            _bcrypt.BCryptDestroyKey(hkey)
            hkey.value = None
        if alg:
            _bcrypt.BCryptCloseAlgorithmProvider(alg, 0)
            alg.value = None


class Aes256Ecb:
    """AES-256-ECB (no padding) decryptor backed by one BCrypt key object.

    `decrypt` needs a byte length that is a multiple of 16; `close()` is thread-safe and idempotent,
    and a decryptor dropped without `close()` is released by its finalizer.
    """

    def __init__(self, key: AesKey):
        if not isinstance(key, AesKey):
            raise TypeError(f'Aes256Ecb takes an AesKey, got {type(key).__name__}')
        self._lock = threading.RLock()  # re-entered by close() -> finalizer -> _release
        self._alg = ctypes.c_void_p()
        self._key = ctypes.c_void_p()
        self._finalizer = weakref.finalize(self, _release, self._lock, self._alg, self._key)
        try:
            st = _bcrypt.BCryptOpenAlgorithmProvider(ctypes.byref(self._alg), 'AES', None, 0)
            if st:
                raise OSError(f'BCryptOpenAlgorithmProvider failed {st & 0xFFFFFFFF:#x}')
            mode = ctypes.create_unicode_buffer('ChainingModeECB')
            st = _bcrypt.BCryptSetProperty(self._alg, 'ChainingMode', mode, ctypes.sizeof(mode), 0)
            if st:
                raise OSError(f'BCryptSetProperty failed {st & 0xFFFFFFFF:#x}')
            kb = (ctypes.c_char * 32).from_buffer_copy(key._material())
            try:  # byref, not the buffer or addressof(), so no audit event carries the key
                st = _bcrypt.BCryptGenerateSymmetricKey(self._alg, ctypes.byref(self._key), None, 0, ctypes.byref(kb), 32, 0)
            finally:
                kb.raw = bytes(32)
            if st:
                raise OSError(f'BCryptGenerateSymmetricKey failed {st & 0xFFFFFFFF:#x}')
        except BaseException:
            self.close()
            raise

    def decrypt(self, data) -> bytes:
        n = memoryview(data).nbytes
        if n % 16:
            raise ValueError(f'AES-ECB input must be a multiple of 16 bytes, got {n}')
        src = (ctypes.c_char * n).from_buffer_copy(data)
        dst = ctypes.create_string_buffer(n)
        out = wintypes.ULONG()
        with self._lock:  # one BCryptDecrypt at a time per key object
            if not self._key:
                raise ValueError('Aes256Ecb is closed')
            st = _bcrypt.BCryptDecrypt(self._key, src, n, None, None, 0, dst, n, ctypes.byref(out), 0)
        if st:
            raise OSError(f'BCryptDecrypt failed {st & 0xFFFFFFFF:#x}')
        return dst.raw[:out.value]

    def close(self) -> None:
        with self._lock:  # a second close() returns only after the first has released the key
            self._finalizer()
