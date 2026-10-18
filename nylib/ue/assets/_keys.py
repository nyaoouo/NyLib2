"""AesKey: the AES-256 key carrier between a caller and nylib.ue.assets."""
import os
import re

from ..errors import InvalidKeyError

_HEX64_RE = re.compile(r'[0-9A-Fa-f]{64}')
_GUID_RE = re.compile(r'[0-9A-Fa-f]{32}')
_HEX_OR_SPACE = frozenset(b'0123456789abcdefABCDEF \t\n\r\x0b\x0c')


def _check_path(value, argname: str) -> str:
    if isinstance(value, str):
        text = value
    elif isinstance(value, os.PathLike):
        text = os.fspath(value)
        if not isinstance(text, str):
            raise TypeError(f'{argname} must be a str or os.PathLike[str], got a bytes path')
    else:
        raise TypeError(f'{argname} must be a str or os.PathLike[str], got {type(value).__name__}')
    if '\x00' in text:
        raise ValueError(f'{argname} must not contain a NUL byte')
    return os.path.abspath(text)


def _parse_hex_key(text: str) -> bytes | None:
    body = ''.join(text.split())
    if body[:2] in ('0x', '0X'):
        body = body[2:]
    return bytes.fromhex(body) if _HEX64_RE.fullmatch(body) else None


def _all_hex_or_space(data: bytes) -> bool:
    return all(b in _HEX_OR_SPACE for b in data)


def _parse_key_file(data: bytes) -> bytes | None:
    if len(data) == 32 and not _all_hex_or_space(data):
        return data
    if len(data) > 4096:
        return None
    try:
        text = data.decode('utf-8-sig')
    except UnicodeDecodeError:
        return None
    return _parse_hex_key(text)


class AesKey:
    """The AES-256 key carrier between a caller and nylib.ue.assets; no public route returns the key bytes."""
    __slots__ = ('_key', '_guid')

    def __init__(self, key: bytes | bytearray | memoryview, *, guid: str = '0' * 32):
        guid = _normalize_guid(guid)
        if isinstance(key, str):
            raise TypeError('AesKey takes bytes-like key material; use AesKey.from_hex() or AesKey.from_file() for text')
        try:
            mv = memoryview(key)
        except TypeError:
            raise TypeError(f'AesKey key must be bytes-like, got {type(key).__name__}') from None
        if not mv.c_contiguous:
            raise ValueError('AesKey key must be C-contiguous')
        if mv.nbytes != 32:
            raise ValueError(f'AES key must be 32 bytes, got {mv.nbytes}')
        object.__setattr__(self, '_key', bytes(mv))
        object.__setattr__(self, '_guid', guid)

    def __setattr__(self, name, value):
        raise AttributeError('AesKey is read-only')

    def __delattr__(self, name):
        raise AttributeError('AesKey is read-only')

    @property
    def guid(self) -> str:
        return self._guid

    @classmethod
    def from_hex(cls, text: str, *, guid: str = '0' * 32) -> 'AesKey':
        guid = _normalize_guid(guid)
        if not isinstance(text, str):
            raise TypeError(f'AesKey.from_hex text must be a str, got {type(text).__name__}')
        key = _parse_hex_key(text)
        if key is None:
            raise ValueError('not a 32-byte AES-256 key in hex')
        return cls(key, guid=guid)

    @classmethod
    def from_file(cls, path: str | os.PathLike, *, guid: str = '0' * 32) -> 'AesKey':
        guid = _normalize_guid(guid)
        abspath = _check_path(path, 'path')
        name = os.path.basename(abspath)
        try:
            with open(abspath, 'rb') as f:
                data = f.read(4097)
        except FileNotFoundError as e:
            raise InvalidKeyError(f'AES key file {name} not found', reason='not found', path=abspath, errno=e.errno, winerror=e.winerror) from None
        except OSError as e:
            raise InvalidKeyError(f'AES key file {name} cannot be read', reason='unreadable', path=abspath, errno=e.errno, winerror=e.winerror) from None
        key = _parse_key_file(data)
        del data  # no file content left in this frame when the format error is raised
        if key is None:
            raise InvalidKeyError(f'AES key file {name} is not a 32-byte AES-256 key in hex or raw form', reason='format', path=abspath)
        return cls(key, guid=guid)

    def _material(self) -> bytes:
        """Return the raw key bytes; private to nylib.ue.assets and not documented."""
        return self._key

    def __repr__(self) -> str:
        return f'AesKey(guid={self._guid}, 32 bytes)'

    __str__ = __repr__

    def __format__(self, spec) -> str:
        return self.__repr__()

    def __reduce_ex__(self, protocol):
        raise TypeError('AesKey cannot be pickled: read the key file again in the other process')

    def __getstate__(self):
        raise TypeError('AesKey cannot be pickled: read the key file again in the other process')


def _normalize_guid(value) -> str:
    if not isinstance(value, str):
        raise TypeError(f'guid must be a str, got {type(value).__name__}')
    stripped = value.replace('-', '')
    if not _GUID_RE.fullmatch(stripped):
        raise ValueError('guid must be 32 hex digits, optionally with dashes')
    return stripped.upper()
