import ctypes
import datetime
import os
import typing

from .. import winapi

__all__ = ['get_file_version_info', 'get_file_properties']

# ---------------------------------------------------------------------------
# Classic PE version resource (version.dll)
# ---------------------------------------------------------------------------

# Standard StringFileInfo field names (the "Details" fields exposed by PE files).
_VERSION_STRING_FIELDS = (
    'Comments', 'CompanyName', 'FileDescription', 'FileVersion',
    'InternalName', 'LegalCopyright', 'LegalTrademarks', 'OriginalFilename',
    'PrivateBuild', 'ProductName', 'ProductVersion', 'SpecialBuild',
)


def _ver_to_str(ms: int, ls: int) -> str:
    return '%d.%d.%d.%d' % (ms >> 16 & 0xFFFF, ms & 0xFFFF, ls >> 16 & 0xFFFF, ls & 0xFFFF)


def get_file_version_info(path: str) -> typing.Optional[dict]:
    """Read the classic PE version resource of *path*.

    Returns a ``dict`` of version fields, or ``None`` if the file has no version
    resource (which is the case for most non-PE files). The fixed numeric version
    is exposed as ``FileVersion`` / ``ProductVersion`` strings alongside the
    localized string-table fields (``CompanyName``, ``FileDescription`` ...).
    """
    path = os.fspath(path)
    size = winapi.GetFileVersionInfoSizeW(path, None)
    if not size:
        return None
    buf = ctypes.create_string_buffer(size)
    winapi.GetFileVersionInfoW(path, 0, size, buf)

    result: dict = {}
    block = ctypes.c_void_p()
    length = ctypes.c_uint()

    # Fixed file info (root block).
    if winapi.VerQueryValueW(buf, '\\', ctypes.byref(block), ctypes.byref(length)) and length.value:
        ffi = ctypes.cast(block, ctypes.POINTER(winapi.VS_FIXEDFILEINFO)).contents
        result['FileVersion'] = _ver_to_str(ffi.dwFileVersionMS, ffi.dwFileVersionLS)
        result['ProductVersion'] = _ver_to_str(ffi.dwProductVersionMS, ffi.dwProductVersionLS)
        result['FileFlags'] = ffi.dwFileFlags & ffi.dwFileFlagsMask
        result['FileOS'] = ffi.dwFileOS
        result['FileType'] = ffi.dwFileType
        result['FileSubtype'] = ffi.dwFileSubtype

    # Language/codepage translations available in the resource.
    if winapi.VerQueryValueW(buf, '\\VarFileInfo\\Translation', ctypes.byref(block), ctypes.byref(length)) and length.value >= 4:
        words = ctypes.cast(block, ctypes.POINTER(ctypes.c_ushort * (length.value // 2))).contents
        translations = [(words[i], words[i + 1]) for i in range(0, len(words) - 1, 2)]
    else:
        translations = [(0x0409, 0x04B0)]  # fall back to US-English / Unicode codepage

    for lang, codepage in translations:
        prefix = '\\StringFileInfo\\%04x%04x\\' % (lang, codepage)
        for field in _VERSION_STRING_FIELDS:
            if winapi.VerQueryValueW(buf, prefix + field, ctypes.byref(block), ctypes.byref(length)) and length.value:
                value = ctypes.wstring_at(block.value).strip()
                if value:
                    result.setdefault(field, value)
    return result


# ---------------------------------------------------------------------------
# Shell Property Store (the Explorer "Details" tab)
# ---------------------------------------------------------------------------

_IID_IPropertyStore = winapi.GUID('{886D8EEB-8CF2-4446-8D02-CDBA1DBDCF99}')
_IID_IPropertyDescription = winapi.GUID('{6F79D558-3E96-4549-A1D1-7D75D2288814}')

# IPropertyStore vtable indices.
_IPS_RELEASE = 2
_IPS_GETCOUNT = 3
_IPS_GETAT = 4
_IPS_GETVALUE = 5
# IPropertyDescription vtable indices.
_IPD_GETDISPLAYNAME = 6

_COINIT_APARTMENTTHREADED = 0x2
_GPS_DEFAULT = 0

# VARTYPE values (winnt.h / propidl.h).
_VT_EMPTY, _VT_NULL = 0, 1
_VT_I2, _VT_I4, _VT_R4, _VT_R8 = 2, 3, 4, 5
_VT_BSTR, _VT_BOOL = 8, 11
_VT_I1, _VT_UI1, _VT_UI2, _VT_UI4, _VT_I8, _VT_UI8 = 16, 17, 18, 19, 20, 21
_VT_INT, _VT_UINT = 22, 23
_VT_LPSTR, _VT_LPWSTR = 30, 31
_VT_FILETIME = 64
_VT_VECTOR = 0x1000

_EPOCH = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)


def _com_call(ptr, index, restype, argtypes, *args):
    """Invoke COM method #*index* on the interface pointer *ptr* via its vtable."""
    addr = ptr.value if isinstance(ptr, ctypes.c_void_p) else ptr
    vtbl = ctypes.cast(ptr, ctypes.POINTER(ctypes.c_void_p))[0]
    fn_addr = ctypes.cast(ctypes.c_void_p(vtbl), ctypes.POINTER(ctypes.c_void_p))[index]
    proto = ctypes.WINFUNCTYPE(restype, ctypes.c_void_p, *argtypes)
    return proto(fn_addr)(addr, *args)


def _release(ptr):
    if ptr:
        _com_call(ptr, _IPS_RELEASE, ctypes.c_ulong, ())


def _co_initialize() -> bool:
    """Initialize COM for the current thread. Returns True if we must uninitialize."""
    hr = winapi.CoInitializeEx(None, _COINIT_APARTMENTTHREADED)
    # S_OK (0) and S_FALSE (1, already initialized) must both be balanced by a
    # CoUninitialize; RPC_E_CHANGED_MODE (0x80010106) means our call had no effect.
    return hr in (0, 1)


def _cotask_wstr(out: ctypes.c_void_p) -> typing.Optional[str]:
    """Read and free a CoTaskMem-allocated wide string out-parameter."""
    if not out.value:
        return None
    try:
        return ctypes.wstring_at(out.value)
    finally:
        winapi.CoTaskMemFree(out)


def _filetime_to_datetime(ft) -> typing.Optional[datetime.datetime]:
    value = (ft.dwHighDateTime << 32) | ft.dwLowDateTime
    if not value:
        return None
    return _EPOCH + datetime.timedelta(microseconds=value / 10)


def _format_propvariant(pv) -> typing.Optional[str]:
    out = ctypes.c_void_p()
    if winapi.PropVariantToStringAlloc(ctypes.byref(pv), ctypes.byref(out)) != 0:
        return None
    return _cotask_wstr(out)


def _propvariant_to_py(pv):
    """Convert a PROPVARIANT into a native Python value (string fallback otherwise)."""
    vt = pv.vt
    v = pv.val

    if vt & _VT_VECTOR:
        base = vt & 0x0FFF
        count = v.ca.cElems
        if not count:
            return []
        if base in (_VT_LPWSTR, _VT_BSTR):
            arr = ctypes.cast(v.ca.pElems, ctypes.POINTER(ctypes.c_wchar_p))
            return [arr[i] for i in range(count)]
        if base == _VT_LPSTR:
            arr = ctypes.cast(v.ca.pElems, ctypes.POINTER(ctypes.c_char_p))
            return [arr[i].decode('mbcs', 'replace') if arr[i] else None for i in range(count)]
        return _format_propvariant(pv)

    if vt in (_VT_EMPTY, _VT_NULL):
        return None
    if vt in (_VT_LPWSTR, _VT_BSTR):
        return v.pwszVal
    if vt == _VT_LPSTR:
        return v.pszVal.decode('mbcs', 'replace') if v.pszVal else None
    if vt == _VT_BOOL:
        return v.boolVal != 0
    if vt == _VT_I1:
        return v.cVal
    if vt == _VT_UI1:
        return v.bVal
    if vt == _VT_I2:
        return v.iVal
    if vt == _VT_UI2:
        return v.uiVal
    if vt in (_VT_I4, _VT_INT):
        return v.lVal
    if vt in (_VT_UI4, _VT_UINT):
        return v.ulVal
    if vt == _VT_I8:
        return v.hVal
    if vt == _VT_UI8:
        return v.uhVal
    if vt == _VT_R4:
        return v.fltVal
    if vt == _VT_R8:
        return v.dblVal
    if vt == _VT_FILETIME:
        return _filetime_to_datetime(v.filetime)
    # CY, DATE, CLSID and anything else -> formatted display string.
    return _format_propvariant(pv)


def _canonical_name(key) -> typing.Optional[str]:
    out = ctypes.c_void_p()
    if winapi.PSGetNameFromPropertyKey(ctypes.byref(key), ctypes.byref(out)) != 0:
        return None
    return _cotask_wstr(out)


def _display_name(key) -> typing.Optional[str]:
    desc = ctypes.c_void_p()
    if winapi.PSGetPropertyDescription(ctypes.byref(key), ctypes.byref(_IID_IPropertyDescription), ctypes.byref(desc)) != 0 or not desc:
        return _canonical_name(key)
    try:
        out = ctypes.c_void_p()
        if _com_call(desc, _IPD_GETDISPLAYNAME, ctypes.c_long, (ctypes.c_void_p,), ctypes.byref(out)) != 0:
            return _canonical_name(key)
        return _cotask_wstr(out)
    finally:
        _release(desc)


def get_file_properties(path: str, key_style: str = 'canonical') -> dict:
    """Read the Shell Property Store of *path* (the Explorer "Details" tab).

    Works for any file type. Values are converted to native Python types where
    possible (``int``/``float``/``bool``/``str``/``datetime``/``list``); unknown
    types fall back to their formatted display string.

    :param key_style: ``'canonical'`` (default, e.g. ``'System.Author'``) or
        ``'display'`` (the localized label shown in Explorer, e.g. ``'Authors'``).
    """
    if key_style not in ('canonical', 'display'):
        raise ValueError("key_style must be 'canonical' or 'display'")
    path = os.path.abspath(os.fspath(path))
    name_of = _display_name if key_style == 'display' else _canonical_name

    need_uninit = _co_initialize()
    store = ctypes.c_void_p()
    try:
        hr = winapi.SHGetPropertyStoreFromParsingName(
            path, None, _GPS_DEFAULT, ctypes.byref(_IID_IPropertyStore), ctypes.byref(store),
            _ignore_error=True,
        )
        if hr != 0 or not store:
            raise OSError(f'SHGetPropertyStoreFromParsingName failed for {path!r}: 0x{hr & 0xFFFFFFFF:08X}')

        count = ctypes.c_uint()
        _com_call(store, _IPS_GETCOUNT, ctypes.c_long, (ctypes.c_void_p,), ctypes.byref(count))

        result: dict = {}
        for i in range(count.value):
            key = winapi.PROPERTYKEY()
            if _com_call(store, _IPS_GETAT, ctypes.c_long, (ctypes.c_uint, ctypes.c_void_p), i, ctypes.byref(key)) != 0:
                continue
            pv = winapi.PROPVARIANT()
            if _com_call(store, _IPS_GETVALUE, ctypes.c_long, (ctypes.c_void_p, ctypes.c_void_p), ctypes.byref(key), ctypes.byref(pv)) != 0:
                continue
            try:
                value = _propvariant_to_py(pv)
            finally:
                winapi.PropVariantClear(ctypes.byref(pv))
            name = name_of(key) or '%s,%d' % (str(key.fmtid), key.pid)
            result[name] = value
        return result
    finally:
        _release(store)
        if need_uninit:
            winapi.CoUninitialize()
