"""nylib.pdb - DIA-backed PDB symbol/type reader (msdia140.dll via pybind11).

``pe_info`` and ``symbol_server`` are pure Python (no build needed);
``Session``/``Symbol``/``Type``/``Member``/``DiaError`` are served lazily from
the compiled ``_ny_pdb`` extension - build it once with
``<python> scripts/pdb/build.py`` before using them.

Usage::

    from nylib.pdb import Session, SymTag, symbol_server

    sess = Session.from_pe(r'C:\\Windows\\System32\\user32.dll')  # msdl by default
    for sym in sess.find_symbols('MessageBox*', tag=SymTag.PublicSymbol):
        print(sym.name, hex(sym.rva))

    t = sess.find_type('SomeStruct')
    for member in t.fields():          # instance data members only, no bases/statics
        print(member.name, member.offset, member.type and member.type.name)

    print(sess.describe(sym.rva))      # -> 'Name' or 'Name+0xN'

    # non-msdl server, e.g. Mozilla builds - opt in explicitly, never the default:
    sess = Session.from_pe(pe_path, symsrv_url=symbol_server.MOZILLA_SYMBOLS)
"""
import enum
import importlib
import pathlib
import sys
import typing

from . import pe_info, symbol_server

if typing.TYPE_CHECKING:
    from ._ny_pdb import Session, Symbol, Type, Member, DiaError

__all__ = ['Session', 'Symbol', 'Type', 'Member', 'DiaError', 'SymTag', 'pe_info', 'symbol_server']

_EXT_NAMES = {'Session', 'Symbol', 'Type', 'Member', 'DiaError'}
_ext = None


class SymTag(enum.IntEnum):
    """Mirrors DIA's cvconst ``SymTagEnum``."""
    Null = 0
    Exe = 1
    Compiland = 2
    CompilandDetails = 3
    CompilandEnv = 4
    Function = 5
    Block = 6
    Data = 7
    Annotation = 8
    Label = 9
    PublicSymbol = 10
    UDT = 11
    Enum = 12
    FunctionType = 13
    PointerType = 14
    ArrayType = 15
    BaseType = 16
    Typedef = 17
    BaseClass = 18
    Friend = 19
    FunctionArgType = 20
    FuncDebugStart = 21
    FuncDebugEnd = 22
    UsingNamespace = 23
    VTableShape = 24
    VTable = 25
    Custom = 26
    Thunk = 27
    CustomType = 28
    ManagedType = 29
    Dimension = 30
    CallSite = 31
    InlineSite = 32
    BaseInterface = 33
    VectorType = 34
    MatrixType = 35
    HLSLType = 36
    Caller = 37
    Callee = 38
    Export = 39
    HeapAllocationSite = 40
    CoffGroup = 41
    Inlinee = 42
    TaggedUnionCase = 43


def _session_from_pe(cls, pe_path, *, symsrv_url=symbol_server.DEFAULT_MSDL,
                      cache_dir=None, load_address=None, search_local=True):
    """Open a DIA session for the PDB matching ``pe_path``.

    Search order: next-to-PE (if ``search_local``) -> verified cache -> each
    ``symsrv_url`` in turn; each candidate's ``pdb_signature`` is checked
    against the PE's recorded (guid, age) before being returned.
    """
    info = pe_info.read_debug_info(pe_path)
    dia_error = _ext.DiaError
    wanted = (info.guid, info.age)
    addr = int(info.image_base if load_address is None else load_address)

    def accept(path):
        try:
            sess = cls(str(path))
        except dia_error:
            return None
        if sess.pdb_signature != wanted:
            sess.close()
            return None
        sess.load_address = addr
        return sess

    if search_local:
        local = pathlib.Path(pe_path).resolve().parent / info.pdb_name
        if local.is_file() and (sess := accept(local)) is not None:
            return sess

    cache_hit = symbol_server.cache_path(info.pdb_name, info.guid, info.age, cache_dir)
    if cache_hit.is_file():
        if (sess := accept(cache_hit)) is not None:
            return sess
        cache_hit.unlink(missing_ok=True)  # poisoned cache entry - never returned again

    servers = [symsrv_url] if isinstance(symsrv_url, str) else list(symsrv_url)
    last_err = None
    for one in servers:
        try:
            downloaded = symbol_server.ensure_local(
                info.pdb_name, info.guid, info.age,
                symsrv_url=one, cache_dir=cache_dir, force=True)
        except Exception as e:
            last_err = e
            continue
        if (sess := accept(downloaded)) is not None:
            return sess
        downloaded.unlink(missing_ok=True)  # invalid download - don't leave it as a false hit
        last_err = dia_error(
            f'downloaded PDB does not match {pe_path} (guid={info.guid}, age={info.age}): {downloaded}')
    raise last_err if last_err is not None else dia_error(f'no PDB candidate found for {pe_path}')


def _load_ext():
    global _ext
    if _ext is None:
        try:
            ext = importlib.import_module('._ny_pdb', __name__)
        except ModuleNotFoundError as e:
            if e.name == f'{__name__}._ny_pdb':
                raise ImportError(
                    f'nylib.pdb extension not built - run: {sys.executable} scripts/pdb/build.py'
                ) from e
            raise
        ext.Session.from_pe = classmethod(_session_from_pe)
        _ext = ext
    return _ext


def __getattr__(name):
    if name in _EXT_NAMES:
        return getattr(_load_ext(), name)
    raise AttributeError(f'module {__name__!r} has no attribute {name!r}')
