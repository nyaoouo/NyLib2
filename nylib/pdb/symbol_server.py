"""Microsoft Symbol Server (msdl) client with local disk cache.

URL scheme:
    <symsrv>/<pdb>/<GUID_HEX_UPPER><AGE_HEX_UPPER>/<pdb>
Compressed variants (``.pd_``) are fetched on a plain-URL 404 and expanded
with System32 ``expand.exe`` (never PATH-searched - see ``_expand_exe_path``).
"""
import os
import pathlib
import shutil
import subprocess
import tempfile
import urllib.error
import urllib.parse
import urllib.request

from . import pe_info

DEFAULT_MSDL = 'https://msdl.microsoft.com/download/symbols'
MOZILLA_SYMBOLS = 'https://symbols.mozilla.org/'
# Nothing about symsrv identifies clients strictly, but a symsrv-style UA is
# required - the default urllib UA is rejected.
_UA = 'Microsoft-Symbol-Server/10.0 nylib.pdb/0'
_ALLOWED_REDIRECT_SCHEMES = ('http', 'https')


class _SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Refuses a redirect to a non-http(s) scheme or an https -> http downgrade."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        old_scheme = urllib.parse.urlsplit(req.full_url).scheme
        new_scheme = urllib.parse.urlsplit(newurl).scheme
        if new_scheme not in _ALLOWED_REDIRECT_SCHEMES or (old_scheme == 'https' and new_scheme != 'https'):
            raise urllib.error.URLError(f'refused redirect {old_scheme} -> {new_scheme}: {newurl}')
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_opener = urllib.request.build_opener(_SafeRedirectHandler)


def _nt_symbol_path_stores(value: str) -> list[str]:
    """Pure parser: candidate cache-store dirs named by ``_NT_SYMBOL_PATH``.

    Reuses only downstream store directories, never the upstream. A plain
    directory entry is a search dir, not a cache tree, and is ignored.
    """
    stores = []
    for entry in value.split(';'):
        parts = [p.strip() for p in entry.split('*')]
        head = parts[0].lower()
        if head == 'srv':
            tokens = parts[1:]
            tokens = tokens[:-1] if tokens else tokens  # last token is always the upstream
        elif head == 'cache':
            tokens = parts[1:]
        elif head == 'symsrv' and len(parts) > 1 and parts[1].lower() == 'symsrv.dll':
            tokens = parts[2:]
            tokens = tokens[:-1] if tokens else tokens  # last token is always the upstream
        else:
            continue  # plain directory entry, or unrecognized clause - ignored
        for tok in tokens:
            if tok and pathlib.PureWindowsPath(tok).is_absolute():
                stores.append(tok)
    return stores


def _writable_dir(path: pathlib.Path) -> bool:
    try:
        path.mkdir(parents=True, exist_ok=True)
        probe = path / f'.write_test_{os.getpid()}'
        probe.touch()
        probe.unlink()
        return True
    except OSError:
        return False


def default_cache_dir() -> pathlib.Path:
    """Return the downstream symbol cache directory, creating it if absent.

    Prefers the first writable store dir named by ``_NT_SYMBOL_PATH``, else
    ``%LOCALAPPDATA%\\nylib\\symbols`` / ``~/.cache/nylib/symbols``.
    """
    for store in _nt_symbol_path_stores(os.environ.get('_NT_SYMBOL_PATH', '')):
        p = pathlib.Path(store)
        if _writable_dir(p):
            return p
    if os.name == 'nt':
        root = pathlib.Path(os.environ.get('LOCALAPPDATA', pathlib.Path.home())) / 'nylib' / 'symbols'
    else:
        root = pathlib.Path.home() / '.cache' / 'nylib' / 'symbols'
    root.mkdir(parents=True, exist_ok=True)
    return root


def cache_path(pdb_name, guid, age, cache_dir=None) -> pathlib.Path:
    """Return the local filesystem path a msdl-cached PDB would live at:
    ``<root>/<pdb_name>/<GUID><age_hex_upper>/<pdb_name>``.
    """
    pe_info._validate_bare_name(pdb_name)
    if len(guid) != 32 or not all(c in '0123456789abcdefABCDEF' for c in guid):
        raise ValueError(f'guid must be 32 hex chars: {guid!r}')
    root = pathlib.Path(cache_dir) if cache_dir else default_cache_dir()
    return root / pdb_name / f'{guid.upper()}{age:X}' / pdb_name


def _url_for(symsrv, pdb_name, guid, age):
    q = urllib.parse.quote(pdb_name, safe='')
    key = f'{guid.upper()}{age:X}'
    base = symsrv.rstrip('/')
    return f'{base}/{q}/{key}/{q}'


def _download(url, dest_path, timeout=60):
    """Fetch ``url`` to ``dest_path``. Atomic via temp file + ``os.replace``."""
    req = urllib.request.Request(url, headers={'User-Agent': _UA})
    dest_path = pathlib.Path(dest_path)
    dest_path.parent.mkdir(parents=True, exist_ok=True)
    tmp = tempfile.NamedTemporaryFile(delete=False, dir=str(dest_path.parent),
                                      prefix='.part-', suffix=dest_path.name)
    tmp_name = tmp.name
    tmp.close()
    try:
        with _opener.open(req, timeout=timeout) as r, open(tmp_name, 'wb') as f:
            shutil.copyfileobj(r, f, length=1 << 20)
            if r.length:  # non-zero means the transfer stopped short of Content-Length
                raise OSError(f'truncated download {url}: {r.length} bytes short')
        os.replace(tmp_name, dest_path)
    except BaseException:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise
    return dest_path


def _expand_exe_path() -> str:
    """Full path to the Windows CAB expander - never PATH-searched.

    ``shutil.which('expand')`` can resolve to Git's coreutils tab-expander
    instead of the CAB tool, so the System32 path is built directly.
    """
    return os.path.join(os.environ['SystemRoot'], 'System32', 'expand.exe')


def _expand_cab(cab_path, dest_path) -> None:
    """Expand a compressed CAB (``.pd_``) file onto ``dest_path``, atomically."""
    dest_path = pathlib.Path(dest_path)
    tmp_name = str(dest_path) + f'.expand-{os.getpid()}'
    try:
        try:
            r = subprocess.run([_expand_exe_path(), str(cab_path), tmp_name],
                                capture_output=True)  # bytes: localized output may not decode with the locale codec
        except FileNotFoundError as e:
            raise RuntimeError(f'CAB expander not found at {_expand_exe_path()!r}') from e
        if r.returncode != 0:
            err = (r.stderr or r.stdout).decode('mbcs', errors='replace')
            raise RuntimeError(f'expand.exe failed (rc={r.returncode}): {err}')
        os.replace(tmp_name, dest_path)
    except BaseException:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


def _fetch_one(symsrv, pdb_name, guid, age, dest):
    """Try one symbol server: plain URL, else its compressed ``.pd_`` sibling."""
    url = _url_for(symsrv, pdb_name, guid, age)
    try:
        return _download(url, dest)
    except urllib.error.HTTPError as e:
        if e.code != 404:
            raise RuntimeError(f'{url}: HTTP {e.code} {e.reason}') from e
    except urllib.error.URLError as e:
        raise RuntimeError(f'{url}: {e.reason}') from e
    compressed_url = url[:-1] + '_'
    cab_path = dest.parent / (dest.name + '_')
    try:
        try:
            _download(compressed_url, cab_path)
        except urllib.error.HTTPError as e:
            raise RuntimeError(f'{compressed_url}: HTTP {e.code} {e.reason}') from e
        except urllib.error.URLError as e:
            raise RuntimeError(f'{compressed_url}: {e.reason}') from e
        _expand_cab(cab_path, dest)
    finally:
        try:
            cab_path.unlink(missing_ok=True)
        except OSError:
            pass
    return dest


def ensure_local(pdb_name, guid, age, *, symsrv_url=DEFAULT_MSDL, cache_dir=None, force=False):
    """Return a local path to the PDB, downloading if absent or if ``force``.

    ``symsrv_url`` is a URL or a sequence tried in order; all writes are
    atomic, so an interrupted transfer or expand never leaves a false hit.
    """
    dest = cache_path(pdb_name, guid, age, cache_dir)
    if not force and dest.is_file() and dest.stat().st_size > 0:
        return dest
    servers = [symsrv_url] if isinstance(symsrv_url, str) else list(symsrv_url)
    if not servers:
        raise ValueError('symsrv_url is empty')
    last_err = None
    for symsrv in servers:
        try:
            return _fetch_one(symsrv, pdb_name, guid, age, dest)
        except Exception as e:
            last_err = e
    raise last_err
