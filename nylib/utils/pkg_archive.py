import base64
import pathlib
import pickle
import zlib

finder_identifier = '_IsNyPkgArchiveFinder0001'

# Template used for top-level packed scripts (is_main=True).
#
# Behaviour depends on the baked-in `_PKG` constant:
#
#   _PKG is None   -- backward-compatible top-level mode. Modules in the
#                     archive are registered with no prefix; the entry
#                     script runs as bare __main__ with no __package__.
#                     Useful when packed code uses absolute imports
#                     against sibling names (e.g. `import rpc_server`).
#
#   _PKG is a str  -- wrapped mode. The whole archive is registered
#                     under "<_PKG>." prefix, a synthetic top-level
#                     `<_PKG>` package module is inserted into
#                     sys.modules, and the entry script runs with
#                     __package__=_PKG so relative imports
#                     (`from .core import x`) resolve.
template_main = f'''
def __pkg_loader__(archive_code):
    import sys
    _PKG = {{package_name!r}}
    for _finder in sys.meta_path:
        if hasattr(_finder, {finder_identifier!r}):
            finder = _finder
            break
    else:
        import base64,importlib.abc,importlib.machinery,importlib.util,inspect,pickle,zlib
        class _NyPkgArchiveLoader(importlib.abc.Loader):
            def __init__(self, code): self.code = code
            def create_module(self, spec): return None
            def exec_module(self, module): exec(self.code, module.__dict__)
        class _NyPkgArchiveFinder(importlib.abc.MetaPathFinder):
            def __init__(self): self.archive = {{{{}}}}
            def reg(self, name, archive):
                prefix = '' if name == '__main__' else name + '.'
                for _name, data in pickle.loads(zlib.decompress(base64.b85decode(archive))).items(): self.archive[prefix + _name] = data
            def exec_pkg(self, name, globals_):
                try:
                    f = inspect.currentframe().f_back
                    name = f.f_globals['__name__']
                    while f.f_code.co_name != 'exec_module': f = f.f_back
                    module = f.f_locals['module']
                    assert module.__name__ == name
                except Exception as e:
                    pass
                else:
                    module.submodule_search_locations = []
                    module.__path__ = ''
                if _data := self.archive.get('__main__' if name == '__main__' else name + '.__init__'):
                    exec(_data[0], globals_)
            def find_spec(self, fullname, path, target=None):
                if fullname in self.archive:
                    code, is_pkg = self.archive[fullname]
                    return importlib.util.spec_from_loader(fullname, _NyPkgArchiveLoader(code), is_package=is_pkg)
                return None
        setattr(_NyPkgArchiveFinder, {finder_identifier!r}, True)
        sys.meta_path.append(finder := _NyPkgArchiveFinder())
    if _PKG:
        # Register everything under "<_PKG>." and synthesize <_PKG> so
        # `__package__=_PKG` actually resolves to a real package object.
        finder.reg(_PKG, archive_code)
        if _PKG not in sys.modules:
            import types as _t
            _m = _t.ModuleType(_PKG)
            _m.__path__ = []
            _m.__package__ = _PKG
            sys.modules[_PKG] = _m
        globals().pop('__pkg_loader__', None)
        globals()['__package__'] = _PKG
        if _data := finder.archive.get(_PKG + '.__main__'):
            exec(_data[0], globals())
    else:
        finder.reg(__name__, archive_code)
        globals().pop('__pkg_loader__', None)
        finder.exec_pkg(__name__, globals())
'''.strip()

template = f'''
def __pkg_loader__(archive_code):
    import sys
    for finder in sys.meta_path:
        if hasattr(finder, {finder_identifier!r}):
            finder.reg(__name__, archive_code)
            globals().pop('__pkg_loader__', None)
            finder.exec_pkg(__name__, globals())
            return
    raise Exception('finder not found')
'''.strip()


def pack(p: str | pathlib.Path, o=None, is_main: bool = True,
         package_name: str | None = None):
    """Pack a script or package directory into a self-extracting payload.

    Parameters
    ----------
    p : path
        File or directory to pack.
    o : callable, optional
        Optional source-bytes transform (e.g. obfuscator).
    is_main : bool
        True for the top-level pack call (emits ``template_main`` and uses
        absolute archive keys). False for recursive sub-package packs
        (emits ``template`` and is keyed by the calling module's name).
    package_name : str | None
        Only meaningful when ``is_main=True``.
        - ``None`` (default): packed code runs at module-top-level. The
          entry script becomes ``__main__`` with no parent package, so
          relative imports inside it will fail. Use this when the packed
          script uses absolute imports against sibling names.
        - A string (e.g. ``"packed"``): packed code is wrapped in a
          synthetic top-level package of that name. The entry script
          runs with ``__package__=<package_name>``, so relative imports
          (``from .core import x``) resolve. Sub-modules are accessible
          as ``<package_name>.<sub>``.
    """
    o = o or (lambda x: x)
    p = p if isinstance(p, pathlib.Path) else pathlib.Path(p)
    assert p.exists(), 'path not exists'
    if p.is_file():
        return o(p.read_bytes())
    data = {}
    for _p in p.iterdir():
        if _p.is_file():
            if _p.suffix == '.py' or _p.suffix == '.pyw':
                data[_p.stem] = o(_p.read_bytes()), False
        elif _p.name != '__pycache__' and (_p / '__init__.py').exists():
            data[_p.stem] = pack(_p, o, False), True
    decoded = base64.b85encode(zlib.compress(pickle.dumps(data))).decode('utf-8')
    if is_main:
        head = template_main.format(package_name=package_name)
    else:
        head = template
    return head + f'\n__pkg_loader__({decoded!r})\n'
