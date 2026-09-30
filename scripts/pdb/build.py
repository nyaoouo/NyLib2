"""Build _ny_pdb.cpXY-win_amd64.pyd via pybind11 + MSVC.

Mirrors ``scripts/pyimgui2/pyimgui_generate.py::pybind11_build`` but keeps
the target small: one extension, no code generation.

Run:
    <venv python> scripts/pdb/build.py
"""
import os
import pathlib
import shutil
import sys

# Repo root importable so we can reuse nylib.winutils bootstrap.
REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from nylib.utils.pip import required
from nylib.winutils import ensure_env, msvc


HERE = pathlib.Path(__file__).resolve().parent
SRC_DIR = HERE / 'src'
PY_DIR = REPO_ROOT / 'nylib' / 'pdb'
BUILD_TMP = HERE / 'build_tmp'


def _dia_sdk_root():
    """Locate ``DIA SDK`` under the resolved VS install."""
    _, vc_build_dir = msvc.msvc14_find_vc2017()
    if not vc_build_dir:
        raise RuntimeError('MSVC / VS install not found')
    # vc_build_dir = <VS>/VC/Auxiliary/Build -> parents[2] = <VS>
    vs_root = pathlib.Path(vc_build_dir).parents[2]
    root = vs_root / 'DIA SDK'
    if not (root / 'include' / 'dia2.h').is_file():
        raise RuntimeError(f'DIA SDK not found at {root}')
    return root


def _copy_msdia(dst_dir: pathlib.Path, sdk_root: pathlib.Path):
    """Bundle msdia140.dll (amd64) next to the compiled .pyd. Raises if absent - the DLL is load-bearing."""
    src = sdk_root / 'bin' / 'amd64' / 'msdia140.dll'
    if not src.is_file():
        raise RuntimeError(f'msdia140.dll not found at {src} - cannot bundle a required DLL')
    dst = dst_dir / 'msdia140.dll'
    shutil.copy2(src, dst)
    print(f'[build] bundled {src} -> {dst}')
    return dst


def build(debug=False):
    ensure_env.ensure_msvc()
    required('pybind11')
    required('setuptools')

    if sys.version_info < (3, 12):
        os.environ['SETUPTOOLS_USE_DISTUTILS'] = 'stdlib'

    # Loads vcvarsall and shoves its env into the current process. Later
    # setuptools invocations of cl/link inherit INCLUDE / LIB / PATH.
    for k, v in msvc.load_vcvarsall('x86_amd64').items():
        os.environ[k] = v

    from setuptools import Distribution
    from pybind11.setup_helpers import Pybind11Extension, build_ext

    sdk_root = _dia_sdk_root()
    dia_include = sdk_root / 'include'
    dia_lib = sdk_root / 'lib' / 'amd64'

    ext = Pybind11Extension(
        name='_ny_pdb',
        sources=[
            str(SRC_DIR / '_ny_pdb.cpp'),
            str(SRC_DIR / 'dia_wrap.cpp'),
        ],
        include_dirs=[str(dia_include)],
        library_dirs=[str(dia_lib)],
        libraries=['diaguids', 'ole32', 'oleaut32'],
        cxx_std=20,
    )
    extra = list(getattr(ext, 'extra_compile_args', []) or [])
    for flag in ('/bigobj', '/Zm500', '/std:c++20', '/utf-8', '/EHsc', '/DNOMINMAX'):
        if flag not in extra:
            extra.append(flag)
    ext.extra_compile_args = extra

    # setuptools' inplace step writes _ny_pdb.cpXY-win_amd64.pyd into cwd;
    # collect it into nylib/pdb/ below (loaded lazily via importlib).
    BUILD_TMP.mkdir(exist_ok=True)
    old_cwd = os.getcwd()
    os.chdir(BUILD_TMP)
    try:
        dist = Distribution({
            'cmdclass': {'build_ext': build_ext},
            'ext_modules': [ext],
        })
        cmd = dist.get_command_obj('build_ext')
        cmd.inplace = 1
        cmd.ensure_finalized()
        cmd.debug = 1 if debug else 0
        cmd.run()
    finally:
        os.chdir(old_cwd)

    # Collect the inplace-built pyd from BUILD_TMP into nylib/pdb/.
    produced = list(BUILD_TMP.glob('_ny_pdb*.pyd'))
    if not produced:
        raise RuntimeError('build produced no .pyd - check output above')
    PY_DIR.mkdir(parents=True, exist_ok=True)
    for old in PY_DIR.glob('_ny_pdb*.pyd'):
        old.unlink()
    for src_pyd in produced:
        dst = PY_DIR / src_pyd.name
        shutil.copy2(src_pyd, dst)
        print(f'[build] {src_pyd} -> {dst}')

    _copy_msdia(PY_DIR, sdk_root)

    print('[build] done')


def _from_pe_stub_text() -> str:
    """Build the from_pe stub block, reusing its own docstring (not a
    paraphrase of it) so the two can't drift apart."""
    import nylib.pdb as _pdb_pkg
    doc = (_pdb_pkg._session_from_pe.__doc__ or '').strip()
    return (
        '\n    @classmethod\n'
        '    def from_pe(cls, pe_path: str | os.PathLike[str], *, '
        'symsrv_url: str | typing.Sequence[str] = ..., '
        'cache_dir: str | os.PathLike[str] | None = None, '
        'load_address: int | None = None, search_local: bool = True) -> Session:\n'
        f'        """{doc}"""\n'
    )


def _inject_from_pe_stub(stub_path: pathlib.Path):
    """pybind11-stubgen can't see Session.from_pe - it's attached to the
    extension class in Python at import time (__init__.py), not defined in
    the C++ module. Splice its signature into the generated stub by hand."""
    data = stub_path.read_text(encoding='utf-8')
    if 'def from_pe' in data:
        return
    if 'import os\n' not in data:
        data = 'import os\n' + data
    marker = 'class Session:\n'
    idx = data.find(marker)
    if idx == -1:
        raise RuntimeError(f'{stub_path}: no "class Session:" block to patch')
    insert_at = idx + len(marker)
    stub_path.write_text(data[:insert_at] + _from_pe_stub_text() + data[insert_at:], encoding='utf-8')


def stub_gen():
    """Regenerate nylib/pdb/_ny_pdb.pyi via pybind11-stubgen, then patch in
    from_pe (see _inject_from_pe_stub). Mirrors
    scripts/pyimgui2/pyimgui_generate.py::stub_gen."""
    required('pybind11-stubgen')
    import pybind11_stubgen

    stub_path = PY_DIR / '_ny_pdb.pyi'
    stub_path.unlink(missing_ok=True)

    module_name = 'nylib.pdb._ny_pdb'
    args = pybind11_stubgen.arg_parser().parse_args(['-o', str(REPO_ROOT), module_name], namespace=pybind11_stubgen.CLIArgs())
    out_dir, sub_dir = pybind11_stubgen.to_output_and_subdir(
        output_dir=args.output_dir,
        module_name=args.module_name,
        root_suffix=args.root_suffix,
    )
    pybind11_stubgen.run(
        pybind11_stubgen.stub_parser_from_args(args),
        pybind11_stubgen.Printer(invalid_expr_as_ellipses=not args.print_invalid_expressions_as_is),
        args.module_name,
        out_dir,
        sub_dir=sub_dir,
        dry_run=args.dry_run,
        writer=pybind11_stubgen.Writer(stub_ext=args.stub_extension),
    )
    _inject_from_pe_stub(stub_path)


def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument('--debug', action='store_true')
    ap.add_argument('--stubs', dest='stubs', action='store_true', default=True, help='generate nylib/pdb/_ny_pdb.pyi (default: on)')
    ap.add_argument('--no-stubs', dest='stubs', action='store_false')
    args = ap.parse_args()
    build(debug=args.debug)
    if args.stubs:
        try:
            stub_gen()
        except Exception as e:
            print(f'[build] WARNING: stub generation failed, skipping: {e}')


if __name__ == '__main__':
    main()
