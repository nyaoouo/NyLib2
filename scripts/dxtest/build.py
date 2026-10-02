from __future__ import annotations

import argparse
import pathlib
import shutil
import subprocess
import sys


ROOT = pathlib.Path(__file__).resolve().parent
REPO_ROOT = ROOT.parents[1]
OUT_ROOT = ROOT / "out"
BACKENDS = ("dx9", "dx11", "dx12")

# Vendored Detours (scripts/pyimgui2/auto_src/detours), reused so
# foreign_hook.cpp's "detours" mode is a genuinely separate Detours engine,
# like a third-party hooker statically linking its own copy (VF§7.2 S0).
PYIMGUI2_AUTO_SRC = REPO_ROOT / "scripts" / "pyimgui2" / "auto_src"
DETOURS_SRC_DIR = PYIMGUI2_AUTO_SRC / "detours" / "src"


def _import_msvc_helpers():
    sys.path.insert(0, str(REPO_ROOT))
    from nylib.winutils import ensure_env, msvc

    ensure_env.ensure_msvc()
    return msvc


def _run(args: list[str], env: dict[str, str], cwd: pathlib.Path | None = None) -> None:
    print(" ".join(args))
    subprocess.run(args, cwd=cwd or ROOT, env=env, check=True)


def _tool(env: dict[str, str], name: str) -> str:
    path_value = env.get("PATH") or env.get("Path")
    path = shutil.which(name, path=path_value)
    if path is None:
        raise FileNotFoundError(name)
    return path


def _cl(env: dict[str, str], args: list[str]) -> None:
    _run([_tool(env, "cl.exe"), "/nologo", "/EHsc", "/std:c++20", "/utf-8", *args], env=env)


def clean_backend(backend: str) -> pathlib.Path:
    out_dir = OUT_ROOT / backend
    shutil.rmtree(out_dir, ignore_errors=True)
    out_dir.mkdir(parents=True, exist_ok=True)
    return out_dir


def build_bootstrap(env: dict[str, str], out_dir: pathlib.Path) -> None:
    _cl(env, [
        "/LD",
        str(ROOT / "common" / "bootstrap.cpp"),
        "/Fo:" + str(out_dir / "bootstrap.obj"),
        "/Fe:" + str(out_dir / "dxtest_bootstrap.dll"),
        "/link",
        "/IMPLIB:" + str(out_dir / "dxtest_bootstrap.lib"),
    ])


def build_host(env: dict[str, str], backend: str, out_dir: pathlib.Path) -> None:
    libs = {
        "dx9": ["d3d9.lib"],
        "dx11": ["d3d11.lib", "dxgi.lib"],
        "dx12": ["d3d12.lib", "dxgi.lib", "dxguid.lib"],
    }[backend]
    detours_sources = sorted(
        str(p) for p in DETOURS_SRC_DIR.glob("*.cpp") if p.name != "uimports.cpp"
    )
    _cl(env, [
        "/D_AMD64_=1",
        "/I" + str(ROOT / "common"),
        "/I" + str(PYIMGUI2_AUTO_SRC),
        str(ROOT / "common" / "win32_app.cpp"),
        str(ROOT / "common" / "foreign_hook.cpp"),
        *detours_sources,
        str(ROOT / backend / "main.cpp"),
        "/Fo:" + str(out_dir) + "\\",
        "/Fe:" + str(out_dir / f"dxtest_{backend}.exe"),
        "/link",
        str(out_dir / "dxtest_bootstrap.lib"),
        "user32.lib",
        "gdi32.lib",
        *libs,
    ])


def build_backend(env: dict[str, str], backend: str) -> None:
    if backend not in BACKENDS:
        raise ValueError(f"unknown backend: {backend}")
    out_dir = clean_backend(backend)
    build_bootstrap(env, out_dir)
    build_host(env, backend, out_dir)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("backend", choices=("all", *BACKENDS))
    args = parser.parse_args()

    msvc = _import_msvc_helpers()
    env = msvc.load_vcvarsall("x86_amd64")
    targets = BACKENDS if args.backend == "all" else (args.backend,)
    for backend in targets:
        build_backend(env, backend)


if __name__ == "__main__":
    main()