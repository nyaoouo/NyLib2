from __future__ import annotations

import argparse
import os
import pathlib
import subprocess
import sys
import time


ROOT = pathlib.Path(__file__).resolve().parent
REPO_ROOT = ROOT.parents[1]
PYIMGUI2_ROOT = REPO_ROOT / "scripts" / "pyimgui2"
OUT_ROOT = ROOT / "out"
BACKENDS = ("dx9", "dx11", "dx12")


def ensure_paths() -> None:
    for path in (str(REPO_ROOT), str(PYIMGUI2_ROOT)):
        if path not in sys.path:
            sys.path.insert(0, path)


def ensure_project_venv() -> None:
    expected = REPO_ROOT / ".venv"
    try:
        in_expected_venv = pathlib.Path(sys.prefix).resolve() == expected.resolve()
    except OSError:
        in_expected_venv = False
    if not in_expected_venv:
        raise RuntimeError(f"Run dxtest injection with {expected}\\Scripts\\python.exe to keep python_hijack dependencies project-local")


def restore_bootstrap(out_dir: pathlib.Path) -> None:
    proxy = out_dir / "dxtest_bootstrap.dll"
    original = out_dir / "dxtest_bootstrap.pyHijack.dll"
    if original.exists():
        proxy.unlink(missing_ok=True)
        original.rename(proxy)


def build_if_needed(backend: str) -> pathlib.Path:
    out_dir = OUT_ROOT / backend
    exe = out_dir / f"dxtest_{backend}.exe"
    dll = out_dir / "dxtest_bootstrap.dll"
    if not exe.exists() or not dll.exists():
        subprocess.run([sys.executable, str(ROOT / "build.py"), backend], check=True)
    return out_dir


def install_hijack(backend: str, out_dir: pathlib.Path, create_console: bool = False) -> None:
    ensure_paths()
    from nylib.winutils import python_hijack

    restore_bootstrap(out_dir)
    payload = ROOT / backend / "payload.py"
    python_hijack.hijack(
        out_dir / "dxtest_bootstrap.dll",
        build_dir=out_dir / "hijack_build",
        default_config={
            "python_main": str(payload),
            "create_console": "1" if create_console else "",
        },
        dst_dir=out_dir,
        plat_spec="x86_amd64",
    )


def run_host(backend: str, out_dir: pathlib.Path, seconds: int) -> int:
    markers = out_dir / "markers"
    if markers.exists():
        for item in markers.iterdir():
            item.unlink()
    markers.mkdir(parents=True, exist_ok=True)

    env = os.environ.copy()
    env["DXTEST_OUT"] = str(out_dir)
    env["DXTEST_SECONDS"] = str(seconds)
    env["PYTHONUTF8"] = "1"
    exe = out_dir / f"dxtest_{backend}.exe"
    process = subprocess.Popen([str(exe)], cwd=out_dir, env=env)
    return process.wait(timeout=seconds + 10)


def print_markers(out_dir: pathlib.Path) -> bool:
    markers = out_dir / "markers"
    names = sorted(item.name for item in markers.glob("*.txt"))
    print("markers:", ", ".join(names) if names else "<none>")
    return (markers / "payload_drawn.txt").exists()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("backend", choices=BACKENDS)
    parser.add_argument("--seconds", type=int, default=10)
    parser.add_argument("--console", action="store_true")
    parser.add_argument("--no-launch", action="store_true")
    args = parser.parse_args()

    ensure_project_venv()
    out_dir = build_if_needed(args.backend)
    install_hijack(args.backend, out_dir, create_console=args.console)
    if args.no_launch:
        return
    started = time.time()
    exit_code = run_host(args.backend, out_dir, args.seconds)
    drew = print_markers(out_dir)
    elapsed = time.time() - started
    print(f"{args.backend} host exited with {exit_code} after {elapsed:.1f}s; drawn={drew}")
    raise SystemExit(0 if exit_code == 0 and drew else 1)


if __name__ == "__main__":
    main()