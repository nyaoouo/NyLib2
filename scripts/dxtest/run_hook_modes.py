from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent
REPO_ROOT = ROOT.parents[1]
PYIMGUI2_ROOT = REPO_ROOT / "scripts" / "pyimgui2"
CASES = (
    ("vtable", "Vtable", False, {}),
    ("detours", "Detours", True, {}),
    ("auto", "Detours", True, {}),
    ("auto", "Vtable", False, {"DXTEST_FOREIGN": "detours", "DXTEST_FOREIGN_AT": "2", "DXTEST_ATTACH_AT": "3"}),
    ("auto", "Detours", True, {"DXTEST_FOREIGN": "vtable", "DXTEST_FOREIGN_AT": "2", "DXTEST_ATTACH_AT": "3"}),
    ("vtable", "Vtable", False, {"DXTEST_FOREIGN": "vtable", "DXTEST_FOREIGN_AT": "2", "DXTEST_DETACH_AT": "4"}),
    ("vtable", "Vtable", False, {"DXTEST_RESIZE_AT": "2"}),
)


def run_case(backend: str, mode: str, expected: str, body_changed: bool, extra: dict[str, str]) -> None:
    env = os.environ.copy()
    for key in tuple(env):
        if key.startswith("DXTEST_"):
            del env[key]
    env.update(extra)
    env["DXTEST_HOOK_MODE"] = mode
    env["PYTHONPATH"] = os.pathsep.join((str(REPO_ROOT), str(PYIMGUI2_ROOT)))
    label = f"{backend} {mode} {extra}"
    result = subprocess.run([sys.executable, str(ROOT / "inject.py"), backend, "--seconds", "6"],
                            cwd=REPO_ROOT, env=env, check=False, capture_output=True, text=True, errors="replace")
    if result.returncode:
        raise AssertionError(f"{label}: injected host failed: {result.returncode}\n{result.stdout}\n{result.stderr}")
    markers = ROOT / "out" / backend / "markers"
    details = dict(part.split("=", 1) for part in (markers / "hook_mode.txt").read_text().split())
    if details["selected"] != expected:
        raise AssertionError(f"{label}: selected {details['selected']}, expected {expected}")
    if (details["before"] != details["after"]) != body_changed:
        raise AssertionError(f"{label}: Present body changed={details['before'] != details['after']}, expected {body_changed}")
    if backend == "dx12" and (details["queue_before"] != details["queue_after"]) != body_changed:
        raise AssertionError(f"{label}: queue body changed unexpectedly")
    if extra.get("DXTEST_RESIZE_AT") and not (markers / "drawn_after_resize.txt").exists():
        raise AssertionError(f"{label}: drawing did not resume after resize")
    loaded = Path((markers / "nylib_pyimgui_file.txt").read_text().strip()).resolve()
    if not loaded.is_relative_to(REPO_ROOT):
        raise AssertionError(f"{label}: loaded build outside worktree: {loaded}")
    print(f"PASS {label}: {expected}", flush=True)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("backends", nargs="*", choices=("dx11", "dx12"), default=("dx11", "dx12"))
    args = parser.parse_args()
    for backend in args.backends:
        for mode, expected, body_changed, extra in CASES:
            run_case(backend, mode, expected, body_changed, extra)


if __name__ == "__main__":
    main()
