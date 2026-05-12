from __future__ import annotations

import os
import pathlib
import sys
import time


def marker_dir() -> pathlib.Path:
    out = pathlib.Path(os.environ.get("DXTEST_OUT", pathlib.Path.cwd()))
    path = out / "markers"
    path.mkdir(parents=True, exist_ok=True)
    return path


def mark(name: str, text: str = "ok") -> None:
    (marker_dir() / f"{name}.txt").write_text(text, encoding="utf-8")


def keep_alive(seconds: float | None = None) -> None:
    if seconds is None:
        seconds = float(os.environ.get("DXTEST_SECONDS", "10")) + 2.0
    end = time.time() + seconds
    while time.time() < end:
        time.sleep(0.1)


def configure_imports() -> None:
    scripts_dir = pathlib.Path(__file__).resolve().parents[2]
    repo_root = scripts_dir.parent
    pyimgui2 = scripts_dir / "pyimgui2"
    for path in (str(repo_root), str(pyimgui2)):
        if path not in sys.path:
            sys.path.insert(0, path)