"""PyInstaller hook discovery for ``nylib``.

``nylib`` ships pre-built C extensions (notably ``nylib.pyimgui`` and its
frontend ``.pyd`` submodules) whose layout PyInstaller cannot infer from
static analysis alone — the ``pyimgui`` core extension installs its
``__path__`` programmatically at import time so the ``pyimgui/dx9.pyd``,
``pyimgui/dx11.pyd`` ... siblings become importable as
``pyimgui.dx9``, ``pyimgui.dx11`` ... etc.

This package exposes the hooks dir to PyInstaller via the standard
``pyinstaller40`` entry point. If ``nylib`` is installed (``pip install``
or in editable mode with ``pyproject.toml``), declare the entry point in
your build config::

    [project.entry-points."pyinstaller40"]
    hook-dirs = "nylib.__pyinstaller:get_hook_dirs"

If ``nylib`` is used in-tree (no installation step), tell PyInstaller about
the hooks dir on the command line::

    pyinstaller --additional-hooks-dir <path/to>/nylib/__pyinstaller your_app.py
"""

from __future__ import annotations

import os


def get_hook_dirs() -> list[str]:
    """Return the directory containing the PyInstaller hooks for nylib."""
    return [os.path.dirname(__file__)]


def get_PyInstaller_tests() -> list[str]:  # pragma: no cover - optional
    return []
