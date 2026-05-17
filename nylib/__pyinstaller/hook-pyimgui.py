"""PyInstaller hook for a top-level ``pyimgui`` import.

Some applications import the ``pyimgui`` extension directly (i.e.
``import pyimgui.dx11`` rather than ``import nylib.pyimgui.dx11``). When the
``pyimgui.pyd`` core module is laid out at the bundle root with a sibling
``pyimgui/`` directory of frontend ``.pyd`` files, PyInstaller cannot infer
the layout statically because ``pyimgui`` rewrites its own ``__path__`` at
import time.

This hook delegates to the same collection logic as ``hook-nylib.pyimgui``
but targets the top-level ``pyimgui`` module and places the frontend
extensions at the bundle root's ``pyimgui/`` directory.
"""

from __future__ import annotations

import os
import pathlib

from PyInstaller.utils.hooks import (  # type: ignore[import-not-found]
    get_module_file_attribute,
    logger,
)

binaries: list[tuple[str, str]] = []
datas: list[tuple[str, str]] = []
hiddenimports: list[str] = []


def _collect() -> None:
    try:
        pyimgui_pyd = pathlib.Path(get_module_file_attribute('pyimgui'))
    except Exception as exc:  # noqa: BLE001
        logger.info('hook-pyimgui: pyimgui not importable as top-level (%s)', exc)
        return

    package_dir = pyimgui_pyd.with_name('pyimgui')
    if not package_dir.is_dir():
        logger.warning(
            'hook-pyimgui: expected sibling package dir %s but it does not exist',
            package_dir,
        )
        return

    dest = 'pyimgui'

    for entry in sorted(package_dir.iterdir()):
        if entry.is_file() and entry.suffix.lower() == '.pyd':
            binaries.append((str(entry), dest))
            stem = entry.name.split('.', 1)[0]
            hiddenimports.append(f'pyimgui.{stem}')
        elif entry.is_file() and entry.suffix.lower() == '.pyi':
            datas.append((str(entry), dest))
        elif entry.is_dir():
            for sub in entry.rglob('*'):
                if sub.is_file() and sub.suffix.lower() == '.pyi':
                    rel_parent = sub.parent.relative_to(package_dir)
                    datas.append((str(sub), os.path.join(dest, str(rel_parent))))


_collect()
