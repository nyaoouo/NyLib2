"""PyInstaller hook for ``nylib.winutils.python_loader``.

The loader package ships a C++ source file (``python_loader.cpp``) and a
compiled DLL (``python_loader.dll``). The runtime code in
``nylib.winutils.python_loader.run_script`` looks for the DLL next to
``__init__.py`` and loads it into the target process. PyInstaller would
normally drop the ``.dll`` because compiled binaries are excluded from
the wheel by ``pyproject.toml`` - this hook reverses that for the frozen
bundle.

Behaviour
---------
1. Locate ``nylib.winutils.python_loader``'s on-disk directory.
2. If ``python_loader.dll`` is missing, build it via
   :func:`nylib.winutils.python_loader.build_loader`. That requires MSVC
   on the build machine; the build is performed at *freeze* time only.
   If the build fails the hook logs the error and continues without the
   DLL - the frozen app can still call ``build_loader`` at runtime if a
   compiler happens to be available.
3. Add the DLL and the ``.cpp`` source as data files under
   ``nylib/winutils/python_loader/`` inside the bundle so the package's
   ``__file__``-relative lookups keep working.
"""

from __future__ import annotations

import os
import pathlib

from PyInstaller.utils.hooks import (  # type: ignore[import-not-found]
    get_module_file_attribute,
    logger,
)

datas: list[tuple[str, str]] = []
binaries: list[tuple[str, str]] = []
hiddenimports: list[str] = []


def _collect() -> None:
    try:
        init_py = pathlib.Path(get_module_file_attribute('nylib.winutils.python_loader'))
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            'hook-nylib.winutils.python_loader: cannot locate package (%s)', exc
        )
        return

    pkg_dir = init_py.parent
    dest = os.path.join('nylib', 'winutils', 'python_loader')

    cpp = pkg_dir / 'python_loader.cpp'
    if cpp.is_file():
        datas.append((str(cpp), dest))

    dll = pkg_dir / 'python_loader.dll'
    if not dll.is_file():
        try:
            from nylib.winutils.python_loader import build_loader

            logger.info(
                'hook-nylib.winutils.python_loader: building %s at freeze time', dll
            )
            build_loader(dll)
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                'hook-nylib.winutils.python_loader: failed to build %s (%s); '
                'frozen app will need to build it on first use',
                dll,
                exc,
            )
    if dll.is_file():
        # Use the binaries channel: PyInstaller will treat the DLL the same
        # way it treats any other native dependency.
        binaries.append((str(dll), dest))


_collect()
