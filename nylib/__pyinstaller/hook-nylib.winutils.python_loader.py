"""Bundle the DLL for ``nylib.winutils.python_loader``.

Build the missing loader DLL at freeze time only when MSVC is installed;
otherwise warn and continue without it.
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


def _msvc_installed() -> bool:
    try:
        from nylib.winutils.msvc import msvc14_find_vc2017
        return msvc14_find_vc2017()[1] is not None
    except Exception as exc:  # noqa: BLE001
        logger.debug('hook-nylib.winutils.python_loader: MSVC detection failed (%s); treating it as absent', exc)
        return False


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

    dll = pkg_dir / 'python_loader.dll'
    if not dll.is_file() and not _msvc_installed():
        logger.warning(
            'hook-nylib.winutils.python_loader: %s is missing and MSVC is not installed; '
            'not building it (prebuild it with nylib.winutils.python_loader.build_loader()); '
            'a frozen app that injects Python fails',
            dll,
        )
    elif not dll.is_file():
        try:
            from nylib.winutils.python_loader import build_loader

            logger.info(
                'hook-nylib.winutils.python_loader: building %s at freeze time', dll
            )
            build_loader(dll)
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                'hook-nylib.winutils.python_loader: failed to build %s (%s); '
                'a frozen app that injects Python fails',
                dll,
                exc,
            )
    if dll.is_file():
        binaries.append((str(dll), dest))


_collect()
