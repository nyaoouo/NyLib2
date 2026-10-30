"""PyInstaller hook for ``nylib.winutils.breakpoint``.

Each backend subdirectory ships a C++ source file and (after a successful
local build) a compiled DLL. PyInstaller normally drops .dll files because
``pyproject.toml`` excludes binaries from the wheel - this hook reverses that
for the frozen bundle, mirroring ``hook-nylib.winutils.python_loader.py``.

For each ``nylib/winutils/breakpoint/<backend>/<backend>_backend.cpp``:
  1. If ``<backend>_backend.dll`` is missing, build it at freeze time only when MSVC
     is already installed; otherwise warn and go on without it.
  2. Add both the source and the DLL as data so package-relative lookups
     keep working in the bundle.
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
hiddenimports: list[str] = [
    "nylib.winutils.breakpoint.veh",
    "nylib.winutils.breakpoint.debugger",
]


def _msvc_installed() -> bool:
    try:
        from nylib.winutils.msvc import msvc14_find_vc2017
        return msvc14_find_vc2017()[1] is not None
    except Exception as exc:  # noqa: BLE001
        logger.debug("hook-nylib.winutils.breakpoint: MSVC detection failed (%s); treating it as absent", exc)
        return False


def _collect() -> None:
    try:
        init_py = pathlib.Path(get_module_file_attribute("nylib.winutils.breakpoint"))
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "hook-nylib.winutils.breakpoint: cannot locate package (%s)", exc
        )
        return

    pkg_dir = init_py.parent
    for sub in pkg_dir.iterdir():
        if not sub.is_dir():
            continue
        for cpp in sub.glob("*_backend.cpp"):
            rel_dest = os.path.join("nylib", "winutils", "breakpoint", sub.name)
            datas.append((str(cpp), rel_dest))
            dll = cpp.with_suffix(".dll")
            if not dll.is_file() and sub.name in ("veh", "debugger"):
                if not _msvc_installed():
                    logger.warning(
                        "hook-nylib.winutils.breakpoint: %s is missing and MSVC is not installed; "
                        "not building it (prebuild it with nylib.winutils.breakpoint.%s.build_backend()); "
                        "a frozen app that uses this backend fails",
                        dll, sub.name,
                    )
                else:
                    try:
                        if sub.name == "veh":
                            from nylib.winutils.breakpoint.veh import build_backend as _bv
                            logger.info(
                                "hook-nylib.winutils.breakpoint: building %s", dll
                            )
                            _bv(dll)
                        else:
                            from nylib.winutils.breakpoint.debugger import build_backend as _bd
                            logger.info(
                                "hook-nylib.winutils.breakpoint: building %s", dll
                            )
                            _bd(dll)
                    except Exception as exc:  # noqa: BLE001
                        logger.warning(
                            "hook-nylib.winutils.breakpoint: failed to build %s (%s); "
                            "frozen app will fail at runtime if this backend is used",
                            dll, exc,
                        )
            if dll.is_file():
                binaries.append((str(dll), rel_dest))


_collect()
