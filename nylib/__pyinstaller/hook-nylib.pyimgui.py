"""PyInstaller hook for ``nylib.pyimgui``.

``nylib.pyimgui`` is shipped as a single extension module
(``pyimgui.cp3XX-win_amd64.pyd``) that, at import time, sets its own
``__path__`` to a sibling directory ``pyimgui/`` containing the per-backend
frontend extensions (``dx9.pyd``, ``dx10.pyd``, ``dx11.pyd``, ``dx12.pyd``,
optionally ``gl3.pyd`` / ``vk.pyd``). PyInstaller's static analyser cannot
follow that runtime ``__path__`` rewrite, so without this hook:

* the frontend ``.pyd`` files are never bundled, and
* ``import pyimgui.dx9`` (etc.) raises ``ModuleNotFoundError`` in the
  frozen application.

This hook locates the sibling ``pyimgui/`` directory next to the loaded
``nylib.pyimgui`` extension and:

1. registers each ``*.pyd`` built for this interpreter's ABI as a binary,
   placed next to the core ``.pyd`` inside the bundle so the runtime
   ``__path__`` logic still resolves them (other ABIs are skipped and logged);
2. adds the top-level ``*.py`` modules (``esp.py``) as data; and
3. lists the frontends as hidden imports (PyInstaller logs them as not
   found, which is harmless: the binaries carry the files).

The hook is intentionally tolerant: if a particular backend wasn't built
(``dx12.pyd`` missing on a dx9-only build), it simply isn't bundled. The
short-name aliases (``pyimgui.dx9`` in addition to ``nylib.pyimgui.dx9``)
are added because ``DllMain.cpp`` performs ``py::module_::import("<pkg>.dx9")``
using the package's own ``__name__`` at runtime — which is
``nylib.pyimgui`` here — but user code commonly does
``importlib.import_module('pyimgui.dx9')`` as well.
"""

from __future__ import annotations

import importlib.machinery
import os
import pathlib

from PyInstaller.utils.hooks import (  # type: ignore[import-not-found]
    get_module_file_attribute,
    logger,
)

binaries: list[tuple[str, str]] = []
datas: list[tuple[str, str]] = []
hiddenimports: list[str] = []

_EXT_SUFFIXES = tuple(importlib.machinery.EXTENSION_SUFFIXES)


def _is_native_ext(name: str) -> bool:
    """True when the file's ABI tag is accepted by the interpreter being frozen."""
    return '.' + name.lower().partition('.')[2] in _EXT_SUFFIXES


def _collect() -> None:
    try:
        pyimgui_pyd = pathlib.Path(get_module_file_attribute('nylib.pyimgui'))
    except Exception as exc:  # noqa: BLE001
        logger.warning('hook-nylib.pyimgui: cannot locate nylib.pyimgui (%s)', exc)
        return

    package_dir = pyimgui_pyd.with_name('pyimgui')
    if not package_dir.is_dir():
        logger.warning(
            'hook-nylib.pyimgui: expected sibling package dir %s but it does not exist',
            package_dir,
        )
        return

    dest = os.path.join('nylib', 'pyimgui')

    entries = sorted(package_dir.iterdir())
    collected_stems = set()
    for entry in entries:
        if entry.is_file() and entry.suffix.lower() == '.pyd':
            if not _is_native_ext(entry.name):
                logger.info('hook-nylib.pyimgui: skipping %s, built for another Python ABI', entry.name)
                continue
            binaries.append((str(entry), dest))
            stem = entry.name.split('.', 1)[0]
            collected_stems.add(stem.lower())
            hiddenimports.append(f'nylib.pyimgui.{stem}')
            hiddenimports.append(f'pyimgui.{stem}')
        elif entry.is_file() and entry.suffix.lower() == '.py':
            datas.append((str(entry), dest))
        elif entry.is_file() and entry.suffix.lower() in {'.pyi'}:
            datas.append((str(entry), dest))

    for entry in entries:
        if entry.is_dir():
            if entry.name.lower() != 'imgui' and entry.name.lower() not in collected_stems:
                logger.debug('hook-nylib.pyimgui: skipping stub folder %s, its frontend was not collected', entry.name)
                continue
            for sub in entry.rglob('*'):
                if sub.is_file() and sub.suffix.lower() in {'.pyi'}:
                    rel_parent = sub.parent.relative_to(package_dir)
                    datas.append((str(sub), os.path.join(dest, str(rel_parent))))


_collect()
