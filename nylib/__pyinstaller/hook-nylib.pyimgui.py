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

1. registers every ``*.pyd`` it contains as a binary, placed next to the
   core ``.pyd`` inside the bundle so the runtime ``__path__`` logic still
   resolves them; and
2. exposes them as hidden imports so PyInstaller's collect phase keeps
   them around.

The hook is intentionally tolerant: if a particular backend wasn't built
(``dx12.pyd`` missing on a dx9-only build), it simply isn't bundled. The
short-name aliases (``pyimgui.dx9`` in addition to ``nylib.pyimgui.dx9``)
are added because ``DllMain.cpp`` performs ``py::module_::import("<pkg>.dx9")``
using the package's own ``__name__`` at runtime — which is
``nylib.pyimgui`` here — but user code commonly does
``importlib.import_module('pyimgui.dx9')`` as well.
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

    # Destination inside the frozen bundle. ``pyimgui.pyd`` is bundled under
    # ``nylib/`` so its sibling ``pyimgui/`` directory must end up at the
    # same place.
    dest = os.path.join('nylib', 'pyimgui')

    for entry in sorted(package_dir.iterdir()):
        if entry.is_file() and entry.suffix.lower() == '.pyd':
            binaries.append((str(entry), dest))
            # ``dx9.cp313-win_amd64.pyd`` -> ``dx9``
            stem = entry.name.split('.', 1)[0]
            hiddenimports.append(f'nylib.pyimgui.{stem}')
            hiddenimports.append(f'pyimgui.{stem}')
        elif entry.is_file() and entry.suffix.lower() in {'.pyi'}:
            # Stubs are only useful at type-check time, but PyInstaller users
            # occasionally ship them for IDE-friendly bundles; keep them as
            # datas so they round-trip without bloating binaries.
            datas.append((str(entry), dest))
        elif entry.is_dir():
            # Per-frontend stub subpackages (``pyimgui/dx9/__init__.pyi`` etc.).
            for sub in entry.rglob('*'):
                if sub.is_file() and sub.suffix.lower() in {'.pyi'}:
                    rel_parent = sub.parent.relative_to(package_dir)
                    datas.append((str(sub), os.path.join(dest, str(rel_parent))))


_collect()
