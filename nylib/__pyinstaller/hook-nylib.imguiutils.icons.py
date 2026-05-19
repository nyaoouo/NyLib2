"""PyInstaller hook for ``nylib.imguiutils.icons``.

The icon module ships TTF resources next to the per-icon-set constants
(``nylib/imguiutils/icons/fa/resources/*.ttf``). PyInstaller doesn't bundle
non-Python files automatically, so without this hook ``install_icon`` would
raise ``FileNotFoundError`` in a frozen build at the
``atlas.AddFontFromFileTTF`` call.

Auto-generated submodules (``fa/solid.py``, ``fa/regular.py``) are imported
statically by ``fa/__init__.py``, so PyInstaller's analyser already picks
them up — we only need to ensure the data files travel with them.
"""

from __future__ import annotations

from PyInstaller.utils.hooks import (  # type: ignore[import-not-found]
    collect_data_files,
    collect_submodules,
)

# Bundle every non-Python file inside the icons package tree (the TTFs).
datas = collect_data_files('nylib.imguiutils.icons')

# Defensive: pin every submodule (per-icon-set constants modules) as a hidden
# import in case a future icon set is loaded via ``importlib`` rather than a
# direct ``from . import ...`` at module top level.
hiddenimports = collect_submodules('nylib.imguiutils.icons')
