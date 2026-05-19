"""PyInstaller hook for ``capstone`` (defensive copy).

``pyinstaller-hooks-contrib`` already ships a hook that bundles
``capstone.dll`` via ``collect_dynamic_libs('capstone')``. Since
``pyinstaller-hooks-contrib`` is a mandatory dependency of ``pyinstaller``,
this hook is **strictly redundant** under normal conditions — PyInstaller
will discover and run both, and the resulting binaries list is deduplicated.

It exists so that ``nylib`` remains self-sufficient under non-default
configurations:

* a user with a vendored / stripped-down PyInstaller install that excludes
  the contrib hooks package;
* a future contrib release that breaks or removes the capstone hook;
* downstream projects that explicitly disable contrib hook auto-discovery.

``nylib`` uses capstone via ``nylib.winutils.inline_hook`` and
``nylib.utils.ks_asm``; without ``capstone.dll`` bundled, frozen consumers
fail at import with ``ImportError: ERROR: Fail to load the dynamic library``.
"""

from PyInstaller.utils.hooks import collect_dynamic_libs

binaries = collect_dynamic_libs('capstone')
