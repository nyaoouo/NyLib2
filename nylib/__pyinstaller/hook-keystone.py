"""PyInstaller hook for ``keystone-engine``.

``keystone-engine`` ships its native ``keystone.dll`` (``libkeystone.so`` /
``libkeystone.dylib`` on other platforms) next to ``keystone.py`` and loads
it at import time via ``ctypes.cdll.LoadLibrary(join(<package_dir>,
'keystone.dll'))``. PyInstaller does not pick up the DLL through static
analysis, and ``pyinstaller-hooks-contrib`` (as of 2026.5) ships a hook for
``capstone`` but **not** for ``keystone``. Without this hook, a frozen
application that imports ``keystone`` raises::

    ImportError: ERROR: fail to load the dynamic library.

at startup.

``nylib`` uses ``keystone`` via ``nylib.winutils.inline_hook`` and
``nylib.utils.ks_asm``, so any downstream project freezing code that pulls
``nylib`` in needs the DLL bundled. Placing this hook in ``nylib`` itself
makes it a zero-config dependency: as long as the consumer points
PyInstaller at ``nylib/__pyinstaller`` (entry point or
``--additional-hooks-dir``), keystone is bundled automatically.
"""

from PyInstaller.utils.hooks import collect_dynamic_libs

binaries = collect_dynamic_libs('keystone')
