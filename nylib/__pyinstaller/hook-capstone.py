"""Bundle ``capstone.dll``, as the contrib hook also does.

PyInstaller runs one hook per module, selecting the higher priority.
When found, nylib's hook (entry point: 0; ``--additional-hooks-dir``: 1000) replaces contrib's (-1000).
"""

from PyInstaller.utils.hooks import collect_dynamic_libs

binaries = collect_dynamic_libs('capstone')
