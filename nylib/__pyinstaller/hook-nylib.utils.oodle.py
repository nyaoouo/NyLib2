"""PyInstaller hook for ``nylib.utils.oodle``: bundle its Oodle DLLs at ``nylib/utils/oodle/``."""
from PyInstaller.utils.hooks import collect_dynamic_libs

binaries = collect_dynamic_libs('nylib.utils.oodle')
