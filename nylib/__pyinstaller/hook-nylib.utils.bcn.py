"""PyInstaller hook for ``nylib.utils.bcn``: bundle its DLL at ``nylib/utils/bcn/``."""
from PyInstaller.utils.hooks import collect_dynamic_libs

binaries = collect_dynamic_libs('nylib.utils.bcn')
