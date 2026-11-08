import sys
import tkinter.font


def merge_font(a, *b):
    tk_def = tkinter.font.nametofont(a)
    orig_family = tk_def.actual("family")
    tk_def.configure(family=(orig_family, *b))


if sys.platform == "win32":
    import ctypes


    def register_font(fa_path):
        ctypes.set_last_error(0)
        if not ctypes.WinDLL("gdi32", use_last_error=True).AddFontResourceW(str(fa_path)):
            if code := ctypes.get_last_error(): raise ctypes.WinError(code)
            raise OSError(f"AddFontResourceW added no font from {str(fa_path)!r}")
else:
    import shutil


    def register_font(fa_path):
        shutil.copy(str(fa_path), '~/.fonts/')
