import sys
import tkinter.font


def merge_font(a, *b):
    tk_def = tkinter.font.nametofont(a)
    orig_family = tk_def.actual("family")
    tk_def.configure(family=(orig_family, *b))


if sys.platform == "win32":
    import ctypes


    def register_font(fa_path):
        if not ctypes.windll.gdi32.AddFontResourceW(str(fa_path)):
            raise ctypes.WinError()
else:
    import shutil


    def register_font(fa_path):
        shutil.copy(str(fa_path), '~/.fonts/')
