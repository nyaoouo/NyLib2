from .process import *
from .. import winapi


def write_to_clipboard(text: str):
    text = text.encode('utf-16le') + b'\0\0'
    winapi.OpenClipboard(0)
    winapi.EmptyClipboard()
    try:
        h = winapi.GlobalAlloc(0x0042, len(text))
        p = winapi.GlobalLock(h)
        winapi.memcpy(p, text, len(text))
        winapi.GlobalUnlock(h)
        winapi.SetClipboardData(13, h)
        return True
    finally:
        winapi.CloseClipboard()
