import tkinter

from nylib.utils.delegate import GroupDelegate
from .utils import Css


class Div(tkinter.Frame):
    def __init__(self, *args, css: dict = None, binds: dict = None, **kwargs):
        super().__init__(*args, **kwargs)
        self.css = Css(self)
        if css:
            self.css(css)
        self.events = GroupDelegate()
        if binds:
            for event, callback in binds.items():
                self.events.add(event, callback)

class _Canvas(tkinter.Canvas):
    def __init__(self, master, *args, css: dict = None, binds: dict = None, **kwargs):
        super().__init__(master, *args, **kwargs)
        self.css = Css(self)
        if css: self.css(css)
        self.events = GroupDelegate()
        if binds:
            for event, callback in binds.items():
                self.events.add(event, callback)
