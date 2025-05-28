import tkinter

from nylib.utils.delegate import GroupDelegate
from .utils import Css


class Label(tkinter.Entry):
    def __init__(self, master, text='', *args, css=None, binds: dict = None, **kwargs):
        super().__init__(master, *args, highlightthickness=0, borderwidth=0, **kwargs)
        self.css = Css(self)
        if css:
            self.css(css)
        self.events = GroupDelegate()
        if binds:
            for event, callback in binds.items():
                self.events.add(event, callback)
        self.css.watch('background', lambda k, v: self.configure(readonlybackground=v), immediate=True)
        if text:
            self.text = text
        else:
            self.configure(state='readonly', width=0)

    @property
    def text(self):
        return self.get()

    @text.setter
    def text(self, value: str):
        if value == self.get(): return
        self.configure(state='normal')
        self.delete(0, tkinter.END)
        self.insert(0, value)
        self.configure(state='readonly', width=len(value))


class LabelCantSelect(tkinter.Label):
    def __init__(self, master, text='', *args, **kwargs):
        super().__init__(master, *args, **kwargs)
        self.css = Css(self)

    @property
    def text(self):
        return self.cget("text")

    @text.setter
    def text(self, value: str): \
            self.configure(text=value)
