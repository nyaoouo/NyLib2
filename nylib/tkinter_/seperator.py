import tkinter

from nylib.utils.delegate import GroupDelegate
from .utils import Css
from .utils.css import watch_padding


class Seperator(tkinter.Canvas):
    def __init__(self, master, *args, css=None, binds: dict = None, **kwargs):
        super().__init__(master, *args, highlightthickness=0, borderwidth=0, **kwargs)
        self.css = Css(self)
        if css:
            self.css(css)
        self.events = GroupDelegate()
        if binds:
            for event, callback in binds.items():
                self.events.add(event, callback)

        self.want_redraw = False
        self.bind("<Configure>", self.redraw)
        watch_padding(self, self.css, 'seperator-padx', 'seperator-pady')

    def pack(self, *args, **kwargs):
        kwargs.setdefault('fill', 'x')
        kwargs.setdefault('expand', False)
        super().pack(*args, **kwargs)

    def redraw(self, *a):
        if self.want_redraw: return
        self.want_redraw = True
        self.after(0, self._redraw)

    def _redraw(self, *a):
        self.want_redraw = False
        height = self.css.get('seperator-height', 3)
        color = self.css.get('seperator-color', 'gray')
        self.configure(height=height)  # width should be autp expanded
        self.delete("all")
        self.create_rectangle(0, 0, self.winfo_width(), height, fill=color, outline=color)
