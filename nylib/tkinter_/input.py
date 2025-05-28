import tkinter
from .div import Div
from .utils import Css, Border
from .utils.css import watch_padding


class Input(Div):
    def __init__(self, master, *args, title='', type_='text', **kwargs):
        super().__init__(master, *args, **kwargs)
        self._type = type_
        self.border = Border(self, title=title)
        self.entry = tkinter.Entry(self, highlightthickness=0, borderwidth=0)
        Css(self.entry)  # just attach a Css instance to the entry widget
        self.entry.pack(padx=5, pady=(self.border.base_y * 2 + 5, 5), fill=tkinter.BOTH, expand=True)
        self.entry.bind('<KeyRelease>', self.on_key_release)

        self.css.watch('input-border-width', lambda k, v: self.border.css({'border-width': v}), immediate=True)
        self.css.watch('input-border-radius', lambda k, v: self.border.css({'border-radius': v}), immediate=True)
        self.css.watch('input-border-color', lambda k, v: self.border.css({'border-color': v}), immediate=True)

        self._last_value = ''
        watch_padding(self, self.css, 'input-padx', 'input-pady')

    def __revert_last_value(self):
        self.entry.delete(0, tkinter.END)
        self.entry.insert(0, self._last_value)

    def __save_last_value(self, v=None):
        self._last_value = self.entry.get() if v is None else v

    def on_key_release(self, event):
        value = raw = event.widget.get()
        if self._type == 'number':
            if value:
                if not value.replace('.', '', 1).isdigit():
                    self.__revert_last_value()
                    return
                value = float(value) if '.' in value else int(value)
            else:
                value = 0

        self.__save_last_value(raw)
        self.events('OnChange', value)
        if event.keysym == 'Return':
            self.events('OnEnter', value)

    @property
    def value(self):
        value = self.entry.get()
        if self._type == 'number':
            if value and value.replace('.', '', 1).isdigit():
                value = float(value) if '.' in value else int(value)
            else:
                value = 0
        return value

    @value.setter
    def value(self, v):
        if self._type == 'number':
            if isinstance(v, str) and v.replace('.', '', 1).isdigit():
                v = float(v) if '.' in v else int(v)
            elif not isinstance(v, (int, float)):
                raise ValueError(f"Invalid value for type '{self._type}': {v}")
        self.__save_last_value(v)
        self.entry.delete(0, tkinter.END)
        self.entry.insert(0, str(v))
        self.events('OnUpdate', v)
