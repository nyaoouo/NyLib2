import tkinter
import typing

from .div import Div

_T = typing.TypeVar('_T')
_T2 = typing.TypeVar('_T2')


class Container(Div, typing.Generic[_T, _T2]):
    main: _T2
    content: _T

    def __init__(self, *args, container_t: typing.Type[_T] = None, container_kw=None, main_t: typing.Type[_T2] = None, main_kw=None, **kwargs):
        super().__init__(*args, **kwargs)
        main_kw = main_kw or {}
        main_kw.setdefault('name', 'main')
        self.main = (main_t or Div)(self, **main_kw)
        container_kw = container_kw or {}
        container_kw.setdefault('name', 'content')
        self.content = (container_t or Div)(self, **container_kw)

    def pack(self, **kwargs):
        kwargs['fill'] = tkinter.BOTH
        kwargs['expand'] = True
        super().pack(**kwargs)


class Aside(Container):
    def __init__(self, parent, width: int, *args, **kwargs):
        super().__init__(parent, *args, **kwargs)
        self.content.config(width=width)
        self.main.config(width=0)

    def pack(self, **kwargs):
        super().pack(**kwargs)
        self.content.pack(side=tkinter.LEFT, fill=tkinter.Y)
        self.main.pack(side=tkinter.LEFT, fill=tkinter.BOTH, expand=True)

    @property
    def width(self):
        return self.content.cget('width')

    @width.setter
    def width(self, value: int):
        self.content.config(width=value)
        self.content.update_idletasks()


class _VContainer(Container):
    _side: str

    def __init__(self, parent, height: int, *args, **kwargs):
        super().__init__(parent, *args, **kwargs)
        self.content.config(height=height)
        self.content.pack_propagate(False)
        self.main.config(height=0)

    def pack(self, **kwargs):
        super().pack(**kwargs)
        self.content.pack(side=self._side, fill=tkinter.X)
        self.main.pack(side=self._side, fill=tkinter.BOTH, expand=True)

    @property
    def height(self):
        return self.content.cget('height')

    @height.setter
    def height(self, value: int):
        self.content.config(height=value)
        self.content.update_idletasks()


class Header(_VContainer):
    _side = tkinter.TOP


class Footer(_VContainer):
    _side = tkinter.BOTTOM
