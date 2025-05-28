import tkinter
import typing

from . import base_css

_NONE = object()


class Css:
    _is_init = False
    default_mapping = {
        'bg': 'background',
        'fg': 'foreground',
        'font_family': 'font-family',
        'font_size': 'font-size',
        'font_style': 'font-style',
        'border_width': 'border-width',
        'border_radius': 'border-radius',
        'border_color': 'border-color',
    }

    def __new__(cls, widget: tkinter.Misc, no_inherit: list[str] = None, mapping: dict = None):
        if not hasattr(widget, '_css_'):
            return object.__new__(cls)
        if isinstance(_css := widget._css_, Css):
            return _css
        else:
            raise TypeError(f"Widget {widget} already has a Css instance of type {type(_css)}")

    def __init__(self, widget: tkinter.Misc, no_inherit: list[str] = None, mapping: dict = None):
        if self._is_init: return
        self._is_init = True
        self.widget = widget
        self.attrs = {}
        self.vars = {}
        self._valid_keys = set(widget.configure().keys())
        self._listen_fonts = 'font' in self._valid_keys
        self.child = []
        self._no_inherit = set(no_inherit or [])
        self._mapping = mapping or {}
        self._listeners = {}

        self.parent = None
        ptr = widget
        while self.parent is None and ptr is not None:
            if isinstance(css := getattr(ptr, '_css_', None), Css):
                self.parent = css
                css.child.append(self)
                break
            ptr = getattr(ptr, 'master', None)

        widget._css_ = self
        if self.parent is None:
            self.vars = base_css.ROOT_VARS.copy()
            self.attrs = base_css.ROOT_CSS.copy()
        self.reload()

    def reload(self):
        params = {}
        for key in self._valid_keys:
            if key not in self._no_inherit:
                value = self.get(key, None)
                if value is not None:
                    params[key] = self.get_val(value)
        if params:
            self.widget.configure(params)

        for child in self.child:
            child.reload()

    def apply_font(self, *a, widget=None, family=None, size=None, style=None):
        (widget or self.widget).after(0, self._apply_font, widget, family, size, style)

    def _apply_font(self, widget=None, family=None, size=None, style=None):
        (widget or self.widget).configure(font=(
            self.get_val(family or self.get('font-family') or base_css.ROOT_CSS['font-family']),
            self.get_val(size or self.get('font-size') or base_css.ROOT_CSS['font-size']),
            self.get_val(style or self.get('font-style') or base_css.ROOT_CSS['font-style'])
        ))

    def _trigger_change(self, key, new_value):
        new_value_parsed = self.get_val(new_value)
        if key in ('font-family', 'font-size', 'font-style') and 'font' in self._valid_keys:
            if key == 'font-family':
                self.apply_font(family=new_value_parsed)
            elif key == 'font-size':
                self.apply_font(size=new_value_parsed)
            elif key == 'font-style':
                self.apply_font(style=new_value_parsed)
        elif key in self._valid_keys:
            self.widget.configure({key: new_value_parsed})
        for callback in self._listeners.get(key, []):
            callback(key, new_value_parsed)
        for callback in self._listeners.get('*', []):
            callback(key, new_value_parsed)
        if key not in self._no_inherit:
            for child in self.child:
                child._on_parent_change(key, new_value)

    def _on_parent_change(self, key, new_value):
        if key in self._no_inherit: return
        if key in self.attrs: return
        self._trigger_change(key, new_value)

    def get_val(self, val: typing.Any):
        if isinstance(val, str) and val.startswith('var:'):
            val_ = self.get_var(val[4:], None)
            if val_ is None:
                raise ValueError(f"Variable '{val[4:]}' not found in Css.get_var()")
            return self.get_val(val_)
        return val

    def get_var(self, key, default=_NONE):
        if key in self.vars:
            return self.get_val(self.vars[key])
        if self.parent:
            return self.parent.get_var(key, default)
        if default is _NONE:
            raise KeyError(f"Variable '{key}' not found in Css.get_var()")
        return self.get_val(default)

    def get(self, key, default=_NONE):
        key = self._parse_key(key)
        if key == 'font':
            return (
                self.get('font-family') or base_css.ROOT_CSS['font-family'],
                self.get('font-size') or base_css.ROOT_CSS['font-size'],
                self.get('font-style') or base_css.ROOT_CSS['font-style']
            )
        if key in self.attrs:
            return self.get_val(self.attrs[key])
        if self.parent:
            return self.parent.get(key, default)
        if default is _NONE:
            raise KeyError(f"Key '{key}' not found in Css.get()")
        return self.get_val(base_css.ROOT_CSS.get(key, default))

    def set(self, key, value):
        if key == 'font':
            f, s, *a = value
            self.set('font-family', f)
            self.set('font-size', s)
            if a: self.set('font-style', a[0])
            return
        key = self._parse_key(key)
        if value is None:
            self.attrs.pop(key, None)
            if self.parent:
                self._trigger_change(key, self.parent.get(key, None))
        else:
            self.attrs[key] = value
            self._trigger_change(key, value)

    def __getitem__(self, key):
        val = self.get(key)
        if val is None:
            raise KeyError(f"Key '{key}' not found in Css")
        return val

    def __setitem__(self, key, value):
        self.set(key, value)

    def __delitem__(self, key):
        self.set(key, None)

    def _parse_key(self, key: str):
        if key in self._mapping:
            key = self._mapping[key]
        else:
            key = self.default_mapping.get(key, key)
        return key

    def watch(self, key, callback, immediate=False):
        if key == 'font':
            self.watch('font-family', callback, immediate)
            self.watch('font-size', callback, immediate)
            self.watch('font-style', callback, immediate)
            return
        self._listeners.setdefault(self._parse_key(key), []).append(callback)
        if immediate and (val := self.get(key, None)) is not None:
            callback(key, val)

    def unwatch(self, key, callback):
        if key == 'font':
            self.unwatch('font-family', callback)
            self.unwatch('font-size', callback)
            self.unwatch('font-style', callback)
            return
        if key in self._listeners:
            self._listeners[key].remove(callback)
            if not self._listeners[key]:
                del self._listeners[key]

    def __call__(self, cfg: dict = None, **kwargs):
        if cfg is None: cfg = {}
        cfg.update(kwargs)
        for key, value in cfg.items():
            self.set(key, value)


def watch_padding(widget: tkinter.Pack | tkinter.Grid | tkinter.Place, css: Css, padx_key, pady_key):
    old_pack = widget.pack if isinstance(widget, tkinter.Pack) else None
    old_grid = widget.grid if isinstance(widget, tkinter.Grid) else None
    old_place = widget.place if isinstance(widget, tkinter.Place) else None
    if old_pack is not None:
        def new_pack(*args, **kwargs):
            kwargs.setdefault('padx', css.get(padx_key))
            kwargs.setdefault('pady', css.get(pady_key))
            if not hasattr(new_pack, 'isset'):
                css.watch(padx_key, lambda _, v: widget.pack_configure(padx=v))
                css.watch(pady_key, lambda _, v: widget.pack_configure(pady=v))
                setattr(new_pack, 'isset', True)
            return old_pack(*args, **kwargs)

        widget.pack = new_pack
    if old_grid is not None:
        def new_grid(*args, **kwargs):
            kwargs.setdefault('padx', css.get(padx_key))
            kwargs.setdefault('pady', css.get(pady_key))
            if not hasattr(new_grid, 'isset'):
                css.watch(padx_key, lambda _, v: widget.grid_configure(padx=v))
                css.watch(pady_key, lambda _, v: widget.grid_configure(pady=v))
                setattr(new_grid, 'isset', True)
            return old_grid(*args, **kwargs)

        widget.grid = new_grid
    if old_place is not None:
        def new_place(*args, **kwargs):
            kwargs.setdefault('x', css.get(padx_key))
            kwargs.setdefault('y', css.get(pady_key))
            if not hasattr(new_place, 'isset'):
                css.watch(padx_key, lambda _, v: widget.place_configure(x=v))
                css.watch(pady_key, lambda _, v: widget.place_configure(y=v))
                setattr(new_place, 'isset', True)
            return old_place(*args, **kwargs)

        widget.place = new_place
