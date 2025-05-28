import tkinter.font

from nylib.utils.delegate import GroupDelegate
from .utils import Css, border


class Button(tkinter.Canvas):
    def __init__(self, master, text: str, preset='info', cfg=None, css: dict = None, binds: dict = None, disabled=False, **kwargs):
        cfg = cfg or {}
        cfg.update(kwargs)

        super().__init__(master, cfg, highlightthickness=0, borderwidth=0)

        self.css = Css(self)
        if css:
            self.css(css)
        self.events = GroupDelegate()
        if binds:
            for event, callback in binds.items():
                self.events.add(event, callback)

        self._text = text
        self._mode = 'normal'
        self._preset = preset
        self._disabled = disabled

        self.bind('<Enter>', self.on_enter)
        self.bind('<Leave>', self.on_leave)
        self.bind('<ButtonPress-1>', self.on_press)
        self.bind('<ButtonRelease-1>', self.on_release)
        self.bind('<Configure>', self.redraw)
        self.css.watch('font', self.redraw)
        self._font = self._tk_font = None

        self._waiting_redraw = False
        self.redraw()

        self._ui_mode = None

    def pack(self, *args, **kwargs):
        self._ui_mode = 'pack'
        super().pack(*args, **kwargs)

    def grid(self, *args, **kwargs):
        self._ui_mode = 'grid'
        super().grid(*args, **kwargs)

    def place(self, *args, **kwargs):
        self._ui_mode = 'place'
        super().place(*args, **kwargs)

    @property
    def text(self):
        return self._text

    @text.setter
    def text(self, value: str):
        if value == self._text: return
        self._text = value
        self.redraw()

    @property
    def disabled(self):
        return self._disabled

    @disabled.setter
    def disabled(self, value: bool):
        if value == self._disabled: return
        self._disabled = value
        self.redraw()
        if self._mode == 'hover':
            self.configure(cursor='')

    def set_mode(self, mode):
        if mode == self._mode: return
        self._mode = mode
        if self._disabled: return
        self.redraw()

    def on_enter(self, event):
        self.set_mode('hover')
        if not self._disabled:
            self.configure(cursor='hand2')

    def on_leave(self, event):
        self.set_mode('normal')
        self.configure(cursor='')

    def on_press(self, event):
        self.set_mode('active')

    def on_release(self, event):
        if not self._disabled:
            self.events("OnClick")
        self.set_mode('hover')

    def redraw(self, *a):
        if self._waiting_redraw: return
        self.after(0, self._redraw)

    def _redraw(self):
        self._waiting_redraw = False
        font = self.css.get('font')
        if font != self._font:
            self._font = font
            self._tk_font = tkinter.font.Font(font=self._font)

        padding = self.css.get('button-padding')
        b_radius = self.css.get('button-border-radius')
        b_width = self.css.get('button-border-width')
        if self._disabled:
            b_color = self.css.get_var(f'color-button-disabled-border')
            bg_color = self.css.get_var(f'color-button-disabled-bg')
            fg_color = self.css.get_var(f'color-button-disabled-fg')
        else:
            b_color = self.css.get_var(f'color-button-{self._mode}-border-{self._preset}')
            bg_color = self.css.get_var(f'color-button-{self._mode}-bg-{self._preset}')
            fg_color = self.css.get_var(f'color-button-{self._mode}-fg-{self._preset}')

        size_pad = (padding + b_width) * 2
        height = self._tk_font.metrics('linespace') + size_pad
        pinfo = {}
        try:
            if self._ui_mode == 'grid':
                pinfo = self.grid_info()
            elif self._ui_mode == 'pack':
                pinfo = self.pack_info()
            elif self._ui_mode == 'place':
                pinfo = self.place_info()
        except tkinter.TclError:
            return
        if pinfo.get('fill') not in (tkinter.BOTH, tkinter.X) and not pinfo.get('expand'):
            width = self._tk_font.measure(self._text) + size_pad
        else:
            width = self.master.winfo_width() - pinfo.get('padx', 0) * 2 - pinfo.get('ipadx', 0) * 2
        self.configure(width=width, height=height)
        self.delete('all')
        if b_width > 0:
            if b_radius > 0:
                border.create_rounded_rect(
                    self, 0, 0, width, height,
                    radius=b_radius, fill=bg_color,
                    outline=b_color, width=b_width
                )
                border.create_rounded_rect(
                    self, b_width, b_width, width - b_width, height - b_width,
                    radius=b_radius, fill=bg_color, outline=''
                )
            else:
                self.create_rectangle(
                    0, 0, width, height,
                    fill=bg_color, outline=b_color, width=b_width
                )
                self.create_rectangle(
                    b_width, b_width, width - b_width, height - b_width,
                    fill=bg_color, outline=''
                )
        else:
            if b_radius > 0:
                border.create_rounded_rect(
                    self, 0, 0, width, height,
                    radius=b_radius, fill=bg_color, outline=''
                )
            else:
                self.create_rectangle(
                    0, 0, width, height,
                    fill=bg_color, outline=''
                )
        self.create_text(
            width // 2, height // 2,
            text=self._text, fill=fg_color, font=self._tk_font
        )
