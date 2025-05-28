import tkinter.font
from .css import Css


def create_rounded_rect(self, x1, y1, x2, y2, radius=25, **kwargs):
    return self.create_polygon([
        x1 + radius, y1,  # Top left point
        x2 - radius, y1,  # Top right point
        x2, y1,  # Top right corner start
        x2, y1 + radius,  # Top right corner end
        x2, y2 - radius,  # Bottom right corner start
        x2, y2,  # Bottom right corner end
        x2 - radius, y2,  # Bottom right point
        x1 + radius, y2,  # Bottom left point
        x1, y2,  # Bottom left corner start
        x1, y2 - radius,  # Bottom left corner end
        x1, y1 + radius,  # Top left corner start
        x1, y1  # Top left corner end
    ], **kwargs, smooth=True)


class Border(tkinter.Canvas):
    def __init__(self, master, *args, fill_css='background', title='', **kwargs):
        super().__init__(master, *args, **kwargs, borderwidth=0, highlightthickness=0)
        self.css = Css(self)

        self._waiting_redraw = False
        self._fill_css = fill_css
        self._title = title

        self.place(relx=0, rely=0, relwidth=1, relheight=1, anchor='nw')

        self.css.watch('border-width', self.next_frame_redraw)
        self.css.watch('border-radius', self.next_frame_redraw)
        self.css.watch('border-color', self.next_frame_redraw)
        self.css.watch(fill_css, self.next_frame_redraw)
        self.bind('<Configure>', self.next_frame_redraw)
        self._tk_font = None
        self._font = None
        self.next_frame_redraw()

    def next_frame_redraw(self, *a):
        if not self._waiting_redraw:
            self._waiting_redraw = True
            self.after(0, self.redraw)

    @property
    def title(self):
        return self._title

    @title.setter
    def title(self, value: str):
        if value == self._title: return
        self._title = value
        self.place_forget()
        self.place(relx=0, rely=0, relwidth=1, relheight=1, anchor='nw')
        self.next_frame_redraw()

    @property
    def tk_font(self):
        font = self.css.get('border-title-font')
        if font == self._font:
            return self._tk_font
        self._font = font
        self._tk_font = tkinter.font.Font(family=font[0], size=font[1])
        return self._tk_font

    @property
    def base_y(self):
        if self.title:
            return self.tk_font.metrics('ascent') // 2
        return 0

    def redraw(self):
        self._waiting_redraw = False
        border_width = self.css.get('border-width')
        if border_width <= 0: return
        radius = self.css.get('border-radius')
        color = self.css.get('border-color')
        fill = self.css.get(self._fill_css)

        width = self.winfo_width()
        height = self.winfo_height()
        # print(f"Redrawing border: {width}x{height}, radius={radius}, color={color}, fill={fill}")
        self.delete('all')
        base_y = self.base_y

        if radius > 0:
            create_rounded_rect(
                self,
                0, base_y, width, height, radius=radius,
                outline=color, width=border_width, fill=fill
            )
            # create_rounded_rect(
            #     self,
            #     border_width, base_y+border_width, width - border_width, height - border_width,
            #     radius=radius,
            #     fill=fill, outline=''
            # )
        else:
            self.create_rectangle(
                0, base_y, width, height,
                outline=color, width=border_width, fill=fill
            )
            # self.create_rectangle(
            #     border_width, base_y+border_width, width - border_width, height - border_width,
            #     fill=fill, outline=''
            # )
        if self._title:
            # add to the top left corner on the border
            text_fg = self.css.get('border-title-foreground')
            tk_font = self.tk_font
            text_width = self.tk_font.measure(self._title)
            self.create_rectangle(border_width, 0, border_width + text_width + 6, base_y * 2, fill=fill, outline='')
            self.create_text(border_width + 3, 0, text=self._title, anchor='nw', fill=text_fg, font=tk_font)
