import sys
import tkinter
from .button import Button
from .div import Div
from .label import LabelCantSelect


class BorderlessWindow(Div):
    def __init__(self, root: tkinter.Toplevel | tkinter.Tk, title=None):
        self.root = root
        super().__init__(root)
        self.pack(fill=tkinter.BOTH, expand=True)
        root.overrideredirect(True)

        try:
            root.attributes("-alpha", 0.95)
            root.attributes("-topmost", True)
        except:
            pass  # Not all platforms support this

        # Variables for window dragging
        self.drag_x = 0
        self.drag_y = 0
        self.dragging = False

        # Variables for window resizing
        self.resizing = False
        self.resize_edge = None
        self.resize_x = 0
        self.resize_y = 0
        self.min_width = 300
        self.min_height = 200
        self.border_size = 5  # Size of the invisible border for resizing

        # Store window state
        self.maximized = False
        self.normal_size = None

        self.title_bar = Div(self, height=30)
        self.title_bar.css._no_inherit.add('background')
        self.title_bar.pack(fill=tkinter.X)
        self.title_bar.pack_propagate(False)

        self.title_label = LabelCantSelect(self.title_bar)
        self.title_label.pack(side=tkinter.LEFT, padx=10)
        self.title = title or root.title()

        self.title_buttons = Div(self.title_bar)
        self.title_buttons.pack(side=tkinter.RIGHT, padx=5)
        self.title_buttons.css({
            'button-border-width': 0,
            'font-size': 14,
        })

        self.close_button = Button(self.title_buttons, text="×", preset='danger', command=root.destroy)
        self.close_button.pack(side=tkinter.RIGHT, padx=2)

        self.max_button = Button(self.title_buttons, text="□", preset='primary', command=self.toggle_maximize)
        self.max_button.pack(side=tkinter.RIGHT, padx=2)

        self.min_button = Button(self.title_buttons, text="-", preset='success', command=self.minimize)
        self.min_button.pack(side=tkinter.RIGHT, padx=2)

        self.title_bar.css.watch('title-bar-background', self.on_title_bar_bg_change)
        self.title_bar.bind("<ButtonPress-1>", self.start_drag)
        self.title_bar.bind("<ButtonRelease-1>", self.stop_drag)
        self.title_bar.bind("<B1-Motion>", self.do_drag)
        self.title_label.bind("<ButtonPress-1>", self.start_drag)
        self.title_label.bind("<ButtonRelease-1>", self.stop_drag)
        self.title_label.bind("<B1-Motion>", self.do_drag)
        self.title_bar.css(font_size=10)

        self.main = Div(self)
        self.main.pack(fill=tkinter.BOTH, expand=True, padx=2, pady=2)

        root.bind("<Motion>", self.check_cursor)
        root.bind("<ButtonPress-1>", self.start_resize)
        root.bind("<ButtonRelease-1>", self.stop_resize)
        root.bind("<B1-Motion>", self.do_resize)

    @property
    def title(self):
        return self.title_label.text

    @title.setter
    def title(self, value):
        self.title_label.text = value
        self.root.title(value)

    def on_title_bar_bg_change(self, k, color):
        self.title_bar.config(background=color)
        self.title_label.css(background=color)

    def start_drag(self, event):
        self.drag_x = event.x
        self.drag_y = event.y
        self.dragging = True
        return "break"  # Stop event propagation

    def stop_drag(self, event):
        self.dragging = False
        return "break"  # Stop event propagation

    def do_drag(self, event):
        if self.dragging and not self.maximized:
            x = self.root.winfo_x() - self.drag_x + event.x
            y = self.root.winfo_y() - self.drag_y + event.y
            self.root.geometry(f"+{x}+{y}")
        return "break"  # Stop event propagation

    def toggle_maximize(self):
        if self.maximized:
            # Restore window size
            self.root.geometry(self.normal_size)
            self.maximized = False
            self.max_button.text = "□"
        else:
            # Save current size for restore
            self.normal_size = self.root.geometry()
            # Maximize
            width = self.root.winfo_screenwidth()
            height = self.root.winfo_screenheight()
            self.root.geometry(f"{width}x{height}+0+0")
            self.maximized = True
            self.max_button.text = "❐"

    def minimize(self):
        self.root.withdraw()
        self.root.overrideredirect(False)
        self.root.iconify()

        # Bind deiconify event to restore window properly
        self.root.bind("<Map>", self.deiconify)

    def deiconify(self, event=None):
        self.root.overrideredirect(True)
        self.root.deiconify()

    def check_cursor(self, event):
        if self.maximized:
            self.root.config(cursor="arrow")
            return

        # Get window position and size
        root_x = self.root.winfo_x()
        root_y = self.root.winfo_y()
        root_width = self.root.winfo_width()
        root_height = self.root.winfo_height()

        # Convert event position to absolute position
        abs_x = root_x + event.x
        abs_y = root_y + event.y

        # Check if cursor is on window edges
        on_left = abs_x < root_x + self.border_size
        on_right = abs_x > root_x + root_width - self.border_size
        on_top = abs_y < root_y + self.border_size
        on_bottom = abs_y > root_y + root_height - self.border_size

        # Set appropriate cursor
        if on_top and on_left:
            self.root.config(cursor="sizing")  # or "top_left_corner"
            self.resize_edge = "topleft"
        elif on_top and on_right:
            self.root.config(cursor="sizing")  # or "top_right_corner"
            self.resize_edge = "topright"
        elif on_bottom and on_left:
            self.root.config(cursor="sizing")  # or "bottom_left_corner"
            self.resize_edge = "bottomleft"
        elif on_bottom and on_right:
            self.root.config(cursor="sizing")  # or "bottom_right_corner"
            self.resize_edge = "bottomright"
        elif on_left:
            self.root.config(cursor="size_we")  # or "left_side"
            self.resize_edge = "left"
        elif on_right:
            self.root.config(cursor="size_we")  # or "right_side"
            self.resize_edge = "right"
        elif on_top:
            self.root.config(cursor="size_ns")  # or "top_side"
            self.resize_edge = "top"
        elif on_bottom:
            self.root.config(cursor="size_ns")  # or "bottom_side"
            self.resize_edge = "bottom"
        else:
            self.root.config(cursor="arrow")
            self.resize_edge = None

    def start_resize(self, event):
        if not self.maximized and self.resize_edge:
            self.resizing = True
            self.resize_x = event.x_root
            self.resize_y = event.y_root

    def stop_resize(self, event):
        self.resizing = False

    def do_resize(self, event):
        if self.resizing and self.resize_edge and not self.maximized:
            # Calculate change in position
            dx = event.x_root - self.resize_x
            dy = event.y_root - self.resize_y

            # Get current window geometry
            x = self.root.winfo_x()
            y = self.root.winfo_y()
            width = self.root.winfo_width()
            height = self.root.winfo_height()

            # Handle resizing based on edge
            if "left" in self.resize_edge:
                # Don't allow width to go below minimum
                if width - dx >= self.min_width:
                    x += dx
                    width -= dx
                else:
                    width = self.min_width
                    x = x + width - self.min_width

            if "right" in self.resize_edge:
                # Don't allow width to go below minimum
                width = max(width + dx, self.min_width)

            if "top" in self.resize_edge:
                # Don't allow height to go below minimum
                if height - dy >= self.min_height:
                    y += dy
                    height -= dy
                else:
                    height = self.min_height
                    y = y + height - self.min_height

            if "bottom" in self.resize_edge:
                # Don't allow height to go below minimum
                height = max(height + dy, self.min_height)

            # Apply new geometry
            self.root.geometry(f"{width}x{height}+{x}+{y}")

            # Update resize reference position
            self.resize_x = event.x_root
            self.resize_y = event.y_root
