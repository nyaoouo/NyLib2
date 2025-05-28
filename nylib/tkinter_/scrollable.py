import tkinter
import typing

from .div import _Canvas, Div

_T = typing.TypeVar('_T')


class ScrollBar(_Canvas):
    def __init__(self, master, *args, command=None, vertical=True, **kwargs):
        super().__init__(master, *args, borderwidth=0, highlightthickness=0, **kwargs)
        self.command = command

        self.is_dragging = False
        self._vertical = vertical
        self._drag_offset = 0

        self._bar_size = 0
        self._bar_start = 0
        self._first = 0
        self._last = 1

        self.css.watch('scrollbar-width', self.redraw)
        self.css.watch('scrollbar-color', self.redraw)
        self.css.watch('scrollbar-min-height', self.redraw)

        self.bind("<Button-1>", self.on_click)
        self.bind("<ButtonRelease-1>", self.on_release)
        self.bind("<B1-Motion>", self.on_motion)
        self.bind("Leave", self.on_release)

        self._want_redraw = False
        self.redraw()

    def set(self, first, last):
        self._first = float(first)
        self._last = float(last)
        self.redraw()

    def redraw(self, *a):
        if self._want_redraw: return
        self._want_redraw = True
        self.after(0, self._redraw_v if self._vertical else self._redraw_h)

    def _redraw_v(self, *a):
        self._want_redraw = False
        self.delete("all")
        width = self.css.get('scrollbar-width', 5)
        self.configure(width=width)
        available = self._last - self._first
        if available >= 1: return
        progress = self._first / (1 - available)
        color = self.css.get('scrollbar-color', 'gray')
        my_height = self.winfo_height()
        self._bar_size = max(self.css.get('scrollbar-min-height'), int(available / 1 * my_height))
        self._bar_start = int(min(progress, 1) * (my_height - self._bar_size))
        self.create_rectangle(0, self._bar_start, width, self._bar_start + self._bar_size, fill=color, outline=color)

    def _redraw_h(self, *a):
        self._want_redraw = False
        self.delete("all")
        height = self.css.get('scrollbar-width', 5)
        self.configure(height=height)
        available = self._last - self._first
        if available >= 1: return
        progress = self._first / (1 - available)
        color = self.css.get('scrollbar-color', 'gray')
        my_width = self.winfo_width()
        self._bar_size = max(self.css.get('scrollbar-min-height'), int(available / 1 * my_width))
        self._bar_start = int(min(progress, 1) * (my_width - self._bar_size))
        self.create_rectangle(self._bar_start, 0, self._bar_start + self._bar_size, height, fill=color, outline=color)

    def emit(self, *args):
        if self.command:
            self.command(*args)

    def on_click(self, event):
        v = event.y if self._vertical else event.x
        # print(f"Click at {v} in {'vertical' if self._vertical else 'horizontal'} scrollbar, bar start at {self._bar_start}, bar size {self._bar_size}")
        if self._bar_start <= v <= self._bar_start + self._bar_size:
            self.is_dragging = True
            self._drag_offset = v - self._bar_start
            return
        self.is_dragging = False
        if v < self._bar_start:
            self.emit('scroll', -1, "pages")
        else:
            self.emit('scroll', 1, "pages")

    def on_release(self, event):
        self.is_dragging = False

    def on_motion(self, event):
        if not self.is_dragging: return
        if self._vertical:
            v = event.y - self._drag_offset
            max_v = self.winfo_height() - self._bar_size
        else:
            v = event.x - self._drag_offset
            max_v = self.winfo_width() - self._bar_size
        v = max(0, min(v, max_v))
        self.emit('move', v / max_v)


class Scrollable(Div, typing.Generic[_T]):
    main: _T

    def __init__(self, master=None, *args, main_t: typing.Type[_T] = None, main_a=None, main_kw=None, vscroll=True, hscroll=False, **kwargs):
        super().__init__(master, *args, **kwargs)

        self._canvas = tkinter.Canvas(self, borderwidth=0, highlightthickness=0, name='wrapper')
        self.main = (main_t or Div)(self._canvas, *(main_a or []), **({'name': 'main'} | (main_kw or {})))
        if vscroll:
            self.v_scroll_bar = ScrollBar(self, command=self._canvas.yview)
            self.v_scroll_bar.pack(side=tkinter.RIGHT, fill=tkinter.Y)
            self._canvas.bind("<Configure>", lambda e: self.v_scroll_bar.redraw())
            self._canvas.configure(yscrollcommand=self.v_scroll_bar.set)
        else:
            self.v_scroll_bar = None
        if hscroll:
            self.h_scroll_bar = ScrollBar(self, command=self._canvas.xview, vertical=False)
            self.h_scroll_bar.pack(side=tkinter.BOTTOM, fill=tkinter.X)
            self._canvas.bind("<Configure>", lambda e: self.h_scroll_bar.redraw())
            self._canvas.configure(xscrollcommand=self.h_scroll_bar.set)
        else:
            self.h_scroll_bar = None
        self._canvas.pack(side=tkinter.LEFT, fill=tkinter.BOTH, expand=True)
        self._window_id = self._canvas.create_window((0, 0), window=self.main, anchor="nw")

        self.main.bind("<Configure>", lambda e: self._canvas.configure(scrollregion=self._canvas.bbox("all")))
        self._canvas.bind("<Configure>", self._on_canvas_configure)

        self._canvas.bind("<Enter>", lambda e: self._bind_to_mousewheel())
        self._canvas.bind("<Leave>", lambda e: self._unbind_from_mousewheel())

        self.pack_propagate(False)

    def _on_canvas_configure(self, event):
        # whenever the canvas changes size, resize the inner window
        if self.v_scroll_bar:
            height = max(event.height, self.main.winfo_reqheight())
        else:
            height = event.height
        if self.h_scroll_bar:
            width = max(event.width, self.main.winfo_reqwidth())
        else:
            width = event.width
        self._canvas.itemconfigure(self._window_id, width=width, height=height)

    def _on_mousewheel(self, event):
        self._canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

    def _bind_to_mousewheel(self):
        self._canvas.bind_all("<MouseWheel>", self._on_mousewheel)
        self._canvas.bind_all("<Button-4>", lambda e: self._canvas.yview_scroll(-1, "units"))
        self._canvas.bind_all("<Button-5>", lambda e: self._canvas.yview_scroll(1, "units"))

    def _unbind_from_mousewheel(self):
        self._canvas.unbind_all("<MouseWheel>")
        self._canvas.unbind_all("<Button-4>")
        self._canvas.unbind_all("<Button-5>")


_T_Data = typing.TypeVar('_T_Data')
_T_Widget = typing.TypeVar('_T_Widget', bound=tkinter.Widget)


class VirtualScrollable(Div, typing.Generic[_T_Data, _T_Widget]):
    def __init__(self, master=None, *args,
                 create_element_function: typing.Callable[[tkinter.Widget, _T_Data], _T_Widget],
                 data: list[_T_Data] = None,
                 initial_item_height: int = 25,
                 buffer_top: int = 3,
                 buffer_bottom: int = 3,
                 adaptive_buffer: bool = True,
                 max_buffer: int = 10,
                 dynamic_height: bool = True,
                 height_sample_size: int = 10,
                 height_update_threshold: float = 0.1,
                 **kwargs):
        super().__init__(master, *args, **kwargs)

        self.create_element_function = create_element_function
        self.data = data or []

        # Dynamic height estimation
        self._dynamic_height = dynamic_height
        self._initial_item_height = initial_item_height
        self._current_item_height = initial_item_height
        self._height_samples = []
        self._height_sample_size = height_sample_size
        self._height_update_threshold = height_update_threshold
        self._height_measurements = {}  # widget_id -> height mapping
        self._last_average_height = initial_item_height
        self._widget_callbacks = {}  # widget_id -> callback_id mapping

        # Buffer configuration
        self._buffer_top = buffer_top
        self._buffer_bottom = buffer_bottom
        self._adaptive_buffer = adaptive_buffer
        self._max_buffer = max_buffer
        self._current_buffer_top = buffer_top
        self._current_buffer_bottom = buffer_bottom

        # Create canvas for the virtual viewport
        self._canvas = tkinter.Canvas(self, borderwidth=0, highlightthickness=0, name='virtual_wrapper')

        # Create vertical scrollbar
        self.v_scroll_bar = ScrollBar(self, command=self._on_scroll, vertical=True)
        self.v_scroll_bar.pack(side=tkinter.RIGHT, fill=tkinter.Y)

        # Pack canvas
        self._canvas.pack(side=tkinter.LEFT, fill=tkinter.BOTH, expand=True)

        # Virtual scrolling state
        self._visible_widgets: dict[int, _T_Widget] = {}  # index -> widget mapping
        self._first_visible_index = 0
        self._last_visible_index = 0
        self._first_buffer_index = 0
        self._last_buffer_index = 0
        self._total_height = len(self.data) * self._current_item_height

        # Scroll tracking for adaptive buffer
        self._last_scroll_direction = 0
        self._scroll_velocity = 0
        self._last_scroll_time = 0

        # Height recalculation tracking
        self._pending_height_update = False
        self._destroyed = False  # Track if this widget is destroyed

        # Bind events
        self._canvas.bind("<Configure>", self._on_canvas_configure)
        self._canvas.bind("<Enter>", lambda e: self._bind_to_mousewheel())
        self._canvas.bind("<Leave>", lambda e: self._unbind_from_mousewheel())

        # Track when this widget is destroyed
        self.bind("<Destroy>", self._on_destroy)

        # Initial setup
        self.after(1, self._update_view)

    def _on_destroy(self, event):
        """Handle widget destruction"""
        if event.widget == self:
            self._destroyed = True
            # Cancel any pending height updates
            self._pending_height_update = False
            # Clean up all callbacks
            for callback_id in self._widget_callbacks.values():
                try:
                    self.after_cancel(callback_id)
                except:
                    pass
            self._widget_callbacks.clear()

    @property
    def item_height(self) -> float:
        """Get current estimated item height"""
        return self._current_item_height

    def set_dynamic_height(self, enabled: bool, sample_size: int = 10, update_threshold: float = 0.1):
        """Configure dynamic height estimation"""
        self._dynamic_height = enabled
        self._height_sample_size = sample_size
        self._height_update_threshold = update_threshold

        if not enabled:
            self._current_item_height = self._initial_item_height
            self._height_samples.clear()
            self._height_measurements.clear()
            self._cleanup_widget_callbacks()
            self._update_total_height()
            if not self._destroyed:
                self._update_view()

    def _cleanup_widget_callbacks(self):
        """Clean up all widget measurement callbacks"""
        # Create a copy of the items to avoid modification during iteration
        callback_items = list(self._widget_callbacks.items())

        for key, callback_id in callback_items:
            try:
                self.after_cancel(callback_id)
            except:
                pass
            finally:
                # Remove from dictionary
                self._widget_callbacks.pop(key, None)

    def _is_widget_valid(self, widget: _T_Widget) -> bool:
        """Check if a widget is still valid and not destroyed"""
        try:
            # Try to access a basic property to check if widget is valid
            widget.winfo_exists()
            return True
        except (tkinter.TclError, AttributeError):
            return False

    def _measure_widget_height(self, widget: _T_Widget, widget_index: int):
        """Measure and record the height of a widget with error handling"""
        if not self._dynamic_height or self._destroyed:
            return

        if not self._is_widget_valid(widget):
            return

        try:
            # Force update to get accurate measurements
            widget.update_idletasks()

            # Get requested height
            req_height = widget.winfo_reqheight()

            if req_height > 0:  # Valid measurement
                widget_id = id(widget)
                self._height_measurements[widget_id] = req_height

                # Add to samples if not already measured
                if req_height not in self._height_samples:
                    self._height_samples.append(req_height)

                    # Keep only recent samples
                    if len(self._height_samples) > self._height_sample_size:
                        self._height_samples.pop(0)

                    # Schedule height update
                    if not self._pending_height_update and not self._destroyed:
                        self._pending_height_update = True
                        callback_id = self.after_idle(self._update_estimated_height)
                        self._widget_callbacks[f"height_update_{widget_id}"] = callback_id

        except tkinter.TclError:
            # Widget was destroyed or invalid, ignore
            pass
        except Exception as e:
            # Log other exceptions but don't crash
            print(f"Warning: Error measuring widget height: {e}")

    def _update_estimated_height(self):
        """Update the estimated item height based on measurements"""
        if not self._dynamic_height or not self._height_samples or self._destroyed:
            self._pending_height_update = False
            return

        try:
            # Calculate average height
            new_average = sum(self._height_samples) / len(self._height_samples)

            # Only update if change is significant
            height_change_ratio = abs(new_average - self._last_average_height) / self._last_average_height

            if height_change_ratio >= self._height_update_threshold:
                old_height = self._current_item_height
                self._current_item_height = new_average
                self._last_average_height = new_average

                # Adjust scroll position to maintain visual consistency
                self._adjust_scroll_position_for_height_change(old_height, new_average)

                # Update total height and refresh view
                self._update_total_height()
                if not self._destroyed:
                    self._update_view()
                    self._update_scroll_region()

        except Exception as e:
            print(f"Warning: Error updating estimated height: {e}")
        finally:
            self._pending_height_update = False

    def _adjust_scroll_position_for_height_change(self, old_height: float, new_height: float):
        """Adjust scroll position when item height changes to maintain visual consistency"""
        if old_height == new_height:
            return

        # Calculate how the scroll position should change
        height_ratio = new_height / old_height

        # Adjust the first visible index to maintain approximate scroll position
        old_pixel_position = self._first_visible_index * old_height
        new_index_position = old_pixel_position / new_height

        # Keep the scroll position relatively stable
        self._first_visible_index = max(0, min(int(new_index_position), len(self.data) - 1))

    def _update_total_height(self):
        """Update total height based on current item height estimate"""
        self._total_height = len(self.data) * self._current_item_height

    def _create_and_measure_widget(self, index: int) -> _T_Widget:
        """Create a widget and measure its height with proper error handling"""
        widget = self.create_element_function(self._canvas, self.data[index])
        widget_id = id(widget)

        if self._dynamic_height and not self._destroyed:
            # Set up height measurement callback with error handling
            def on_widget_configured(event):
                if event.widget == widget and not self._destroyed:
                    # Schedule measurement for next idle to avoid timing issues
                    if self._is_widget_valid(widget):
                        callback_id = self.after_idle(lambda: self._measure_widget_height(widget, index))
                        self._widget_callbacks[f"measure_{widget_id}"] = callback_id

            # Bind configure event
            widget.bind("<Configure>", on_widget_configured)

            # Initial measurement with delay to ensure widget is fully created
            if not self._destroyed:
                callback_id = self.after(10, lambda: self._measure_widget_height(widget, index))
                self._widget_callbacks[f"initial_{widget_id}"] = callback_id

            # Clean up callback when widget is destroyed
            def on_widget_destroy(event):
                if event.widget == widget:
                    self._remove_widget_measurement(widget)

            widget.bind("<Destroy>", on_widget_destroy)

        return widget

    def _remove_widget_measurement(self, widget: _T_Widget):
        """Remove widget height measurement when widget is destroyed"""
        try:
            widget_id = id(widget)

            # Remove height measurement
            self._height_measurements.pop(widget_id, None)

            # Clean up any pending callbacks for this widget
            # Create a copy of the keys list to avoid modification during iteration
            callback_keys = list(self._widget_callbacks.keys())

            for key in callback_keys:
                if str(widget_id) in key:
                    callback_id = self._widget_callbacks.pop(key, None)
                    if callback_id:
                        try:
                            self.after_cancel(callback_id)
                        except:
                            pass

        except Exception as e:
            # Don't let cleanup errors affect the main operation
            print(f"Warning: Error in _remove_widget_measurement: {e}")

    def set_buffer_sizes(self, top: int, bottom: int):
        """Set the buffer sizes for pre-created widgets"""
        self._buffer_top = max(0, top)
        self._buffer_bottom = max(0, bottom)
        self._current_buffer_top = self._buffer_top
        self._current_buffer_bottom = self._buffer_bottom
        if not self._destroyed:
            self._update_view()

    def get_buffer_sizes(self) -> tuple[int, int]:
        """Get current buffer sizes (top, bottom)"""
        return (self._current_buffer_top, self._current_buffer_bottom)

    def set_adaptive_buffer(self, enabled: bool, max_buffer: int = 10):
        """Enable/disable adaptive buffer sizing based on scroll velocity"""
        self._adaptive_buffer = enabled
        self._max_buffer = max_buffer
        if not enabled:
            self._current_buffer_top = self._buffer_top
            self._current_buffer_bottom = self._buffer_bottom
            if not self._destroyed:
                self._update_view()

    def _calculate_adaptive_buffer(self):
        """Calculate adaptive buffer sizes based on scroll patterns"""
        if not self._adaptive_buffer:
            return

        base_top = self._buffer_top
        base_bottom = self._buffer_bottom

        if self._scroll_velocity > 2:
            multiplier = min(3, 1 + self._scroll_velocity * 0.5)
            if self._last_scroll_direction == 1:
                self._current_buffer_bottom = min(self._max_buffer, int(base_bottom * multiplier))
                self._current_buffer_top = max(1, int(base_top * 0.7))
            elif self._last_scroll_direction == -1:
                self._current_buffer_top = min(self._max_buffer, int(base_top * multiplier))
                self._current_buffer_bottom = max(1, int(base_bottom * 0.7))
        else:
            self._current_buffer_top = max(base_top, self._current_buffer_top - 1)
            self._current_buffer_bottom = max(base_bottom, self._current_buffer_bottom - 1)

    def _on_canvas_configure(self, event):
        """Handle canvas resize"""
        if not self._destroyed:
            self._update_scroll_region()
            self._update_view()

    def _update_scroll_region(self):
        """Update the scroll region based on total data size"""
        if self._destroyed:
            return

        try:
            canvas_height = self._canvas.winfo_height()
            if canvas_height > 1:
                total_height = len(self.data) * self._current_item_height
                visible_ratio = canvas_height / total_height if total_height > 0 else 1.0

                if visible_ratio >= 1.0:
                    self.v_scroll_bar.set(0, 1)
                else:
                    scroll_top = self._first_visible_index * self._current_item_height
                    scroll_bottom = scroll_top + canvas_height

                    first_ratio = scroll_top / total_height
                    last_ratio = scroll_bottom / total_height

                    self.v_scroll_bar.set(first_ratio, min(last_ratio, 1.0))
        except tkinter.TclError:
            # Canvas might be destroyed, ignore
            pass

    def _track_scroll_velocity(self, new_index):
        """Track scrolling velocity for adaptive buffer"""
        import time
        current_time = time.time()

        if self._last_scroll_time > 0:
            time_diff = current_time - self._last_scroll_time
            index_diff = abs(new_index - self._first_visible_index)

            if time_diff > 0:
                self._scroll_velocity = index_diff / time_diff
                if new_index > self._first_visible_index:
                    self._last_scroll_direction = 1
                elif new_index < self._first_visible_index:
                    self._last_scroll_direction = -1

        self._last_scroll_time = current_time

    def _on_scroll(self, *args):
        """Handle scroll events from scrollbar"""
        if not args or self._destroyed:
            return

        try:
            if args[0] == 'scroll':
                direction = args[1]
                canvas_height = self._canvas.winfo_height()
                items_per_page = max(1, int(canvas_height // self._current_item_height))

                if direction > 0:
                    new_first = min(self._first_visible_index + items_per_page, len(self.data) - 1)
                else:
                    new_first = max(0, self._first_visible_index - items_per_page)

                self._track_scroll_velocity(new_first)
                self._scroll_to_index(new_first)

            elif args[0] == 'move':
                position_ratio = args[1]
                total_scrollable = max(0, len(self.data) * self._current_item_height - self._canvas.winfo_height())
                scroll_position = position_ratio * total_scrollable
                new_first = int(scroll_position // self._current_item_height)

                self._track_scroll_velocity(new_first)
                self._scroll_to_index(new_first)
        except tkinter.TclError:
            # Widget might be destroyed, ignore
            pass

    def _scroll_to_index(self, index):
        """Scroll to show item at given index"""
        if self._destroyed:
            return

        self._first_visible_index = max(0, min(index, len(self.data) - 1))
        self._calculate_adaptive_buffer()
        self._update_view()
        self._update_scroll_region()

    def _calculate_widget_ranges(self):
        """Calculate the ranges for visible and buffered widgets"""
        if not self.data or self._destroyed:
            return 0, 0, 0, 0

        try:
            canvas_height = self._canvas.winfo_height()
            if canvas_height <= 1:
                return 0, 0, 0, 0

            # Calculate visible range using current item height
            items_per_view = int(canvas_height // self._current_item_height) + 1
            visible_last = min(len(self.data) - 1, self._first_visible_index + items_per_view - 1)

            # Calculate buffered range
            buffer_first = max(0, self._first_visible_index - self._current_buffer_top)
            buffer_last = min(len(self.data) - 1, visible_last + self._current_buffer_bottom)

            return self._first_visible_index, visible_last, buffer_first, buffer_last
        except tkinter.TclError:
            return 0, 0, 0, 0

    def _update_view(self):
        """Update the visible widgets based on current scroll position"""
        if not self.data or self._destroyed:
            return

        try:
            visible_first, visible_last, buffer_first, buffer_last = self._calculate_widget_ranges()

            # Remove widgets that are outside the buffer range
            # Create a copy of the items to avoid dictionary modification during iteration
            widgets_to_remove = []
            widget_items = list(self._visible_widgets.items())  # Create a snapshot

            for idx, widget in widget_items:
                if idx < buffer_first or idx > buffer_last:
                    widgets_to_remove.append((idx, widget))

            # Remove widgets outside buffer range
            for idx, widget in widgets_to_remove:
                # Remove from dictionary first
                self._visible_widgets.pop(idx, None)
                # Then clean up the widget
                try:
                    self._remove_widget_measurement(widget)
                    widget.destroy()
                except (tkinter.TclError, RuntimeError):
                    pass  # Widget already destroyed

            # Create widgets for items in buffer range that don't exist yet
            for idx in range(buffer_first, buffer_last + 1):
                if idx not in self._visible_widgets and idx < len(self.data):
                    try:
                        widget = self._create_and_measure_widget(idx)
                        self._visible_widgets[idx] = widget
                    except Exception as e:
                        print(f"Warning: Error creating widget at index {idx}: {e}")

            # Position all widgets using current item height
            # Again, create a snapshot to avoid concurrent modification
            widget_items = list(self._visible_widgets.items())
            canvas_width = self._canvas.winfo_width()

            widgets_to_remove = []  # Track invalid widgets found during positioning

            for idx, widget in widget_items:
                if self._is_widget_valid(widget):
                    try:
                        y_position = (idx - self._first_visible_index) * self._current_item_height
                        widget.place(x=0, y=y_position, width=canvas_width)

                        if visible_first <= idx <= visible_last:
                            if not widget.winfo_viewable():
                                widget.lift()
                        else:
                            widget.lower()
                    except tkinter.TclError:
                        # Widget was destroyed, mark for removal
                        widgets_to_remove.append((idx, widget))
                else:
                    # Widget is invalid, mark for removal
                    widgets_to_remove.append((idx, widget))

            # Clean up invalid widgets found during positioning
            for idx, widget in widgets_to_remove:
                self._visible_widgets.pop(idx, None)
                self._remove_widget_measurement(widget)

            self._last_visible_index = visible_last
            self._first_buffer_index = buffer_first
            self._last_buffer_index = buffer_last

        except Exception as e:
            print(f"Warning: Error in _update_view: {e}")

    def _on_mousewheel(self, event):
        """Handle mouse wheel scrolling"""
        if self._destroyed:
            return

        scroll_amount = 3
        direction = -1 if event.delta > 0 else 1

        new_first = self._first_visible_index + (direction * scroll_amount)
        new_first = max(0, min(new_first, len(self.data) - 1))

        self._track_scroll_velocity(new_first)
        self._scroll_to_index(new_first)

    def _bind_to_mousewheel(self):
        """Bind mouse wheel events"""
        if not self._destroyed:
            self._canvas.bind_all("<MouseWheel>", self._on_mousewheel)
            self._canvas.bind_all("<Button-4>", lambda e: self._on_mousewheel(type('Event', (), {'delta': 120})()))
            self._canvas.bind_all("<Button-5>", lambda e: self._on_mousewheel(type('Event', (), {'delta': -120})()))

    def _unbind_from_mousewheel(self):
        """Unbind mouse wheel events"""
        if not self._destroyed:
            try:
                self._canvas.unbind_all("<MouseWheel>")
                self._canvas.unbind_all("<Button-4>")
                self._canvas.unbind_all("<Button-5>")
            except tkinter.TclError:
                pass

    def update_data(self, new_data: list[_T_Data]):
        """Update the data list and refresh the view"""
        if self._destroyed:
            return

        # Create a copy of the widgets list to avoid "dictionary changed size during iteration"
        widgets_to_clean = list(self._visible_widgets.values())
        widget_indices = list(self._visible_widgets.keys())

        # Clear the dictionary first to prevent concurrent access
        self._visible_widgets.clear()

        # Clean up widgets and measurements
        for i, widget in enumerate(widgets_to_clean):
            try:
                # Remove measurements first
                self._remove_widget_measurement(widget)
                # Then destroy the widget
                widget.destroy()
            except (tkinter.TclError, RuntimeError):
                # Widget already destroyed or invalid, continue
                pass
            except Exception as e:
                print(f"Warning: Error cleaning up widget {i}: {e}")

        # Clean up all callbacks
        self._cleanup_widget_callbacks()

        # Reset all tracking
        self._last_scroll_direction = 0
        self._scroll_velocity = 0
        self._last_scroll_time = 0
        self._height_samples.clear()
        self._height_measurements.clear()

        # Update data
        self.data = new_data
        self._first_visible_index = 0
        self._last_visible_index = 0

        # Reset to initial height
        self._current_item_height = self._initial_item_height
        self._last_average_height = self._initial_item_height

        # Update total height and refresh
        self._update_total_height()
        if not self._destroyed:
            self._update_view()
            self._update_scroll_region()

    def scroll_to_item(self, index: int):
        """Scroll to make the item at given index visible"""
        if 0 <= index < len(self.data) and not self._destroyed:
            self._scroll_to_index(index)

    def get_visible_range(self) -> tuple[int, int]:
        """Get the range of currently visible item indices"""
        return (self._first_visible_index, self._last_visible_index)

    def get_buffer_range(self) -> tuple[int, int]:
        """Get the range of currently buffered item indices"""
        return (self._first_buffer_index, self._last_buffer_index)

    def get_height_statistics(self) -> dict:
        """Get statistics about height measurements and estimation"""
        current_measurements = list(self._height_measurements.values())

        stats = {
            'current_estimated_height': self._current_item_height,
            'initial_height': self._initial_item_height,
            'sample_count': len(self._height_samples),
            'measurement_count': len(current_measurements),
            'dynamic_height_enabled': self._dynamic_height,
        }

        if current_measurements:
            stats.update({
                'min_measured_height': min(current_measurements),
                'max_measured_height': max(current_measurements),
                'avg_measured_height': sum(current_measurements) / len(current_measurements),
            })

        if self._height_samples:
            stats.update({
                'min_sample_height': min(self._height_samples),
                'max_sample_height': max(self._height_samples),
                'avg_sample_height': sum(self._height_samples) / len(self._height_samples),
            })

        return stats

    def get_widget_stats(self) -> dict:
        """Get comprehensive statistics about widget creation and performance"""
        if self._destroyed:
            return {'error': 'Widget destroyed'}

        try:
            visible_first, visible_last, buffer_first, buffer_last = self._calculate_widget_ranges()

            base_stats = {
                'total_items': len(self.data),
                'visible_items': visible_last - visible_first + 1 if self.data else 0,
                'buffered_items': len(self._visible_widgets),
                'buffer_top_size': self._current_buffer_top,
                'buffer_bottom_size': self._current_buffer_bottom,
                'scroll_velocity': self._scroll_velocity,
                'scroll_direction': self._last_scroll_direction,
                'visible_range': (visible_first, visible_last),
                'buffer_range': (buffer_first, buffer_last)
            }

            height_stats = self.get_height_statistics()
            base_stats.update(height_stats)

            return base_stats
        except Exception as e:
            return {'error': f'Error getting stats: {e}'}

    def force_height_recalculation(self):
        """Force recalculation of item height from current widgets"""
        if not self._dynamic_height or self._destroyed:
            return

        # Clear existing samples to force fresh calculation
        self._height_samples.clear()

        # Re-measure all current widgets
        for idx, widget in self._visible_widgets.items():
            if self._is_widget_valid(widget):
                self.after_idle(lambda w=widget, i=idx: self._measure_widget_height(w, i))
