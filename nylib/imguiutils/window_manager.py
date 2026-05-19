"""Global window manager for stacked imgui dialogs / popups.

Usage:
    handle = window_manager.add(my_render_fn)   # my_render_fn() -> bool
    # each frame:
    window_manager.render()
    # manually close:
    window_manager.close(handle)

`my_render_fn` returns ``True`` to keep being rendered next frame, ``False`` to
be removed from the manager. Exceptions inside a render fn are caught, logged,
and treated as ``False``.

A render fn registered later is rendered later in the same frame, so it sits
visually on top of earlier ones. Use ``bring_to_front`` / ``send_to_back`` /
``move`` / ``reorder`` to reshuffle.
"""
from __future__ import annotations

import traceback
import typing

RenderFn = typing.Callable[[], bool]


class WindowManager:
    def __init__(self) -> None:
        self._windows: dict[int, RenderFn] = {}
        self._order: list[int] = []
        self._pending_close: set[int] = set()
        self._next: int = 1

    # ---- lifecycle -------------------------------------------------

    def add(self, render: RenderFn) -> int:
        """Register a render function. Returns a handle for ``close``."""
        if not callable(render):
            raise TypeError("render must be callable")
        handle = self._next
        self._next += 1
        self._windows[handle] = render
        self._order.append(handle)
        return handle

    def close(self, handle: int) -> bool:
        """Schedule a window for removal at the next ``render`` boundary."""
        if handle not in self._windows:
            return False
        self._pending_close.add(handle)
        return True

    def render(self) -> None:
        """Render every active window in stack order (back to front)."""
        self._reap()
        for handle in list(self._order):
            if handle in self._pending_close:
                continue
            fn = self._windows.get(handle)
            if fn is None:
                continue
            try:
                keep = bool(fn())
            except Exception:
                traceback.print_exc()
                keep = False
            if not keep:
                self._pending_close.add(handle)
        self._reap()

    def _reap(self) -> None:
        if not self._pending_close:
            return
        for h in self._pending_close:
            self._windows.pop(h, None)
            try:
                self._order.remove(h)
            except ValueError:
                pass
        self._pending_close.clear()

    # ---- reordering ------------------------------------------------

    def bring_to_front(self, handle: int) -> bool:
        return self._move_to(handle, len(self._order))

    def send_to_back(self, handle: int) -> bool:
        return self._move_to(handle, 0)

    def move(self, handle: int, delta: int) -> bool:
        """Shift ``handle`` by ``delta`` positions; positive moves toward front."""
        if handle not in self._windows:
            return False
        try:
            idx = self._order.index(handle)
        except ValueError:
            return False
        return self._move_to(handle, idx + delta)

    def reorder(self, handle: int, position: int) -> bool:
        """Move ``handle`` to ``position``. 0 = back, -1 = front."""
        if handle not in self._windows:
            return False
        if position < 0:
            position = len(self._order) + position
        return self._move_to(handle, position)

    def _move_to(self, handle: int, position: int) -> bool:
        if handle not in self._windows:
            return False
        try:
            self._order.remove(handle)
        except ValueError:
            return False
        position = max(0, min(len(self._order), position))
        self._order.insert(position, handle)
        return True

    # ---- introspection ---------------------------------------------

    def __contains__(self, handle: int) -> bool:
        return handle in self._windows and handle not in self._pending_close

    def __len__(self) -> int:
        return len(self._windows) - len(self._pending_close)

    @property
    def handles(self) -> list[int]:
        return [h for h in self._order if h not in self._pending_close]


# Default instance + module-level convenience functions.
window_manager = WindowManager()


def add(render: RenderFn) -> int:
    return window_manager.add(render)


def close(handle: int) -> bool:
    return window_manager.close(handle)


def render() -> None:
    window_manager.render()


def bring_to_front(handle: int) -> bool:
    return window_manager.bring_to_front(handle)


def send_to_back(handle: int) -> bool:
    return window_manager.send_to_back(handle)


def move(handle: int, delta: int) -> bool:
    return window_manager.move(handle, delta)


def reorder(handle: int, position: int) -> bool:
    return window_manager.reorder(handle, position)
