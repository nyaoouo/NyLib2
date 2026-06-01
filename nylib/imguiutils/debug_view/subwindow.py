"""State-owned ImGui subwindow protocol.

Each DebugView subwindow (Module panel, BP hit window, BP dialog, BP
manager panel, hex/asm edit dialog) subclasses `Subwindow` and lives in
`DebugViewState._subwindows`. `render_debug_view` iterates the list each
frame and drops any subwindow whose `render(state)` returns False.

This replaces v0's `nylib.imguiutils.window_manager` integration for
DebugView-owned subwindows. The global window_manager continues to host
truly-global helpers (`MessageBox`, `FileDialog`).
"""
from __future__ import annotations

import abc
import typing

if typing.TYPE_CHECKING:
    from .state import DebugViewState


class Subwindow(abc.ABC):
    """A state-owned ImGui subwindow.

    Each instance has a stable `id` used in window title hashes
    (`##dvN_<id>`) and in `_subwindows` lookups. Returning False from
    `render(state)` removes the subwindow from `state._subwindows` on
    the next frame.
    """
    id: str

    @abc.abstractmethod
    def render(self, state: "DebugViewState") -> bool:
        """Render this subwindow. Return True to keep, False to remove."""
        raise NotImplementedError

    def on_close(self, state: "DebugViewState") -> None:
        """Optional hook called when the subwindow is removed during
        `state.close()`. Default: no-op."""
        return None


def remove_subwindow(state: "DebugViewState", sw_id: str) -> bool:
    """Remove the first subwindow whose `id` matches `sw_id`.

    Returns True if a removal occurred, False if no match was found.
    Idempotent: safe to call when the subwindow has already been removed.
    """
    for i, sw in enumerate(state._subwindows):
        if sw.id == sw_id:
            del state._subwindows[i]
            return True
    return False


def find_subwindow(state: "DebugViewState",
                    sw_id: str) -> typing.Optional["Subwindow"]:
    """Return the first subwindow with matching `id`, or None."""
    for sw in state._subwindows:
        if sw.id == sw_id:
            return sw
    return None


__all__ = ["Subwindow", "remove_subwindow", "find_subwindow"]
