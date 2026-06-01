"""Module List subwindow - registered with nylib.imguiutils.window_manager."""
from __future__ import annotations

import dataclasses
import threading
import time
import typing

from .widgets import clickable_addr

if typing.TYPE_CHECKING:
    from .state import DebugViewState


@dataclasses.dataclass(frozen=True)
class _Module:
    name: str
    base: int
    size: int


_cache_lock = threading.Lock()
_cache_ts = 0.0
_cache: list[_Module] = []


def _cached_modules(ttl: float = 1.0) -> list[_Module]:
    global _cache_ts, _cache
    now = time.monotonic()
    with _cache_lock:
        if _cache and (now - _cache_ts) < ttl:
            return list(_cache)
    from nylib.process import Process
    proc = Process.current
    out: list[_Module] = []
    try:
        for entry in proc.enum_ldr_data():
            try:
                name = entry.BaseDllName.remote_value(proc)
            except Exception:
                name = "?"
            out.append(_Module(name=name,
                               base=int(entry.DllBase or 0),
                               size=int(entry.SizeOfImage or 0)))
    except Exception:
        pass
    with _cache_lock:
        _cache = out
        _cache_ts = now
    return out


def render_module_panel_fn(state: "DebugViewState"):
    """Build a window_manager render-fn for this state's module panel.

    Returns a callable suitable for `window_manager.add(...)`. The callable
    returns True to keep rendering, False to remove itself when the user closes
    the window."""
    def _fn() -> bool:
        from nylib.pyimgui import imgui
        from nylib.pyimgui.imgui import ctx as imgui_ctx
        from .widgets import use_state

        with use_state(state):
            with imgui_ctx.Begin(f"Modules##dv{state._uid}", open=True) as (show, window_open):
                if not window_open:
                    state.show_module_panel = False
                    return False
                if not show:
                    return True
                flags = (imgui.ImGuiTableFlags_RowBg
                         | imgui.ImGuiTableFlags_BordersInnerV
                         | imgui.ImGuiTableFlags_ScrollY)
                with imgui_ctx.BeginTable(f"##dv{state._uid}_modtable", 3, flags) as show_table:
                    if not show_table:
                        return True
                    for m in _cached_modules():
                        imgui.TableNextRow()
                        imgui.TableNextColumn()
                        imgui.Text(m.name)
                        imgui.TableNextColumn()
                        clickable_addr(m.base, id=f"mod_{m.name}")
                        imgui.TableNextColumn()
                        imgui.Text(f"0x{m.size:X}")
        return True
    return _fn


__all__ = ["render_module_panel_fn", "_cached_modules"]
