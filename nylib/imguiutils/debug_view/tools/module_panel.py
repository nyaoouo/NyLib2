"""Module List subwindow with expandable per-module export sub-trees.

Each module renders as a CollapsingHeader; expanding it shows the
module's base address (clickable), a filter input, and a virtualized
table of all exported symbols read directly from the in-memory PE
export table (see `nylib.winutils.pe_exports.read_exports`).

Exports are cached per module base process-wide (they don't change for
a loaded module).
"""
from __future__ import annotations

import dataclasses
import threading
import time
import typing

from ..subwindow import Subwindow
from ..widgets import clickable_addr, use_state
from nylib.winutils.pe_exports import Export, read_exports

if typing.TYPE_CHECKING:
    from ..state import DebugViewState


@dataclasses.dataclass(frozen=True)
class _Module:
    name: str
    base: int
    size: int


_cache_lock = threading.Lock()
_cache_ts = 0.0
_cache: list[_Module] = []

_exports_lock = threading.Lock()
_exports_cache: dict[int, list[Export]] = {}


def _cached_modules(ttl: float = 1.0) -> list[_Module]:
    """Enumerate LDR data with a `ttl`-second TTL cache (process-wide)."""
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


def _cached_exports(base: int) -> list[Export]:
    """Return the export list for `base`, parsing on first call."""
    with _exports_lock:
        cached = _exports_cache.get(base)
        if cached is not None:
            return cached
    exports = read_exports(base)
    with _exports_lock:
        _exports_cache[base] = exports
    return exports


class ModulePanel(Subwindow):
    """Singleton 'Modules' subwindow with collapsible export trees."""
    id = "module"

    def __init__(self) -> None:
        # Per-module search text, keyed by module base.
        self._search: dict[int, str] = {}

    def render(self, state: "DebugViewState") -> bool:
        from nylib.pyimgui import imgui
        from nylib.pyimgui.imgui import ctx as imgui_ctx

        with use_state(state):
            with imgui_ctx.Begin(f"Modules##dv{state._uid}",
                                  open=True) as (show, window_open):
                if not window_open:
                    state.show_module_panel = False
                    return False
                if not show:
                    return True
                for m in _cached_modules():
                    self._render_module(state, m, imgui, imgui_ctx)
        return True

    def _render_module(self, state, m: _Module, imgui, imgui_ctx) -> None:
        header_label = (f"{m.name}    base=0x{m.base:X}    "
                        f"size=0x{m.size:X}##mod_{m.base:X}")
        if not imgui.CollapsingHeader(header_label):
            return
        # Indent the body so it visually nests under the header.
        with imgui_ctx.PushID(f"mod_body_{m.base:X}"):
            imgui.Indent(16.0)
            try:
                self._render_body(state, m, imgui, imgui_ctx)
            finally:
                imgui.Unindent(16.0)

    def _render_body(self, state, m: _Module, imgui, imgui_ctx) -> None:
        # Clickable base for copy / right-click "Go to disasm/hex".
        imgui.Text("Base:")
        imgui.SameLine()
        clickable_addr(m.base, id=f"mod_{m.base:X}_base")
        # Search input.
        cur_search = self._search.get(m.base, "")
        _changed, new_search = imgui.InputText(
            f"filter##search_{m.base:X}", cur_search)
        if new_search != cur_search:
            self._search[m.base] = new_search

        exports = _cached_exports(m.base)
        if not exports:
            imgui.TextDisabled("(no exports)")
            return

        # Apply filter.
        filt = new_search.strip().lower()
        if filt:
            shown = [e for e in exports
                     if filt in (e.name or "").lower()
                        or filt in f"#{e.ordinal}"]
        else:
            shown = exports

        flags = (imgui.ImGuiTableFlags_RowBg
                 | imgui.ImGuiTableFlags_BordersInnerV
                 | imgui.ImGuiTableFlags_ScrollY)
        # Height: ~16 rows max, min 3 rows, with header overhead.
        height = min(280.0,
                     max(60.0, float(min(len(shown), 14)) * 22.0 + 40.0))
        with imgui_ctx.BeginTable(f"##exports_{m.base:X}", 3, flags,
                                   outer_size=imgui.ImVec2(0.0, height)) as show_table:
            if not show_table:
                return
            imgui.TableSetupColumn("Name")
            imgui.TableSetupColumn("RVA")
            imgui.TableSetupColumn("Address")
            imgui.TableHeadersRow()
            clipper = imgui.ImGuiListClipper()
            clipper.Begin(len(shown))
            while clipper.Step():
                for i in range(clipper.DisplayStart, clipper.DisplayEnd):
                    exp = shown[i]
                    imgui.TableNextRow()
                    imgui.TableNextColumn()
                    imgui.Text(exp.name or f"#{exp.ordinal}")
                    imgui.TableNextColumn()
                    imgui.Text(f"+0x{exp.rva:X}")
                    imgui.TableNextColumn()
                    if exp.forwarder:
                        imgui.TextDisabled(f"=> {exp.forwarder}")
                    else:
                        clickable_addr(
                            exp.address,
                            id=f"exp_{m.base:X}_{exp.ordinal}",
                        )


__all__ = ["ModulePanel", "_cached_modules", "_cached_exports"]
