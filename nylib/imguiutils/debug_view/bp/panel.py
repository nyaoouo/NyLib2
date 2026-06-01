"""Manage Breakpoints subwindow - table of all BPs in the global registry
with simple per-row actions (Show hits, Uninstall) and a single enable
checkbox column.

Singleton: shown when `state.show_bp_panel` is True; closing the window
resets the flag.
"""
from __future__ import annotations

import typing

from .hit_window import _flag_label
from ..subwindow import Subwindow
from ..widgets import clickable_addr, use_state

if typing.TYPE_CHECKING:
    from ..state import DebugViewState


class BpManagerPanel(Subwindow):
    id = "bp_panel"

    def render(self, state: "DebugViewState") -> bool:
        from nylib.pyimgui import imgui
        from nylib.pyimgui.imgui import ctx as imgui_ctx
        from nylib.winutils.breakpoint import list_breakpoints

        title = f"Manage Breakpoints##dv{state._uid}"
        with use_state(state):
            with imgui_ctx.Begin(title, open=True) as (show, window_open):
                if not window_open:
                    state.show_bp_panel = False
                    return False
                if not show:
                    return True
                flags = (imgui.ImGuiTableFlags_RowBg
                         | imgui.ImGuiTableFlags_BordersInnerV
                         | imgui.ImGuiTableFlags_ScrollY)
                with imgui_ctx.BeginTable(f"##bp_panel_t_{state._uid}", 7,
                                           flags) as show_table:
                    if not show_table:
                        return True
                    for bp in list_breakpoints():
                        self._render_row(state, bp, imgui)
        return True

    def _render_row(self, state: "DebugViewState", bp, imgui) -> None:
        imgui.TableNextRow()
        imgui.TableNextColumn()
        clickable_addr(int(bp.address), id=f"bp_{bp.handle}_addr")
        imgui.TableNextColumn()
        imgui.Text(str(bp.size))
        imgui.TableNextColumn()
        imgui.Text(_flag_label(int(bp.flag)))
        imgui.TableNextColumn()
        imgui.Text(getattr(bp, "_backend_name", "?"))
        imgui.TableNextColumn()
        was_enabled = bool(bp.is_enabled())
        changed, now_enabled = imgui.Checkbox(
            f"##en_{bp.handle}", was_enabled)
        if changed:
            if now_enabled:
                bp.enable()
            else:
                bp.disable()
        imgui.TableNextColumn()
        recorder = state.bp_recorders.get(int(bp.handle))
        imgui.Text(str(recorder.total()) if recorder is not None else "-")
        imgui.TableNextColumn()
        if imgui.SmallButton(f"Show hits##{bp.handle}"):
            state.reopen_bp_hit_window(int(bp.handle))
        imgui.SameLine()
        if imgui.SmallButton(f"Uninstall##{bp.handle}"):
            state.uninstall_bp(int(bp.handle))


__all__ = ["BpManagerPanel"]
