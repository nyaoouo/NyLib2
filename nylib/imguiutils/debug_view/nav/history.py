"""History panel: visual list of past goto entries, click to jump."""
from __future__ import annotations

import typing

from ..subwindow import Subwindow
from ..widgets import clickable_addr, use_state

if typing.TYPE_CHECKING:
    from ..state import DebugViewState


class HistoryPanel(Subwindow):
    """Singleton 'Address History' subwindow. Reads `state.history`
    and `state.history_idx`. Row click jumps to that entry without
    truncating the forward stack (browser-style)."""
    id = "history_panel"

    def render(self, state: "DebugViewState") -> bool:
        from nylib.pyimgui import imgui
        from nylib.pyimgui.imgui import ctx as imgui_ctx

        title = f"Address History##dv{state._uid}_hist"
        with use_state(state):
            with imgui_ctx.Begin(title, open=True) as (show, window_open):
                if not window_open:
                    state.show_history_panel = False
                    return False
                if not show:
                    return True
                if imgui.Button("Clear##hist_clear"):
                    state.history.clear()
                    state.history_idx = -1
                flags = (imgui.ImGuiTableFlags_RowBg
                         | imgui.ImGuiTableFlags_BordersInnerV
                         | imgui.ImGuiTableFlags_ScrollY)
                with imgui_ctx.BeginTable(
                    f"##dv{state._uid}_histtable", 3, flags
                ) as show_table:
                    if not show_table:
                        return True
                    imgui.TableSetupColumn(
                        ">", imgui.ImGuiTableColumnFlags_WidthFixed, 20.0)
                    imgui.TableSetupColumn(
                        "where", imgui.ImGuiTableColumnFlags_WidthFixed, 60.0)
                    imgui.TableSetupColumn(
                        "address", imgui.ImGuiTableColumnFlags_WidthStretch)
                    entries = list(state.history)
                    for i, (where, addr) in enumerate(entries):
                        imgui.TableNextRow()
                        imgui.TableNextColumn()
                        imgui.Text(">" if i == state.history_idx else " ")
                        imgui.TableNextColumn()
                        imgui.Text(where)
                        imgui.TableNextColumn()
                        if imgui.Selectable(
                            f"0x{addr:X}##hist_row_{i}",
                            i == state.history_idx,
                        ):
                            if where == "disasm":
                                state.goto_disasm(addr, record=False)
                            else:
                                state.goto_hex(addr, record=False)
                            state.history_idx = i
        return True


__all__ = ["HistoryPanel"]
