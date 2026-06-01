"""Disassembly sub-view renderer."""
from __future__ import annotations

import traceback
import typing

from .formats import format_address
from .widgets import clickable_addr, address_input, current_state

if typing.TYPE_CHECKING:
    from .state import DebugViewState
    from .worker import DisasmCache


def render_disasm_view(state: "DebugViewState",
                        cache: "DisasmCache | None") -> None:
    """Render the disasm pane. Caller must already be inside a parent window."""
    from nylib.pyimgui import imgui
    from nylib.pyimgui.imgui import ctx as imgui_ctx

    with imgui_ctx.BeginChild(f"##dv{state._uid}_disasm",
                               imgui.ImVec2(0, state._splitter_top_h)) as show_child:
        if not show_child:
            return
        try:
            _render_toolbar(state, imgui)
            flags = (imgui.ImGuiTableFlags_RowBg
                     | imgui.ImGuiTableFlags_BordersInnerV
                     | imgui.ImGuiTableFlags_ScrollY)
            with imgui_ctx.BeginTable(f"##dv{state._uid}_disasm_t", 3, flags) as show_table:
                if show_table:
                    if cache is None or (not cache.instructions and not cache.sync_failed):
                        imgui.TableNextRow(); imgui.TableNextColumn()
                        imgui.TextDisabled("(no disassembly yet)")
                    elif cache.sync_failed:
                        _render_db_rows(state, cache, imgui)
                    else:
                        _render_insn_rows(state, cache, imgui, imgui_ctx)
                    _detect_edge_scroll(state, imgui)
            if imgui.IsWindowFocused():
                state.focused_view = "disasm"
        except Exception:
            imgui.TextColored(imgui.ImVec4(1, 0.3, 0.3, 1),
                              "render error in disasm view")
            with imgui_ctx.BeginChild(f"##dv{state._uid}_disasm_err",
                                       imgui.ImVec2(0, 80)):
                imgui.TextWrapped(traceback.format_exc())


def _render_toolbar(state, imgui) -> None:
    if imgui.Button("<"):
        state.back()
    imgui.SameLine()
    if imgui.Button(">"):
        state.forward()
    imgui.SameLine()
    addr = address_input("goto", default=state.disasm_cursor, width=240.0)
    if addr is not None:
        state.goto_disasm(addr)
    imgui.SameLine()
    if imgui.Button("Sync -> hex"):
        state.sync_disasm_to_hex()


def _render_insn_rows(state, cache, imgui, imgui_ctx) -> None:
    clipper = imgui.ImGuiListClipper()
    clipper.Begin(len(cache.instructions))
    while clipper.Step():
        for i in range(clipper.DisplayStart, clipper.DisplayEnd):
            insn = cache.instructions[i]
            imgui.TableNextRow()
            imgui.TableNextColumn()
            clickable_addr(int(insn.address), id=f"di{i}")
            imgui.TableNextColumn()
            imgui.Text(" ".join(f"{b:02X}" for b in bytes(insn.bytes)))
            imgui.TableNextColumn()
            imgui.Text(f"{insn.mnemonic} {insn.op_str}")
            with imgui_ctx.BeginPopupContextItem(f"di{i}_insn_ctx") as show_popup:
                if show_popup:
                    if imgui.MenuItem("Copy address"):
                        imgui.SetClipboardText(format_address(int(insn.address),
                                                               state.address_fmt))
                    if imgui.MenuItem("Copy bytes"):
                        imgui.SetClipboardText(" ".join(f"{b:02X}" for b in bytes(insn.bytes)))
                    if imgui.MenuItem("Copy instruction"):
                        imgui.SetClipboardText(f"{insn.mnemonic} {insn.op_str}")
                    imgui.Separator()
                    if imgui.MenuItem("Show in hex view"):
                        state.goto_hex(int(insn.address))


def _render_db_rows(state, cache, imgui) -> None:
    """Sync failed; show raw bytes as `db 0xNN` rows."""
    for off, b in enumerate(cache.data):
        addr = cache.base + off
        imgui.TableNextRow()
        imgui.TableNextColumn()
        clickable_addr(addr, id=f"dd{off}")
        imgui.TableNextColumn()
        imgui.Text(f"{b:02X}")
        imgui.TableNextColumn()
        imgui.Text(f"db 0x{b:02X}")


def _detect_edge_scroll(state, imgui) -> None:
    wheel = imgui.GetIO().MouseWheel if hasattr(imgui, "GetIO") else 0.0
    if wheel == 0.0:
        return
    sy = imgui.GetScrollY()
    sy_max = imgui.GetScrollMaxY()
    # ImGui wheel: positive = scroll up.
    if wheel > 0 and sy <= 1.0:
        state._extend_up = True
        state.request_refresh()
    elif wheel < 0 and sy >= sy_max - 1.0:
        state._extend_down = True
        state.request_refresh()


__all__ = ["render_disasm_view"]
