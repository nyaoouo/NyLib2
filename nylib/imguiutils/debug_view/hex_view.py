"""Hex sub-view renderer."""
from __future__ import annotations

import traceback
import typing

from .formats import AddressFormat, MemFormat, MemCellSize, format_address, format_cell, snap_pow2_in
from .widgets import clickable_addr, address_input, current_state

if typing.TYPE_CHECKING:
    from .state import DebugViewState
    from .worker import HexCache


def render_hex_view(state: "DebugViewState",
                     cache: "HexCache | None") -> None:
    from nylib.pyimgui import imgui
    from nylib.pyimgui.imgui import ctx as imgui_ctx

    with imgui_ctx.BeginChild(f"##dv{state._uid}_hex",
                               imgui.ImVec2(0, 0)) as show_child:
        if not show_child:
            return
        try:
            _render_toolbar(state, imgui)
            cell_bytes = int(state.mem_fmt.cell)
            cell_text_w = imgui.CalcTextSize(_max_cell_width(state.mem_fmt)).x + 8
            addr_w = imgui.CalcTextSize("0" * 18).x + 16
            avail_w = max(0.0, imgui.GetContentRegionAvail().x - addr_w)
            raw_n = max(1, int(avail_w // cell_text_w) * cell_bytes)
            bpr = snap_pow2_in({8, 16, 32, 64}, raw_n)
            cols = 1 + bpr // cell_bytes

            flags = imgui.ImGuiTableFlags_RowBg | imgui.ImGuiTableFlags_ScrollY
            with imgui_ctx.BeginTable(f"##dv{state._uid}_hex_t", cols, flags) as show_table:
                if show_table:
                    if cache is None:
                        imgui.TableNextRow(); imgui.TableNextColumn()
                        imgui.TextDisabled("(no hex data yet)")
                    else:
                        _render_rows(state, cache, bpr, cell_bytes, imgui, imgui_ctx)
                    _detect_edge_scroll(state, imgui)
            if imgui.IsWindowFocused():
                state.focused_view = "hex"
        except Exception:
            imgui.TextColored(imgui.ImVec4(1, 0.3, 0.3, 1),
                              "render error in hex view")
            with imgui_ctx.BeginChild(f"##dv{state._uid}_hex_err",
                                       imgui.ImVec2(0, 80)):
                imgui.TextWrapped(traceback.format_exc())


def _max_cell_width(mf: MemFormat) -> str:
    return "F" * mf.cell_text_width() + " "


def _render_toolbar(state, imgui) -> None:
    addr = address_input("goto", default=state.hex_cursor, width=240.0)
    if addr is not None:
        state.goto_hex(addr)
    imgui.SameLine()
    if imgui.Button("Sync -> disasm"):
        state.sync_hex_to_disasm()
    imgui.SameLine()
    cur_cell = int(state.mem_fmt.cell)
    for cell in MemCellSize:
        is_sel = cur_cell == int(cell)
        if imgui.SmallButton(f"U{cell * 8}"):
            state.mem_fmt = MemFormat(cell, state.mem_fmt.radix)
        if is_sel:
            imgui.SameLine(); imgui.TextDisabled("*"); imgui.SameLine()
        imgui.SameLine()
    if imgui.SmallButton("hex/dec"):
        state.mem_fmt = MemFormat(state.mem_fmt.cell,
                                   "dec" if state.mem_fmt.radix == "hex" else "hex")


def _render_rows(state, cache, bpr, cell_bytes, imgui, imgui_ctx) -> None:
    total_bytes = cache.pre_bytes + cache.post_bytes
    total_rows = -(-total_bytes // bpr)
    clipper = imgui.ImGuiListClipper()
    clipper.Begin(total_rows)
    while clipper.Step():
        for row in range(clipper.DisplayStart, clipper.DisplayEnd):
            row_addr = cache.base + row * bpr
            imgui.TableNextRow()
            imgui.TableNextColumn()
            clickable_addr(row_addr, id=f"hr{row}")
            for c in range(bpr // cell_bytes):
                imgui.TableNextColumn()
                byte_off = row * bpr + c * cell_bytes
                if byte_off + cell_bytes > len(cache.data):
                    imgui.TextDisabled("..")
                    continue
                if _any_failed(cache.read_failed, byte_off, cell_bytes):
                    with imgui_ctx.PushStyleColor(imgui.ImGuiCol_Text,
                                                   imgui.ImVec4(0.5, 0.5, 0.5, 1)):
                        imgui.Text("?" * (cell_bytes * 2))
                    continue
                value = int.from_bytes(cache.data[byte_off:byte_off + cell_bytes],
                                        "little")
                label = format_cell(value, state.mem_fmt)
                imgui.Selectable(f"{label}##hc{row}_{c}", False,
                                 flags=imgui.ImGuiSelectableFlags_AllowItemOverlap)
                with imgui_ctx.BeginPopupContextItem(f"hc{row}_{c}_ctx") as show_popup:
                    if show_popup:
                        if imgui.MenuItem("Copy address"):
                            imgui.SetClipboardText(format_address(cache.base + byte_off,
                                                                   state.address_fmt))
                        if imgui.MenuItem("Copy value"):
                            imgui.SetClipboardText(label)
                        imgui.Separator()
                        if imgui.MenuItem("Show in disasm view"):
                            tgt = value if cell_bytes == 8 else (cache.base + byte_off)
                            state.goto_disasm(tgt)


def _any_failed(failed: bytes, off: int, span: int) -> bool:
    for i in range(off, off + span):
        if i >= len(failed):
            return True
        if failed[i]:
            return True
    return False


def _detect_edge_scroll(state, imgui) -> None:
    wheel = imgui.GetIO().MouseWheel if hasattr(imgui, "GetIO") else 0.0
    if wheel == 0.0:
        return
    sy = imgui.GetScrollY()
    sy_max = imgui.GetScrollMaxY()
    if wheel > 0 and sy <= 1.0:
        state._extend_up = True
        state.request_refresh()
    elif wheel < 0 and sy >= sy_max - 1.0:
        state._extend_down = True
        state.request_refresh()


__all__ = ["render_hex_view"]
