"""Hex sub-view renderer."""
from __future__ import annotations

import traceback
import typing

from ..formats import AddressFormat, MemFormat, MemCellSize, format_address, format_cell, snap_pow2_in
from ..widgets import clickable_addr, address_input, current_state

if typing.TYPE_CHECKING:
    from ..state import DebugViewState
    from ..worker import HexCache

PIN_W = 32.0  # px; pin gutter column width


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
            # Address column width: fit the current cursor's formatted text
            # so the column never clips. Was previously a bogus "0"*18
            # CalcTextSize that competed with WidthStretch defaults and
            # produced visible truncation of the address.
            addr_w = _address_column_width(state, imgui)
            avail_w = max(0.0, imgui.GetContentRegionAvail().x - addr_w - PIN_W)
            raw_n = max(1, int(avail_w // cell_text_w) * cell_bytes)
            bpr = snap_pow2_in({8, 16, 32, 64}, raw_n)
            cols = 1 + bpr // cell_bytes

            # NOTE: do not add ImGuiTableFlags_Resizable here. The
            # hex view's "auto fit" picks the bytes-per-row count
            # from GetContentRegionAvail() at frame start; Resizable
            # adds drag gutters between every one of the 16+ cell
            # columns which throws that calculation off and clutters
            # the row layout with drag-handles. If the user needs a
            # wider addr column for long module:export forms, the
            # disasm view (synced to hex) IS Resizable.
            flags = (imgui.ImGuiTableFlags_RowBg
                     | imgui.ImGuiTableFlags_ScrollY)
            with imgui_ctx.BeginTable(f"##dv{state._uid}_hex_t", cols + 1, flags) as show_table:
                if show_table:
                    # Explicit per-column setup so the address column
                    # fits its content instead of getting equal-stretched
                    # to 1/(N+1) of the table width (default sizing for
                    # ScrollY-only tables).
                    imgui.TableSetupColumn("pin", imgui.ImGuiTableColumnFlags_WidthFixed, PIN_W)
                    imgui.TableSetupColumn(
                        "addr", imgui.ImGuiTableColumnFlags_WidthFixed, addr_w)
                    for c in range(cols - 1):
                        imgui.TableSetupColumn(
                            f"c{c}", imgui.ImGuiTableColumnFlags_WidthFixed,
                            cell_text_w)
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


def _address_column_width(state, imgui) -> float:
    """Initial width for the address column.

    Measured from the current cursor's formatted text (routed through
    the state's ModuleResolver so MODULE_OFFSET / module:export forms
    are sized realistically). The column is also Resizable so the user
    can drag the boundary when other visible rows resolve to even
    longer forms. A floor protects against degenerate cursors."""
    resolver = getattr(state, "_module_resolver", None)
    sample = format_address(state.hex_cursor or 0x140000000,
                            state.address_fmt, resolver=resolver)
    w = imgui.CalcTextSize(sample).x + 16.0
    # Bigger floor when MODULE_OFFSET is active: even short-form
    # cursors will likely sit next to long-form rows once the user
    # scrolls into a code region.
    from ..formats import AddressFormat
    floor = 240.0 if state.address_fmt is AddressFormat.MODULE_OFFSET else 110.0
    return max(w, floor)


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
            label = "[*]" if state.is_pinned(row_addr) else "[ ]"
            if imgui.Selectable(f"{label}##hpin_{row}_{row_addr:X}"):
                state.toggle_pinned(row_addr)
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
                if imgui.IsItemHovered() and imgui.IsMouseDoubleClicked(0):
                    state.open_hex_editor(
                        addr=cache.base + byte_off,
                        current=bytes(cache.data[byte_off:byte_off + cell_bytes]),
                        cell_bytes=cell_bytes,
                    )
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
                        imgui.Separator()
                        if imgui.MenuItem(f"Create breakpoint here (READ)##hc{row}_{c}_bpr"):
                            from ..bp.dialog import BpPrefill
                            state.open_bp_dialog(BpPrefill(
                                address=cache.base + byte_off,
                                size=cell_bytes,
                                flag=(1 << 2) | (1 << 8),    # READ | HARD
                            ))
                        if imgui.MenuItem(f"Create breakpoint here (WRITE)##hc{row}_{c}_bpw"):
                            from ..bp.dialog import BpPrefill
                            state.open_bp_dialog(BpPrefill(
                                address=cache.base + byte_off,
                                size=cell_bytes,
                                flag=(1 << 1) | (1 << 8),    # WRITE | HARD
                            ))
                        if imgui.MenuItem(f"Edit value##hc{row}_{c}_edit"):
                            state.open_hex_editor(
                                addr=cache.base + byte_off,
                                current=bytes(cache.data[byte_off:byte_off + cell_bytes]),
                                cell_bytes=cell_bytes,
                            )


def _any_failed(failed: bytes, off: int, span: int) -> bool:
    for i in range(off, off + span):
        if i >= len(failed):
            return True
        if failed[i]:
            return True
    return False


def _detect_edge_scroll(state, imgui) -> None:
    # Forward-only extension: when the user scrolls past the bottom of the
    # current decoded window, ask the worker to read more memory forward.
    # Backward extension is intentionally disabled - the view always starts
    # AT the cursor address (set via state.goto_hex) and only grows down.
    wheel = imgui.GetIO().MouseWheel if hasattr(imgui, "GetIO") else 0.0
    if wheel >= 0.0:
        return
    sy = imgui.GetScrollY()
    sy_max = imgui.GetScrollMaxY()
    if sy >= sy_max - 1.0:
        state._extend_down = True
        state.request_refresh()


__all__ = ["render_hex_view"]
