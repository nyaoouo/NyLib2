"""Disassembly sub-view renderer."""
from __future__ import annotations

import traceback
import typing

from ..formats import format_address
from ..widgets import clickable_addr, address_input, current_state

if typing.TYPE_CHECKING:
    from ..state import DebugViewState
    from ..worker import DisasmCache

PIN_W = 32.0  # px; pin gutter column width


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
                     | imgui.ImGuiTableFlags_ScrollY
                     # Resizable + WidthFixed lets the user drag the
                     # addr / bytes column boundary when long
                     # module:export+offset attribution would clip
                     # the default initial width.
                     | imgui.ImGuiTableFlags_Resizable)
            addr_w = _address_column_width(state, imgui)
            # 15-byte x86 instruction max -> 15*3 chars + padding.
            bytes_w = imgui.CalcTextSize("FF " * 15).x + 12.0
            with imgui_ctx.BeginTable(f"##dv{state._uid}_disasm_t", 4, flags) as show_table:
                if show_table:
                    # Explicit per-column widths so the address column
                    # doesn't get equal-stretched to 1/4 of the table
                    # width and clip the formatted address.
                    imgui.TableSetupColumn("pin", imgui.ImGuiTableColumnFlags_WidthFixed, PIN_W)
                    imgui.TableSetupColumn(
                        "addr", imgui.ImGuiTableColumnFlags_WidthFixed, addr_w)
                    imgui.TableSetupColumn(
                        "bytes", imgui.ImGuiTableColumnFlags_WidthFixed, bytes_w)
                    imgui.TableSetupColumn(
                        "insn", imgui.ImGuiTableColumnFlags_WidthStretch)
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


def _address_column_width(state, imgui) -> float:
    """Initial width for the address column. Routed through the
    state's ModuleResolver so MODULE_OFFSET / module:export forms are
    sized realistically; column is also Resizable so the user can
    drag if other visible rows resolve to longer forms."""
    resolver = getattr(state, "_module_resolver", None)
    sample = format_address(state.disasm_cursor or 0x140000000,
                            state.address_fmt, resolver=resolver)
    w = imgui.CalcTextSize(sample).x + 16.0
    from ..formats import AddressFormat
    floor = 240.0 if state.address_fmt is AddressFormat.MODULE_OFFSET else 110.0
    return max(w, floor)


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
            row_addr = int(insn.address)
            label = "[*]" if state.is_pinned(row_addr) else "[ ]"
            if imgui.Selectable(f"{label}##dpin_{i}_{row_addr:X}"):
                state.toggle_pinned(row_addr)
            imgui.TableNextColumn()
            clickable_addr(row_addr, id=f"di{i}")
            imgui.TableNextColumn()
            imgui.Text(" ".join(f"{b:02X}" for b in bytes(insn.bytes)))
            imgui.TableNextColumn()
            # Selectable (not Text) so BeginPopupContextItem can attach -
            # right-click on Text is a no-op because Text isn't an
            # interactive item. The Selectable renders like text by default.
            imgui.Selectable(f"{insn.mnemonic} {insn.op_str}##di{i}_insn",
                             False,
                             flags=imgui.ImGuiSelectableFlags_AllowItemOverlap)
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
                    imgui.Separator()
                    if imgui.MenuItem(f"Create breakpoint here (EXEC)##di{i}_bp"):
                        from ..bp.dialog import BpPrefill
                        state.open_bp_dialog(BpPrefill(
                            address=int(insn.address), size=1,
                            flag=(1 << 0) | (1 << 8),    # EXEC | HARD
                        ))
                    if imgui.MenuItem(f"Edit instruction##di{i}_edit"):
                        state.open_asm_editor(
                            addr=int(insn.address),
                            original_size=int(insn.size),
                            original_text=f"{insn.mnemonic} {insn.op_str}",
                        )


def _render_db_rows(state, cache, imgui) -> None:
    """Sync failed; show raw bytes as `db 0xNN` rows."""
    for off, b in enumerate(cache.data):
        addr = cache.base + off
        imgui.TableNextRow()
        imgui.TableNextColumn()
        label = "[*]" if state.is_pinned(addr) else "[ ]"
        if imgui.Selectable(f"{label}##dpin_{off}_{addr:X}"):
            state.toggle_pinned(addr)
        imgui.TableNextColumn()
        clickable_addr(addr, id=f"dd{off}")
        imgui.TableNextColumn()
        imgui.Text(f"{b:02X}")
        imgui.TableNextColumn()
        imgui.Text(f"db 0x{b:02X}")


def _detect_edge_scroll(state, imgui) -> None:
    # Forward-only extension: when the user scrolls past the bottom of the
    # current decoded window, ask the worker to read more memory forward.
    # Backward extension is intentionally disabled - the view always starts
    # AT the cursor address (set via state.goto_disasm) and only grows down.
    wheel = imgui.GetIO().MouseWheel if hasattr(imgui, "GetIO") else 0.0
    if wheel >= 0.0:
        return
    sy = imgui.GetScrollY()
    sy_max = imgui.GetScrollMaxY()
    if sy >= sy_max - 1.0:
        state._extend_down = True
        state.request_refresh()


__all__ = ["render_disasm_view"]
