"""Shared ImGui widget helpers for the debug view.

ImGui is imported lazily inside the rendering functions so the
pure-Python test suite can import this module without needing the
native pyimgui .pyd.
"""
from __future__ import annotations

import contextlib
import contextvars
import typing

from .formats import AddressFormat, MemFormat, MemCellSize, format_address, parse_address

if typing.TYPE_CHECKING:
    from .state import DebugViewState

_current_state: contextvars.ContextVar = contextvars.ContextVar("dv_current_state")


def current_state() -> "DebugViewState":
    """Return the DebugViewState pushed by the innermost `use_state` block."""
    return _current_state.get()


@contextlib.contextmanager
def use_state(state: "DebugViewState"):
    token = _current_state.set(state)
    try:
        yield state
    finally:
        _current_state.reset(token)


# ----- ImGui widgets (lazy imports) -----


def _check(selected: bool) -> str:
    """Three-char prefix for menu items: `[*]` when selected, `[ ]` blank.

    Uses ASCII brackets + asterisk so the default ImGui font atlas
    always has the glyphs. Prior `✔` (U+2714) lived outside the default
    range and rendered as the missing-glyph `?` placeholder."""
    return "[*] " if selected else "[ ] "


def clickable_addr(addr: int, *, id: str | None = None) -> None:
    """Render `addr` as a clickable label. Left-click = copy; right-click = ctx menu."""
    from nylib.pyimgui import imgui
    from nylib.pyimgui.imgui import ctx as imgui_ctx

    state = current_state()
    # Route through state's ModuleResolver so MODULE_OFFSET lookups hit
    # the cached snapshot instead of a fresh LDR walk per call.
    label = format_address(addr, state.address_fmt,
                            resolver=getattr(state, "_module_resolver", None))
    sel_id = f"{label}##{id or addr}"
    if imgui.Selectable(sel_id, False,
                        flags=imgui.ImGuiSelectableFlags_AllowItemOverlap):
        imgui.SetClipboardText(label)
        state._copy_log.append(label)
    with imgui_ctx.BeginPopupContextItem(f"{id or addr}_ctx") as show_popup:
        if not show_popup:
            return
        if imgui.MenuItem("Copy address (hex)"):
            imgui.SetClipboardText(f"0x{addr & 0xFFFFFFFFFFFFFFFF:016X}")
        if imgui.MenuItem("Copy as module+offset"):
            imgui.SetClipboardText(format_address(addr, AddressFormat.MODULE_OFFSET))
        imgui.Separator()
        if imgui.MenuItem("Go to in disasm view"):
            state.goto_disasm(addr)
        if imgui.MenuItem("Go to in hex view"):
            state.goto_hex(addr)


def address_input(label: str, *, default: int, width: float = 220.0) -> int | None:
    """Text input that parses hex / module+offset. Returns the address on
    Enter, or None when the input is unchanged or unparseable."""
    from nylib.pyimgui import imgui
    from nylib.pyimgui.imgui import ctx as imgui_ctx

    state = current_state()
    key = f"##addr_in_{label}_{state._uid}"
    text_default = f"0x{default & 0xFFFFFFFFFFFFFFFF:X}"
    with imgui_ctx.PushItemWidth(width):
        changed, text = imgui.InputText(label + key, text_default,
                                         imgui.ImGuiInputTextFlags_EnterReturnsTrue)
    if not changed:
        return None
    return parse_address(text,
                         resolver=getattr(state, "_module_resolver", None))


def render_address_format_submenu(state) -> None:
    from nylib.pyimgui import imgui

    for fmt in AddressFormat:
        if imgui.MenuItem(f"{_check(state.address_fmt is fmt)}{fmt.value}"):
            state.address_fmt = fmt


def render_memory_format_submenu(state) -> None:
    from nylib.pyimgui import imgui

    for cell in MemCellSize:
        for radix in ("hex", "dec"):
            mf = MemFormat(cell, radix)
            label = f"U{cell * 8}-{radix}"
            if imgui.MenuItem(f"{_check(state.mem_fmt == mf)}{label}"):
                state.mem_fmt = mf


def render_update_interval_submenu(state) -> None:
    from nylib.pyimgui import imgui

    for ms in (50, 100, 200, 500, 1000):
        label = f"{ms} ms"
        if imgui.MenuItem(f"{_check(state.update_interval_ms == ms)}{label}"):
            state.set_update_interval(ms)


__all__ = [
    "use_state", "current_state",
    "clickable_addr", "address_input",
    "render_address_format_submenu",
    "render_memory_format_submenu",
    "render_update_interval_submenu",
    "_check",
]
