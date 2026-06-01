"""Pinned-address support: PinnedEntry dataclass + PinnedAddressesPanel
subwindow. State fields and mutator methods live in state.py.
"""
from __future__ import annotations

import dataclasses
import typing

from ..subwindow import Subwindow
from ..widgets import clickable_addr, use_state

if typing.TYPE_CHECKING:
    from ..state import DebugViewState


@dataclasses.dataclass
class PinnedEntry:
    """Single pinned address with optional user label."""
    addr: int
    label: typing.Optional[str] = None


class PinnedAddressesPanel(Subwindow):
    """Singleton 'Pinned Addresses' subwindow.

    Closed via the window X button: sets `state.show_pinned_panel = False`
    and returns False so the subwindow is dropped from `_subwindows`.
    """
    id = "pinned_panel"

    def __init__(self) -> None:
        self._edit_label_idx: int | None = None
        self._edit_label_buf: str = ""
        self._confirm_clear_open: bool = False

    def render(self, state: "DebugViewState") -> bool:
        from nylib.pyimgui import imgui
        from nylib.pyimgui.imgui import ctx as imgui_ctx

        title = f"Pinned Addresses##dv{state._uid}_pinned"
        with use_state(state):
            with imgui_ctx.Begin(title, open=True) as (show, window_open):
                if not window_open:
                    state.show_pinned_panel = False
                    return False
                if not show:
                    return True
                # Toolbar.
                if imgui.Button("Add current cursor##pin_add_cur"):
                    cur = state.disasm_cursor if state.focused_view != "hex" \
                                              else state.hex_cursor
                    state.pin_address(cur)
                imgui.SameLine()
                if imgui.Button("Clear all##pin_clear"):
                    self._confirm_clear_open = True
                if self._confirm_clear_open:
                    from nylib.imguiutils.message_box import MessageBox
                    result = MessageBox.show(
                        "Clear all pinned addresses?",
                        title="Confirm",
                        buttons=("Yes", "No"),
                    )
                    if result == "Yes":
                        # Drain pinned list via the mutator.
                        for entry in list(state.pinned_addresses):
                            state.unpin_address(entry.addr)
                        self._confirm_clear_open = False
                    elif result == "No":
                        self._confirm_clear_open = False
                # Table.
                flags = (imgui.ImGuiTableFlags_RowBg
                         | imgui.ImGuiTableFlags_BordersInnerV
                         | imgui.ImGuiTableFlags_ScrollY)
                with imgui_ctx.BeginTable(
                    f"##dv{state._uid}_pintable", 4, flags
                ) as show_table:
                    if not show_table:
                        return True
                    imgui.TableSetupColumn(
                        "pin", imgui.ImGuiTableColumnFlags_WidthFixed, 32.0)
                    imgui.TableSetupColumn(
                        "label", imgui.ImGuiTableColumnFlags_WidthStretch)
                    imgui.TableSetupColumn(
                        "address", imgui.ImGuiTableColumnFlags_WidthFixed, 180.0)
                    imgui.TableSetupColumn(
                        "x", imgui.ImGuiTableColumnFlags_WidthFixed, 24.0)
                    to_remove: list[int] = []
                    for i, entry in enumerate(list(state.pinned_addresses)):
                        imgui.TableNextRow()
                        imgui.TableNextColumn()
                        if imgui.Selectable(f"[*]##pin_sel_{i}"):
                            to_remove.append(entry.addr)
                        imgui.TableNextColumn()
                        label = entry.label or ""
                        if self._edit_label_idx == i:
                            changed, self._edit_label_buf = imgui.InputText(
                                f"##pin_lbl_edit_{i}",
                                self._edit_label_buf, 128,
                                imgui.ImGuiInputTextFlags_EnterReturnsTrue,
                            )
                            if changed:
                                state.pin_address(
                                    entry.addr,
                                    label=self._edit_label_buf or None,
                                )
                                self._edit_label_idx = None
                        else:
                            if imgui.Selectable(
                                f"{label or '(no label)'}##pin_lbl_{i}"
                            ):
                                self._edit_label_idx = i
                                self._edit_label_buf = label
                        imgui.TableNextColumn()
                        clickable_addr(entry.addr,
                                       id=f"pin_addr_{i}_{entry.addr:X}")
                        imgui.TableNextColumn()
                        if imgui.SmallButton(f"X##pin_rm_{i}"):
                            to_remove.append(entry.addr)
                    for addr in to_remove:
                        state.unpin_address(addr)
        return True


__all__ = ["PinnedEntry", "PinnedAddressesPanel"]
