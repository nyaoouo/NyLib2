"""BP creation dialog (floating, non-modal, multi-instance).

This module ships:
- `BpPrefill` dataclass for prefill values.
- `validate_bp_form(prefill) -> str | None` pure-Python validation.
- `_parse_tids(text) -> list[int] | None` TID-list parser.
- `BpDialog(Subwindow)` class (rendering body filled in by Task 11).

The validation helpers are kept pure-Python so they're unit-tested
without ImGui. `BpDialog.render` invokes `state.install_bp(...)` on
success and removes itself by returning False.
"""
from __future__ import annotations

import dataclasses
import typing

from ..subwindow import Subwindow

if typing.TYPE_CHECKING:
    from ..state import DebugViewState


# Mirror nylib.winutils.breakpoint.BP_E without importing it (so tests
# don't drag in the ctypes backend init at import time).
_BP_E_EXEC = 1 << 0
_BP_E_WRITE = 1 << 1
_BP_E_READ = 1 << 2
_BP_E_HARD = 1 << 8
_BP_E_SOFT = 1 << 9
_ACCESS_MASK = _BP_E_EXEC | _BP_E_WRITE | _BP_E_READ


@dataclasses.dataclass
class BpPrefill:
    """Initial values for a BpDialog form. Right-click entry points fill
    this with their context; Tools > Create BP uses defaults."""
    address: int = 0
    size: int = 1
    flag: int = _BP_E_EXEC | _BP_E_HARD
    backend: str = "veh"
    stack_frames: int = 32
    tids_text: str = ""


def validate_bp_form(p: BpPrefill) -> str | None:
    """Return None when the form is valid, else a human-readable error."""
    if p.address < 0x1000:
        return "address must be >= 0x1000"
    if p.size <= 0:
        return "size must be > 0"
    access = p.flag & _ACCESS_MASK
    if access == 0:
        return "select one of EXEC / READ / WRITE"
    if (p.flag & _BP_E_EXEC) and p.size != 1:
        return "EXEC requires size=1"
    if (p.flag & _BP_E_HARD) == 0 and (p.flag & _BP_E_SOFT) == 0:
        return "select HARD or SOFT"
    if p.backend not in ("veh", "debugger"):
        return f"unknown backend: {p.backend}"
    if p.stack_frames < 1 or p.stack_frames > 64:
        return "stack frames must be 1..64"
    return None


def _parse_tids(text: str) -> list[int] | None:
    """Parse a comma/space-separated TID list. Empty -> None (all threads)."""
    text = text.strip()
    if not text:
        return None
    parts = [p.strip() for p in text.replace(",", " ").split()]
    out: list[int] = []
    for tok in parts:
        try:
            out.append(int(tok, 0))
        except ValueError:
            return None
    return out or None


class BpDialog(Subwindow):
    """Floating BP creation dialog."""

    def __init__(self, *, prefill: BpPrefill, dialog_id: int) -> None:
        self.id = f"bp_dialog_{dialog_id}"
        self._form = prefill
        self._error: str | None = None
        self._addr_text = f"0x{prefill.address:X}"
        self._size_text = str(prefill.size)
        self._stack_text = str(prefill.stack_frames)

    def render(self, state: "DebugViewState") -> bool:
        from nylib.pyimgui import imgui
        from nylib.pyimgui.imgui import ctx as imgui_ctx
        from ..widgets import use_state

        title = f"Create Breakpoint##{self.id}_{state._uid}"
        flags = imgui.ImGuiWindowFlags_AlwaysAutoResize
        with use_state(state):
            with imgui_ctx.Begin(title, open=True, flags=flags) as (show, window_open):
                if not window_open:
                    return False
                if not show:
                    return True

                # --- Address ---
                changed, self._addr_text = imgui.InputText(
                    f"Address##{self.id}", self._addr_text)
                if changed:
                    try:
                        self._form.address = int(self._addr_text, 0)
                    except ValueError:
                        pass

                # --- Size ---
                changed, self._size_text = imgui.InputText(
                    f"Size##{self.id}", self._size_text)
                if changed:
                    try:
                        self._form.size = int(self._size_text, 0)
                    except ValueError:
                        pass

                # --- Access flag (radio) ---
                imgui.Text("Access:")
                imgui.SameLine()
                for label, bit in (("EXEC", _BP_E_EXEC),
                                   ("WRITE", _BP_E_WRITE),
                                   ("READ", _BP_E_READ)):
                    is_sel = bool(self._form.flag & bit)
                    if imgui.RadioButton(f"{label}##{self.id}", is_sel):
                        self._form.flag = (self._form.flag & ~_ACCESS_MASK) | bit
                        if bit == _BP_E_EXEC:
                            self._form.size = 1
                            self._size_text = "1"
                    imgui.SameLine()
                imgui.NewLine()

                # --- HARD / SOFT (radio) ---
                imgui.Text("Mode:")
                imgui.SameLine()
                is_hard = bool(self._form.flag & _BP_E_HARD)
                if imgui.RadioButton(f"HARD##{self.id}", is_hard):
                    self._form.flag = (self._form.flag & ~(_BP_E_HARD | _BP_E_SOFT)) | _BP_E_HARD
                imgui.SameLine()
                if imgui.RadioButton(f"SOFT##{self.id}",
                                      not is_hard and bool(self._form.flag & _BP_E_SOFT)):
                    self._form.flag = (self._form.flag & ~(_BP_E_HARD | _BP_E_SOFT)) | _BP_E_SOFT

                # --- Backend (radio) ---
                imgui.Text("Backend:")
                imgui.SameLine()
                for name in ("veh", "debugger"):
                    if imgui.RadioButton(f"{name}##{self.id}",
                                          self._form.backend == name):
                        self._form.backend = name
                    imgui.SameLine()
                imgui.NewLine()

                # --- Stack frames ---
                changed, n = imgui.SliderInt(
                    f"stack frames##{self.id}", int(self._form.stack_frames),
                    1, 64)
                if changed:
                    self._form.stack_frames = int(n)
                    self._stack_text = str(n)

                # --- TID filter ---
                changed, self._form.tids_text = imgui.InputText(
                    f"TIDs (blank=all)##{self.id}", self._form.tids_text)

                # --- Error inline ---
                if self._error:
                    imgui.TextColored(imgui.ImVec4(1, 0.3, 0.3, 1), self._error)

                # --- Buttons ---
                if imgui.Button(f"Install##{self.id}"):
                    err = validate_bp_form(self._form)
                    if err is not None:
                        self._error = err
                    else:
                        try:
                            state.install_bp(
                                address=self._form.address,
                                size=self._form.size,
                                flag=self._form.flag,
                                backend=self._form.backend,
                                stack_frames=self._form.stack_frames,
                                tids=_parse_tids(self._form.tids_text),
                            )
                            return False    # success -> close dialog
                        except Exception as exc:
                            self._error = repr(exc)
                imgui.SameLine()
                if imgui.Button(f"Cancel##{self.id}"):
                    return False
        return True


__all__ = [
    "BpPrefill", "validate_bp_form", "_parse_tids", "BpDialog",
]
