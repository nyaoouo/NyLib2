"""Hex inline edit - safe-write helper + HexEditDialog subwindow.

The commit helper (`commit_hex_edit`) is pure-Python and unit-tested.
The HexEditDialog Subwindow renders the inline form; its body is
filled in by Task 12.
"""
from __future__ import annotations

import dataclasses
import typing

from ..subwindow import Subwindow

if typing.TYPE_CHECKING:
    from ..state import DebugViewState
    from ..formats import MemFormat


# PAGE_EXECUTE = 0x10, EXECUTE_READ = 0x20, EXECUTE_READWRITE = 0x40,
# EXECUTE_WRITECOPY = 0x80. The low nibble of the high byte (0xF0)
# captures all four.
_PAGE_EXECUTE_MASK = 0xF0


@dataclasses.dataclass(frozen=True)
class HexEditResult:
    """Outcome of a `commit_hex_edit` call."""
    ok: bool
    need_confirm: bool = False
    confirm_message: str = ""
    error: str | None = None


def is_page_executable(addr: int) -> bool:
    """Return True iff the page containing `addr` has any PAGE_EXECUTE* protection."""
    from nylib.process import Process
    mbi = Process.current.virtual_query(addr)
    return bool(int(mbi.Protect) & _PAGE_EXECUTE_MASK)


def commit_hex_edit(addr: int, data: bytes, *,
                    allow_executable: bool = False) -> HexEditResult:
    """Write `data` to `addr`. Guards executable pages.

    If the target page is executable AND `allow_executable` is False,
    returns `need_confirm=True` (caller pops a MessageBox; Yes re-calls
    with allow_executable=True). Otherwise attempts the write and
    returns ok=True on success, ok=False with `error` on failure.
    Never raises.
    """
    from nylib.process import Process
    try:
        executable = is_page_executable(addr)
    except Exception as exc:
        return HexEditResult(ok=False, error=f"virtual_query failed: {exc!r}")
    if executable and not allow_executable:
        return HexEditResult(
            ok=False, need_confirm=True,
            confirm_message=f"Write to executable page at 0x{addr:X}?",
        )
    try:
        Process.current.write(addr, bytes(data))
    except Exception as exc:
        return HexEditResult(ok=False, error=f"write failed: {exc!r}")
    return HexEditResult(ok=True)


class HexEditDialog(Subwindow):
    """Inline hex cell edit dialog. Parses input per the current MemFormat,
    calls commit_hex_edit, pops a MessageBox on need_confirm."""

    def __init__(self, *, dialog_id: int, addr: int, cell_bytes: int,
                 current: bytes, mem_fmt: "MemFormat") -> None:
        self.id = f"hex_edit_{dialog_id}"
        self._addr = addr
        self._cell_bytes = cell_bytes
        self._mem_fmt = mem_fmt
        self._current = bytes(current)
        from ..formats import format_cell
        self._text = format_cell(
            int.from_bytes(self._current, "little"), mem_fmt)
        self._error: str | None = None
        self._pending_allow_exec = False    # set by MessageBox Yes callback

    def render(self, state: "DebugViewState") -> bool:
        from nylib.pyimgui import imgui
        from nylib.pyimgui.imgui import ctx as imgui_ctx
        from ..widgets import use_state

        title = f"Edit @ 0x{self._addr:X}##{self.id}_{state._uid}"
        flags = imgui.ImGuiWindowFlags_AlwaysAutoResize
        with use_state(state):
            with imgui_ctx.Begin(title, open=True, flags=flags) as (show, window_open):
                if not window_open:
                    return False
                if not show:
                    return True
                # Auto-retry path: a previous MessageBox Yes callback set
                # _pending_allow_exec. Commit with allow_executable=True
                # without waiting for another Commit click.
                if self._pending_allow_exec:
                    self._pending_allow_exec = False
                    return self._commit(state, allow_executable=True)
                imgui.Text(f"Cell: {self._cell_bytes} bytes "
                           f"({self._mem_fmt.radix})")
                _changed, self._text = imgui.InputText(
                    f"value##{self.id}", self._text)
                if self._error:
                    imgui.TextColored(imgui.ImVec4(1, 0.3, 0.3, 1), self._error)
                if imgui.Button(f"Commit##{self.id}"):
                    return self._commit(state, allow_executable=False)
                imgui.SameLine()
                if imgui.Button(f"Cancel##{self.id}"):
                    return False
        return True

    def _parse(self) -> bytes | None:
        """Parse `self._text` per self._mem_fmt to a `cell_bytes`-long bytes.
        Returns None on parse error (sets self._error)."""
        text = self._text.strip()
        if not text:
            self._error = "value required"
            return None
        try:
            if self._mem_fmt.radix == "hex":
                value = int(text, 16)
            else:
                value = int(text)
        except ValueError as exc:
            self._error = f"parse error: {exc}"
            return None
        mask = (1 << (self._cell_bytes * 8)) - 1
        return (value & mask).to_bytes(self._cell_bytes, "little")

    def _commit(self, state: "DebugViewState", *,
                allow_executable: bool) -> bool:
        new_bytes = self._parse()
        if new_bytes is None:
            return True   # stay open
        result = commit_hex_edit(self._addr, new_bytes,
                                  allow_executable=allow_executable)
        if result.ok:
            state.request_refresh()
            return False
        if result.need_confirm:
            # Pop a MessageBox; Yes re-tries with allow_executable=True
            # via the _pending_allow_exec flag (consumed at the top of
            # the next render).
            from nylib.imguiutils import MessageBox
            self_ref = self

            def cb(value):
                if value is True:
                    self_ref._pending_allow_exec = True

            MessageBox(
                result.confirm_message,
                title="Confirm write to executable page",
                buttons=[("Yes", True), ("Cancel", False)],
                callback=cb,
            )
            self._error = "awaiting confirmation..."
            return True   # stay open; user confirms via MessageBox
        self._error = result.error or "write failed"
        return True


__all__ = [
    "HexEditResult", "commit_hex_edit", "is_page_executable",
    "HexEditDialog",
]
