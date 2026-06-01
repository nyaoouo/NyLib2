"""Edit-asm via keystone direct - assemble + commit helper +
AsmEditDialog subwindow (render body in Task 13).

Same-size or smaller assembled bytes are NOP-padded silently. Larger
output returns `need_confirm=True` with a disassembled preview of the
bytes that would be clobbered in the following instruction(s).
"""
from __future__ import annotations

import dataclasses
import typing

from ..subwindow import Subwindow

if typing.TYPE_CHECKING:
    from ..state import DebugViewState


@dataclasses.dataclass(frozen=True)
class AsmEditResult:
    """Outcome of `commit_asm_edit`."""
    ok: bool
    new_bytes: bytes = b""
    overflow_into: bytes = b""
    overflow_decoded: str = ""
    error: str | None = None
    need_confirm: bool = False


def assemble(text: str, addr: int) -> bytes:
    """Assemble `text` at `addr` via keystone (x86-64). Returns bytes.

    Raises ValueError on syntax error or empty output.
    """
    from nylib.utils.pip import required
    required("setuptools", "keystone-engine")
    import keystone
    ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64)
    try:
        encoded, _count = ks.asm(text, addr)
    except keystone.KsError as exc:
        raise ValueError(f"keystone error: {exc}") from exc
    if not encoded:
        raise ValueError(f"keystone returned empty bytes for {text!r}")
    return bytes(encoded)


def _decode_for_preview(data: bytes, base: int) -> str:
    """Disassemble `data` for a human-readable preview. Falls back to hex."""
    if not data:
        return ""
    try:
        from ..worker import _get_cs
        cs = _get_cs()
        decoded = list(cs.disasm(data, base))
        if decoded:
            return "; ".join(f"{i.mnemonic} {i.op_str}" for i in decoded)
    except Exception:
        pass
    return data.hex()


def commit_asm_edit(addr: int, text: str, *, original_size: int,
                    allow_overflow: bool = False) -> AsmEditResult:
    """Assemble `text` at `addr` and write the result.

    Behaviour:
    - Same size: write new bytes.
    - Smaller: write new bytes + NOP padding to fill `original_size`.
    - Larger and `allow_overflow=False`: return `need_confirm=True`
      with the decoded preview of the bytes that would be clobbered.
      Caller pops a confirmation in the dialog; on Yes, re-calls with
      `allow_overflow=True`.
    - Larger and `allow_overflow=True`: write new bytes verbatim.

    Never raises; returns `AsmEditResult` with `error` set on failure.
    """
    from nylib.process import Process
    try:
        new = assemble(text, addr)
    except Exception as exc:
        return AsmEditResult(ok=False, error=f"assemble failed: {exc!r}")
    if len(new) <= original_size:
        padded = new + b"\x90" * (original_size - len(new))
        try:
            Process.current.write(addr, padded)
        except Exception as exc:
            return AsmEditResult(ok=False, new_bytes=new,
                                 error=f"write failed: {exc!r}")
        return AsmEditResult(ok=True, new_bytes=new)
    # len(new) > original_size: overflow case.
    if not allow_overflow:
        try:
            overflow_bytes = Process.current.read(
                addr + original_size, len(new) - original_size)
        except Exception:
            overflow_bytes = b""
        overflow_decoded = _decode_for_preview(
            overflow_bytes, addr + original_size)
        return AsmEditResult(ok=False, need_confirm=True, new_bytes=new,
                             overflow_into=bytes(overflow_bytes),
                             overflow_decoded=overflow_decoded)
    try:
        Process.current.write(addr, new)
    except Exception as exc:
        return AsmEditResult(ok=False, new_bytes=new,
                             error=f"write failed: {exc!r}")
    return AsmEditResult(ok=True, new_bytes=new)


class AsmEditDialog(Subwindow):
    """Edit-asm dialog. Two-stage: assemble + commit, or confirm-overflow."""

    def __init__(self, *, dialog_id: int, addr: int, original_size: int,
                 original_text: str) -> None:
        self.id = f"asm_edit_{dialog_id}"
        self._addr = addr
        self._orig_size = original_size
        self._text = original_text
        self._error: str | None = None
        self._pending: AsmEditResult | None = None

    def render(self, state: "DebugViewState") -> bool:
        from nylib.pyimgui import imgui
        from nylib.pyimgui.imgui import ctx as imgui_ctx
        from ..widgets import use_state

        title = f"Edit asm @ 0x{self._addr:X}##{self.id}_{state._uid}"
        flags = imgui.ImGuiWindowFlags_AlwaysAutoResize
        with use_state(state):
            with imgui_ctx.Begin(title, open=True, flags=flags) as (show, window_open):
                if not window_open:
                    return False
                if not show:
                    return True
                imgui.Text(f"Original size: {self._orig_size} bytes")
                _changed, self._text = imgui.InputText(
                    f"asm##{self.id}", self._text)
                if self._error:
                    imgui.TextColored(imgui.ImVec4(1, 0.3, 0.3, 1), self._error)

                if self._pending is not None:
                    # Confirmation stage.
                    imgui.Separator()
                    imgui.TextWrapped(
                        f"New instruction is {len(self._pending.new_bytes)} bytes "
                        f"(original {self._orig_size}). Would clobber the "
                        f"following bytes:")
                    imgui.TextWrapped(self._pending.overflow_decoded
                                      or self._pending.overflow_into.hex())
                    if imgui.Button(f"Overwrite##{self.id}"):
                        result = commit_asm_edit(
                            self._addr, self._text,
                            original_size=self._orig_size,
                            allow_overflow=True,
                        )
                        if result.ok:
                            state.request_refresh()
                            return False
                        self._error = result.error or "write failed"
                        self._pending = None
                    imgui.SameLine()
                    if imgui.Button(f"Back##{self.id}"):
                        self._pending = None
                else:
                    if imgui.Button(f"Commit##{self.id}"):
                        result = commit_asm_edit(
                            self._addr, self._text,
                            original_size=self._orig_size,
                            allow_overflow=False,
                        )
                        if result.ok:
                            state.request_refresh()
                            return False
                        if result.need_confirm:
                            self._pending = result
                            self._error = None
                        else:
                            self._error = result.error or "write failed"
                    imgui.SameLine()
                    if imgui.Button(f"Cancel##{self.id}"):
                        return False
        return True


__all__ = [
    "AsmEditResult", "assemble", "commit_asm_edit", "AsmEditDialog",
]
