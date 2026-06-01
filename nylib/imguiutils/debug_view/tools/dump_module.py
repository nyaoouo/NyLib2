"""Dump Module tool: write a loaded module to disk, either unmapped
(pe_unmap, sections rewritten to file layout) or raw (verbatim memory
copy)."""
from __future__ import annotations

import os
import typing

from nylib.process import Process
from nylib.winutils.pe_unmap import pe_unmap

from ..subwindow import Subwindow
from ..widgets import use_state

if typing.TYPE_CHECKING:
    from ..state import DebugViewState


def default_output_path(module_name: str) -> str:
    """Default sink: './<name>.dumped' in the current working dir."""
    return f"./{module_name}.dumped"


def dump_unmapped(*, base: int, size: int, output_path: str) -> None:
    """Read mapped image bytes, call pe_unmap to rewrite to file layout,
    write the result. Raises on read/unmap/write failure."""
    data = Process.current.read(base, size)
    unmapped = pe_unmap(data)
    if unmapped is None:
        raise ValueError("pe_unmap returned None (invalid PE image)")
    with open(output_path, "wb") as f:
        f.write(unmapped)


def dump_raw(*, base: int, size: int, output_path: str) -> None:
    """Read mapped image bytes verbatim, write the result."""
    data = Process.current.read(base, size)
    with open(output_path, "wb") as f:
        f.write(data)


class DumpModuleTool(Subwindow):
    """Singleton 'Dump Module' subwindow."""
    id = "dump_module"

    def __init__(self) -> None:
        self._selected_module: str = ""
        self._output_path: str = ""
        self._mode: str = "unmapped"   # "unmapped" | "raw"
        self._status: str = "ready"
        self._status_is_error: bool = False
        self._confirm_overwrite_open: bool = False

    def _dump_disabled(self) -> bool:
        # module auto-populates to modules[0] in render(); only output_path
        # needs explicit user input to enable Dump.
        return not self._output_path

    def _maybe_default_output(self) -> None:
        if not self._output_path and self._selected_module:
            self._output_path = default_output_path(self._selected_module)

    def _run_dump(self, *, base: int, size: int) -> None:
        try:
            if self._mode == "unmapped":
                dump_unmapped(base=base, size=size,
                              output_path=self._output_path)
            else:
                dump_raw(base=base, size=size,
                         output_path=self._output_path)
            self._status = f"wrote {self._output_path}"
            self._status_is_error = False
        except Exception as exc:
            self._status = f"failed: {exc!r}"
            self._status_is_error = True

    def render(self, state: "DebugViewState") -> bool:
        from nylib.pyimgui import imgui
        from nylib.pyimgui.imgui import ctx as imgui_ctx

        title = f"Dump Module##dv{state._uid}_dump"
        with use_state(state):
            with imgui_ctx.Begin(title, open=True) as (show, window_open):
                if not window_open:
                    state.show_dump_module = False
                    return False
                if not show:
                    return True
                modules = []
                if state._module_resolver is not None:
                    modules = state._module_resolver.modules_snapshot()
                if not self._selected_module and modules:
                    self._selected_module = modules[0]["name"]
                if imgui.BeginCombo("Module##dump_mod", self._selected_module):
                    for m in modules:
                        if imgui.Selectable(
                            f"{m['name']}##dump_mod_{m['base']:X}",
                            self._selected_module == m["name"],
                        ):
                            self._selected_module = m["name"]
                            self._output_path = ""    # reset default
                    imgui.EndCombo()
                # Display selected module's base/size.
                base, size = 0, 0
                for m in modules:
                    if m["name"] == self._selected_module:
                        base, size = m["base"], m["size"]
                        break
                imgui.Text(f"base = 0x{base:X}   size = 0x{size:X}")
                self._maybe_default_output()
                _, self._output_path = imgui.InputText(
                    "Output##dump_out", self._output_path, 512)
                imgui.SameLine()
                if imgui.Button("...##dump_browse"):
                    from nylib.imguiutils.file_dialog import FileDialog
                    chosen = FileDialog.show_save_as(
                        default_path=self._output_path or "./",
                    )
                    if chosen:
                        self._output_path = chosen
                # Mode radios.
                if imgui.RadioButton("Unmapped (pe_unmap)##dump_m_u",
                                      self._mode == "unmapped"):
                    self._mode = "unmapped"
                if imgui.RadioButton("Raw (verbatim memory)##dump_m_r",
                                      self._mode == "raw"):
                    self._mode = "raw"
                # Dump button.
                imgui.BeginDisabled(self._dump_disabled())
                clicked = imgui.Button("Dump##dump_go")
                imgui.EndDisabled()
                if clicked and not self._dump_disabled():
                    if os.path.exists(self._output_path):
                        self._confirm_overwrite_open = True
                    else:
                        self._run_dump(base=base, size=size)
                if self._confirm_overwrite_open:
                    from nylib.imguiutils.message_box import MessageBox
                    result = MessageBox.show(
                        f"Overwrite {self._output_path}?",
                        title="Confirm",
                        buttons=("Yes", "No"),
                    )
                    if result == "Yes":
                        self._run_dump(base=base, size=size)
                        self._confirm_overwrite_open = False
                    elif result == "No":
                        self._confirm_overwrite_open = False
                imgui.SameLine()
                if imgui.Button("Cancel##dump_cancel"):
                    self._status = "ready"
                    self._status_is_error = False
                color = (imgui.ImVec4(1, 0.3, 0.3, 1) if self._status_is_error
                         else imgui.ImVec4(0.7, 0.9, 0.7, 1))
                imgui.TextColored(color, f"Status: {self._status}")
        return True


__all__ = ["DumpModuleTool", "default_output_path",
           "dump_unmapped", "dump_raw"]
