"""In-view search dialog: multi-instance subwindow with Find next /
Find prev over a shared ScanWorker."""
from __future__ import annotations

import typing

from nylib.pattern import compile_pattern

from ..subwindow import Subwindow
from ..widgets import use_state
from ._scan_worker import Hit, ScanStatus, ScanWorker, ScopeChoice
from .pattern_scan import build_region_list

if typing.TYPE_CHECKING:
    from ..state import DebugViewState


class InViewSearchDialog(Subwindow):
    """Multi-instance Search dialog. Tools > Search... opens a fresh
    instance. Each dialog owns its own ScanWorker + hit list."""

    def __init__(self, dialog_id: int,
                 initial_scope: ScopeChoice | None = None,
                 initial_pattern: str = ""):
        self.dialog_id = dialog_id
        self.id = f"search_{dialog_id}"
        self._pattern_text: str = initial_pattern
        self._scope: ScopeChoice = initial_scope or ScopeChoice(mode="window")
        self._worker: ScanWorker | None = None
        self._hits: list[Hit] = []
        self._cursor: int = -1
        self._error: str | None = None

    # ----- public step helpers (tested directly) -----

    def find_next(self) -> int | None:
        """Advance the cursor. If at end of loaded hits and the worker
        is paused, request_more() and return None (caller re-tries
        after next drain)."""
        if self._cursor + 1 < len(self._hits):
            self._cursor += 1
            return self._hits[self._cursor].addr
        if self._worker is not None:
            status = self._worker.status()
            if status.state == "paused":
                self._worker.request_more()
        return None

    def find_prev(self) -> int | None:
        """Walk backward in loaded hits. Never triggers request_more."""
        if self._cursor > 0:
            self._cursor -= 1
            return self._hits[self._cursor].addr
        return None

    def _begin_new_scan(self, *, state, regions, pattern: str) -> None:
        if self._worker is not None:
            self._worker.request_cancel()
            self._worker = None
        self._hits = []
        self._cursor = -1
        try:
            compile_pattern(pattern)
        except Exception as exc:
            self._error = repr(exc)
            return
        self._worker = ScanWorker(
            pattern=pattern, scope_regions=regions,
            page_size=100, hit_cap=10_000,
        )
        self._worker.start()
        self._error = None

    # ----- Subwindow protocol -----

    def render(self, state: "DebugViewState") -> bool:
        from nylib.pyimgui import imgui
        from nylib.pyimgui.imgui import ctx as imgui_ctx

        title = f"Search##dv{state._uid}_search_{self.dialog_id}"
        with use_state(state):
            with imgui_ctx.Begin(title, open=True) as (show, window_open):
                if not window_open:
                    if self._worker is not None:
                        self._worker.request_cancel()
                    return False
                if not show:
                    return True
                _, self._pattern_text = imgui.InputText(
                    "Pattern##search_pat", self._pattern_text, 256)
                # Scope radios.
                if imgui.RadioButton("Current window##search_sw",
                                      self._scope.mode == "window"):
                    self._scope.mode = "window"
                if imgui.RadioButton("Module##search_sm",
                                      self._scope.mode == "module"):
                    self._scope.mode = "module"
                modules = []
                if state._module_resolver is not None:
                    modules = state._module_resolver.modules_snapshot()
                imgui.SameLine()
                current = self._scope.module_name or (
                    modules[0]["name"] if modules else "")
                if imgui.BeginCombo("##search_mod", current):
                    for m in modules:
                        if imgui.Selectable(
                            f"{m['name']}##search_mod_{m['base']:X}",
                            current == m["name"],
                        ):
                            self._scope.module_name = m["name"]
                    imgui.EndCombo()
                if imgui.RadioButton("All committed##search_sa",
                                      self._scope.mode == "committed"):
                    self._scope.mode = "committed"
                imgui.SameLine()
                _, self._scope.include_private = imgui.Checkbox(
                    "Include private heap##search_pri",
                    self._scope.include_private)
                # Buttons.
                if imgui.Button("Find##search_find"):
                    regions = build_region_list(state, self._scope)
                    self._begin_new_scan(state=state, regions=regions,
                                          pattern=self._pattern_text)
                imgui.SameLine()
                if imgui.Button("Find next##search_next"):
                    addr = self.find_next()
                    if addr is not None:
                        _jump(state, addr)
                imgui.SameLine()
                if imgui.Button("Find prev##search_prev"):
                    addr = self.find_prev()
                    if addr is not None:
                        _jump(state, addr)
                # Drain hits per frame.
                if self._worker is not None:
                    self._hits.extend(self._worker.drain())
                status = self._worker.status() if self._worker is not None else None
                if self._error is not None:
                    imgui.TextColored(imgui.ImVec4(1, 0.3, 0.3, 1),
                                       f"error: {self._error}")
                elif status is not None:
                    imgui.Text(
                        f"{max(0, self._cursor + 1)} / {status.hits_total} "
                        f"(loaded {status.hits_loaded})"
                    )
                # Optional: collapsible recent hits.
                if imgui.CollapsingHeader("Recent hits##search_hits_hdr"):
                    flags = (imgui.ImGuiTableFlags_RowBg
                             | imgui.ImGuiTableFlags_ScrollY)
                    with imgui_ctx.BeginTable(
                        f"##search_{self.dialog_id}_t", 1, flags
                    ) as show_table:
                        if show_table:
                            imgui.TableSetupColumn(
                                "addr",
                                imgui.ImGuiTableColumnFlags_WidthStretch)
                            for i, hit in enumerate(self._hits):
                                imgui.TableNextRow()
                                imgui.TableNextColumn()
                                from ..widgets import clickable_addr
                                clickable_addr(hit.addr,
                                                id=f"search_{self.dialog_id}_hit_{i}")
        return True


def _jump(state: "DebugViewState", addr: int) -> None:
    if state.focused_view == "hex":
        state.goto_hex(addr)
    else:
        state.goto_disasm(addr)


__all__ = ["InViewSearchDialog"]
