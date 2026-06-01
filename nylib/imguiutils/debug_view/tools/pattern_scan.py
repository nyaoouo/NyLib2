"""Pattern Scan tool: async LocalMemoryPatternScanner with lazy
pagination. Singleton subwindow. Tools > Pattern Scan."""
from __future__ import annotations

import typing

from nylib.pattern import compile_pattern
from nylib.process import Process

from ..subwindow import Subwindow
from ..widgets import clickable_addr, use_state
from ._scan_worker import Hit, ScanStatus, ScanWorker, ScopeChoice

if typing.TYPE_CHECKING:
    from ..state import DebugViewState


def build_region_list(state: "DebugViewState",
                       scope: ScopeChoice) -> list[tuple[int, int]]:
    """Resolve a ScopeChoice into a frozen list of (addr, size) regions."""
    if scope.mode == "window":
        snap = state._worker.snapshot() if state._worker is not None else None
        if snap is None or snap.disasm is None:
            return []
        return [(snap.disasm.base, snap.disasm.size)]
    if scope.mode == "module":
        name = scope.module_name or ""
        base = state._module_resolver.base_of(name)
        size = state._module_resolver.size_of(name)
        if base is None or size is None:
            return []
        return [(base, size)]
    # committed
    return list(Process.current.iter_committed_regions(
        modules_only=not scope.include_private,
        snapshot=True,
    ))


class PatternScanTool(Subwindow):
    """Singleton 'Pattern Scan' subwindow. Tools > Pattern Scan."""
    id = "pattern_scan"

    def __init__(self) -> None:
        self._pattern_text: str = ""
        self._error: str | None = None
        self._scope = ScopeChoice(mode="module", module_name=None)
        self._worker: ScanWorker | None = None
        self._hits: list[Hit] = []
        self._auto_load: bool = True
        self._confirm_private_open: bool = False
        self._private_confirmed: bool = False

    # ----- non-render helpers (tested directly) -----

    def _validate_pattern(self, text: str) -> str | None:
        try:
            compile_pattern(text)
            return None
        except Exception as exc:
            return repr(exc)

    def _start_scan(self, state: "DebugViewState") -> None:
        err = self._validate_pattern(self._pattern_text)
        if err is not None:
            self._error = err
            return
        if self._worker is not None:
            self._worker.request_cancel()
            self._worker = None
        self._hits = []
        regions = build_region_list(state, self._scope)
        self._worker = ScanWorker(
            pattern=self._pattern_text,
            scope_regions=regions,
            page_size=100,
            hit_cap=10_000,
        )
        self._worker.start()
        self._error = None

    # ----- Subwindow protocol -----

    def render(self, state: "DebugViewState") -> bool:
        from nylib.pyimgui import imgui
        from nylib.pyimgui.imgui import ctx as imgui_ctx

        title = f"Pattern Scan##dv{state._uid}_pscan"
        with use_state(state):
            with imgui_ctx.Begin(title, open=True) as (show, window_open):
                if not window_open:
                    state.show_pattern_scan = False
                    if self._worker is not None:
                        self._worker.request_cancel()
                    return False
                if not show:
                    return True
                # Pattern input.
                changed, self._pattern_text = imgui.InputText(
                    "Pattern##pscan_pat", self._pattern_text, 256,
                )
                # Scope radios.
                if imgui.RadioButton("Module##pscan_sc_m",
                                     self._scope.mode == "module"):
                    self._scope.mode = "module"
                modules = []
                if state._module_resolver is not None:
                    modules = state._module_resolver.modules_snapshot()
                imgui.SameLine()
                current = self._scope.module_name or (
                    modules[0]["name"] if modules else "")
                if imgui.BeginCombo("##pscan_mod", current):
                    for m in modules:
                        if imgui.Selectable(f"{m['name']}##pscan_mod_{m['base']:X}",
                                            current == m["name"]):
                            self._scope.module_name = m["name"]
                    imgui.EndCombo()
                if imgui.RadioButton("Current window##pscan_sc_w",
                                     self._scope.mode == "window"):
                    self._scope.mode = "window"
                if imgui.RadioButton("All committed##pscan_sc_a",
                                     self._scope.mode == "committed"):
                    self._scope.mode = "committed"
                imgui.SameLine()
                changed_priv, self._scope.include_private = imgui.Checkbox(
                    "Include private heap##pscan_pri",
                    self._scope.include_private,
                )
                if changed_priv and self._scope.include_private and not self._private_confirmed:
                    self._confirm_private_open = True
                    self._scope.include_private = False
                if self._confirm_private_open:
                    from nylib.imguiutils.message_box import MessageBox
                    result = MessageBox.show(
                        '"Include private heap" scans MEM_PRIVATE regions '
                        "including Python's own allocator. Matches will "
                        "include regex compilation buffers and may grow "
                        "during the scan.\n\nProceed?",
                        title="Confirm",
                        buttons=("Yes", "No"),
                    )
                    if result == "Yes":
                        self._scope.include_private = True
                        self._private_confirmed = True
                        self._confirm_private_open = False
                    elif result == "No":
                        self._confirm_private_open = False
                # Buttons.
                if imgui.Button("Scan##pscan_go"):
                    self._start_scan(state)
                imgui.SameLine()
                if imgui.Button("Cancel##pscan_cancel") and self._worker is not None:
                    self._worker.request_cancel()
                # Drain hits.
                if self._worker is not None:
                    self._hits.extend(self._worker.drain())
                # Status.
                status: ScanStatus | None = self._worker.status() if self._worker else None
                if self._error is not None:
                    imgui.TextColored(imgui.ImVec4(1, 0.3, 0.3, 1),
                                       f"error: {self._error}")
                elif status is not None:
                    imgui.Text(
                        f"Loaded {status.hits_loaded} of {status.hits_total} hits"
                        f"   scanned 0x{status.bytes_scanned:X} / 0x{status.total_bytes:X}"
                        f"   {status.state.upper()}"
                    )
                # Hit table.
                flags = (imgui.ImGuiTableFlags_RowBg
                         | imgui.ImGuiTableFlags_BordersInnerV
                         | imgui.ImGuiTableFlags_ScrollY)
                with imgui_ctx.BeginTable(
                    f"##dv{state._uid}_pscantable", 2, flags
                ) as show_table:
                    if show_table:
                        imgui.TableSetupColumn(
                            "addr",
                            imgui.ImGuiTableColumnFlags_WidthFixed, 200.0)
                        imgui.TableSetupColumn(
                            "context",
                            imgui.ImGuiTableColumnFlags_WidthStretch)
                        for i, hit in enumerate(self._hits):
                            imgui.TableNextRow()
                            imgui.TableNextColumn()
                            clickable_addr(hit.addr, id=f"pscan_hit_{i}")
                            imgui.TableNextColumn()
                            imgui.Text(" ".join(f"{b:02X}" for b in hit.context))
                        # Auto-load-on-scroll: detect at-bottom + wheel down.
                        if (self._auto_load and self._worker is not None
                                and self._worker.status().state == "paused"):
                            scroll_y = imgui.GetScrollY()
                            scroll_max = imgui.GetScrollMaxY()
                            wheel = imgui.GetIO().MouseWheel
                            if wheel < 0 and scroll_y >= scroll_max - 8.0:
                                self._worker.request_more()
                if self._worker is not None and self._worker.status().state == "paused":
                    if imgui.Button(
                        f"Load more ({self._worker.status().hits_total - len(self._hits)} more)##pscan_more"
                    ):
                        self._worker.request_more()
                imgui.SameLine()
                changed_auto, self._auto_load = imgui.Checkbox(
                    "auto-load on scroll##pscan_auto", self._auto_load)
        return True


__all__ = ["PatternScanTool", "build_region_list"]
