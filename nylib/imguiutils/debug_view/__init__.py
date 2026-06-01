"""nylib.imguiutils.debug_view - v0 Dear ImGui debug view.

Usage:
    from nylib import imguiutils
    from nylib.pyimgui import imgui
    from nylib.pyimgui.imgui import ctx as imgui_ctx
    from nylib.imguiutils import DebugViewState

    state = DebugViewState(disasm_cursor=0x140001000, hex_cursor=0x140001000)

    # Inside your render loop (per frame):
    with imgui_ctx.Begin("Debug View",
                          flags=imgui.ImGuiWindowFlags_MenuBar) as (show, _open):
        if show:
            imguiutils.render_debug_view(state)

The caller MUST pass ImGuiWindowFlags_MenuBar on the outer Begin;
render_debug_view places its File/View/Tools menu bar inside that window.

See `docs/superpowers/specs/2026-05-20-debug-view-design.md` for the full
design and `docs/superpowers/plans/2026-05-20-debug-view-v0.md` for the
implementation plan.
"""
from __future__ import annotations

from .formats import AddressFormat, MemCellSize, MemFormat
from .state import DebugViewState
from .widgets import (
    use_state,
    render_address_format_submenu,
    render_memory_format_submenu,
    render_update_interval_submenu,
    _check,
)
from .views.disasm import render_disasm_view
from .views.hex import render_hex_view
from .views.region import render_region_header
from .tools.address_resolver import AddressResolverTool
from .tools.module_panel import ModulePanel
from .bp.panel import BpManagerPanel
from .subwindow import find_subwindow, remove_subwindow
from .nav.pinned import PinnedAddressesPanel
from .nav.history import HistoryPanel
from .tools.pattern_scan import PatternScanTool
from .tools.dump_module import DumpModuleTool
from .tools.console import PythonConsole


def render_debug_view(state: DebugViewState, flags: int = 0) -> None:
    """Render the debug view inside the caller's current ImGui window.

    The caller's outer `Begin(...)` must include
    `imgui.ImGuiWindowFlags_MenuBar` so this function's menu bar renders."""
    from nylib.pyimgui import imgui
    from nylib.pyimgui.imgui import ctx as imgui_ctx

    if state._closed:
        imgui.TextColored(imgui.ImVec4(1, 0.3, 0.3, 1), "[debug view closed]")
        return

    with use_state(state):
        snap = state._worker.snapshot() if state._worker is not None else None
        _render_menu_bar(state, imgui, imgui_ctx)
        # Adaptive splitter: disasm pane gets `_splitter_top_frac` of the available
        # content height (after subtracting the region-header band); hex pane fills
        # the remainder via its `ImVec2(0, 0)` BeginChild. Recomputed every frame so
        # the panes track parent-window resizes. A drag handle is v1+.
        avail_h = imgui.GetContentRegionAvail().y
        state._splitter_top_h = max(50.0,
                                    (avail_h - state._splitter_mid_h)
                                    * state._splitter_top_frac)
        render_disasm_view(state, snap.disasm if snap else None)
        render_region_header(state, snap.region if snap else None)
        render_hex_view(state, snap.hex if snap else None)
        # Singleton subwindows tracked by boolean flags
        _sync_singleton_subwindow(state, "module",
                                   state.show_module_panel, ModulePanel)
        _sync_singleton_subwindow(state, "bp_panel",
                                   state.show_bp_panel, BpManagerPanel)
        _sync_singleton_subwindow(state, "addr_resolver_tool",
                                   state.show_address_resolver,
                                   AddressResolverTool)
        # v2 singletons
        _sync_singleton_subwindow(state, "pinned_panel",
                                   state.show_pinned_panel,
                                   PinnedAddressesPanel)
        _sync_singleton_subwindow(state, "history_panel",
                                   state.show_history_panel,
                                   HistoryPanel)
        _sync_singleton_subwindow(state, "pattern_scan",
                                   state.show_pattern_scan,
                                   PatternScanTool)
        _sync_singleton_subwindow(state, "dump_module",
                                   state.show_dump_module,
                                   DumpModuleTool)
        _sync_singleton_subwindow(state, "python_console",
                                   state.show_python_console,
                                   PythonConsole)

        # State-owned subwindow render loop
        keep = []
        import logging
        _log = logging.getLogger("nylib.imguiutils.debug_view")
        for sw in state._subwindows:
            try:
                if sw.render(state):
                    keep.append(sw)
            except Exception:
                _log.exception("subwindow %r render failed", sw.id)
        state._subwindows = keep


def _render_menu_bar(state, imgui, imgui_ctx) -> None:
    with imgui_ctx.BeginMenuBar() as show_menu_bar:
        if not show_menu_bar:
            return
        with imgui_ctx.BeginMenu("File") as show_file:
            if show_file:
                with imgui_ctx.BeginMenu("Address Format") as sub:
                    if sub:
                        render_address_format_submenu(state)
                with imgui_ctx.BeginMenu("Memory Format") as sub:
                    if sub:
                        render_memory_format_submenu(state)
                with imgui_ctx.BeginMenu("Update Interval") as sub:
                    if sub:
                        render_update_interval_submenu(state)
        with imgui_ctx.BeginMenu("View") as show_view:
            if show_view:
                if imgui.MenuItem(f"{_check(state.show_module_panel)}Module List"):
                    state.show_module_panel = not state.show_module_panel
                if imgui.MenuItem(f"{_check(state.show_bp_panel)}Manage Breakpoints"):
                    state.toggle_bp_panel()
                if imgui.MenuItem(
                    f"{_check(state.resolve_exports)}Resolve exports "
                    "(module:export+offset)"):
                    state.set_resolve_exports(not state.resolve_exports)
                if imgui.MenuItem(f"{_check(state.show_pinned_panel)}Pinned Addresses"):
                    state.show_pinned_panel = not state.show_pinned_panel
                if imgui.MenuItem(f"{_check(state.show_history_panel)}Address History"):
                    state.show_history_panel = not state.show_history_panel
        with imgui_ctx.BeginMenu("Tools") as show_tools:
            if show_tools:
                if imgui.MenuItem("Create Breakpoint..."):
                    state.open_bp_dialog()
                if imgui.MenuItem(
                    f"{_check(state.show_address_resolver)}"
                    "Resolve Address..."):
                    state.show_address_resolver = not state.show_address_resolver
                imgui.Separator()
                if imgui.MenuItem("Pattern Scan..."):
                    state.show_pattern_scan = True
                if imgui.MenuItem("Search..."):
                    state.open_search_dialog()
                if imgui.MenuItem("Dump Module..."):
                    state.show_dump_module = True
                if imgui.MenuItem(
                    f"{_check(state.show_python_console)}Python Console"):
                    state.show_python_console = not state.show_python_console
                if imgui.MenuItem("Run Script..."):
                    from nylib.imguiutils.file_dialog import FileDialog
                    chosen = FileDialog.show_open(default_path="./")
                    if chosen:
                        state.open_run_script_dialog(chosen)


def _sync_singleton_subwindow(state, sw_id: str, want: bool, factory) -> None:
    """Add a singleton subwindow when `want` flips True. The subwindow's
    own render returns False when the user closes its window (which also
    resets its `state.show_*` flag), so this helper only needs to add."""
    if want and find_subwindow(state, sw_id) is None:
        state._subwindows.append(factory())


__all__ = [
    "DebugViewState",
    "render_debug_view",
    "AddressFormat",
    "MemCellSize",
    "MemFormat",
]
