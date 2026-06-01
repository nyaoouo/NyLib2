"""Per-BP hit window Subwindow.

One per BP installed via the DebugView.

Layout:
  [toolbar]   Detach / [attached|detached] / Total / Enabled / stack-frames
  ---
  for each frm (sorted by hit count desc):
    [+]  0x<frm>   hits=N   last=...   <- click [+] to expand
        +-----+-----+--------+-------+-------+-...  <- sticky reg header
        | stk | xmm | when   | rip   | rsp   | ...
        | [S] | [X] | 30 ms  | 0x... | 0x... | ...  <- ImGuiListClipper rows
        | [S] | [X] | 50 ms  | 0x... | 0x... | ...     hover [S] for stack tooltip
        ...                                          hover [X] for xmm table tooltip
        +-----+-----+--------+-------+-------+-...

Buttons:
- **Detach**: uninstalls the BP via `state.detach_bp_hit_window` but keeps
  this window + recorder + accumulated samples visible.
- **X**: fully removes the BP and this window via `state.uninstall_bp`.
"""
from __future__ import annotations

import struct
import time
import typing

from ..formats import format_address
from ..subwindow import Subwindow
from ..widgets import clickable_addr, use_state

if typing.TYPE_CHECKING:
    from ..state import DebugViewState
    from .recorder import BpHitRecorder, HitRecord


_FLAG_BITS = [
    (1 << 0, "EXEC"),
    (1 << 1, "WRITE"),
    (1 << 2, "READ"),
    (1 << 8, "HARD"),
    (1 << 9, "SOFT"),
]

_HIST_HEADER_ROWS = 1            # sticky header
_HIST_VISIBLE_ROWS = 8           # cap sub-table viewport height
_HIST_REG_COL_W = 140.0
_HIST_STK_COL_W = 28.0
_HIST_XMM_COL_W = 28.0
_HIST_WHEN_COL_W = 90.0


def _flag_label(flag: int) -> str:
    parts = [name for bit, name in _FLAG_BITS if int(flag) & bit]
    return "|".join(parts) if parts else f"0x{int(flag):X}"


def _format_last_seen_ns(ns: int) -> str:
    """Render a monotonic-ns timestamp as a relative-time string."""
    age_ms = (time.monotonic_ns() - ns) / 1_000_000.0
    if age_ms < 1000:
        return f"{age_ms:.0f} ms ago"
    if age_ms < 60_000:
        return f"{age_ms / 1000.0:.1f} s ago"
    return f"{age_ms / 60_000.0:.1f} min ago"


def _format_stack_frame(addr: int, resolver) -> str:
    """Render a stack-frame address. Preference order:
      1. `module.dll:export+0xOFF  (0xRAW)` when an export "owns" the
         address (bound by next export's RVA or max_export_offset).
      2. `module.dll+0xOFF  (0xRAW)` when the address is in a loaded
         module but no export owns it (or export resolution is off).
      3. `0xRAW` when no loaded module contains it (or resolver is None).
    """
    if resolver is not None:
        try:
            ex = resolver.lookup_export(int(addr))
        except Exception:
            ex = None
        if ex is not None:
            mod, sym, off = ex
            tail = f"  (0x{int(addr):X})"
            if off == 0:
                return f"{mod}:{sym}{tail}"
            return f"{mod}:{sym}+0x{int(off):X}{tail}"
        try:
            result = resolver.lookup(int(addr))
        except Exception:
            result = None
        if result is not None:
            name, off = result
            return f"{name}+0x{int(off):X}  (0x{int(addr):X})"
    return f"0x{int(addr):X}"


class BpHitWindow(Subwindow):
    """A floating window showing per-`frm` hits for a single BP."""

    def __init__(self, *, bp, recorder: "BpHitRecorder") -> None:
        self.id = f"bp_hit_{bp.handle}"
        self._bp = bp
        self._recorder = recorder
        # True once Detach has uninstalled the BP. The window stays open
        # so historical samples are still visible; new samples won't arrive.
        self._detached = False
        # Multi-expand allowed: any number of frms may be open at once.
        self._expanded_frms: set[int] = set()
        self._stack_frames_input = recorder._stack_frames

    def render(self, state: "DebugViewState") -> bool:
        from nylib.pyimgui import imgui
        from nylib.pyimgui.imgui import ctx as imgui_ctx

        title = (f"BP @ 0x{self._bp.address:X} "
                 f"({_flag_label(self._bp.flag)})##{self.id}_{state._uid}")
        with use_state(state):
            with imgui_ctx.Begin(title, open=True) as (show, window_open):
                if not window_open:
                    # X clicked: fully uninstall the BP and remove this window.
                    state.uninstall_bp(self._bp.handle)
                    return False
                if not show:
                    return True
                self._render_toolbar(state, imgui, imgui_ctx)
                imgui.Separator()
                self._render_frm_list(state, imgui, imgui_ctx)
        return True

    # ----- toolbar -----

    def _render_toolbar(self, state: "DebugViewState",
                         imgui, imgui_ctx) -> None:
        with imgui_ctx.BeginDisabled(self._detached):
            if imgui.Button("Detach"):
                if state.detach_bp_hit_window(self._bp.handle):
                    self._detached = True
        imgui.SameLine()
        status = "detached" if self._detached else "attached"
        imgui.Text(f"[{status}]  "
                   f"Total: {self._recorder.total()}  "
                   f"Enabled: {self._bp.is_enabled()}")
        imgui.SameLine()
        changed, n = imgui.SliderInt("stack frames",
                                      int(self._stack_frames_input), 1, 64)
        if changed:
            self._stack_frames_input = int(n)
            self._recorder.set_stack_frames(int(n))

    # ----- per-frm list -----

    def _render_frm_list(self, state, imgui, imgui_ctx) -> None:
        snap = self._recorder.snapshot()
        if not snap:
            imgui.TextDisabled("(no hits yet)")
            return
        for r in snap:
            self._render_frm_row(r, imgui, imgui_ctx)

    def _render_frm_row(self, r: "HitRecord", imgui, imgui_ctx) -> None:
        expanded = r.frm in self._expanded_frms
        arrow = "[-]" if expanded else "[+]"
        if imgui.SmallButton(f"{arrow}##{self.id}_exp_{r.frm:X}"):
            if expanded:
                self._expanded_frms.discard(r.frm)
                expanded = False
            else:
                self._expanded_frms.add(r.frm)
                expanded = True
        imgui.SameLine()
        clickable_addr(r.frm, id=f"{self.id}_frm_{r.frm:X}")
        imgui.SameLine()
        imgui.Text(f"  hits={r.count}  "
                   f"last={_format_last_seen_ns(r.last_seen_ns)}  "
                   f"samples={len(r.samples)}")
        if expanded:
            imgui.Indent()
            self._render_history(r, imgui, imgui_ctx)
            imgui.Unindent()
        imgui.Separator()

    # ----- per-frm hit-history sub-table -----

    def _render_history(self, r: "HitRecord", imgui, imgui_ctx) -> None:
        """Render the sample ring buffer for one frm as a sticky-header,
        virtual-scrolled sub-table. Newest samples first."""
        if not r.samples:
            imgui.TextDisabled("(no samples)")
            return
        # Column set is taken from the latest sample's reg ordering. (All
        # samples in one BP+thread normally share the same reg set; if an
        # older one is missing a key we render a "-" placeholder.)
        reg_names = [name for name, _ in r.samples[-1].regs]
        # stack-icon + xmm-icon + when + N regs
        n_cols = 3 + len(reg_names)
        flags = (imgui.ImGuiTableFlags_RowBg
                 | imgui.ImGuiTableFlags_BordersOuter
                 | imgui.ImGuiTableFlags_BordersInnerV
                 | imgui.ImGuiTableFlags_ScrollY
                 | imgui.ImGuiTableFlags_ScrollX
                 | imgui.ImGuiTableFlags_Resizable)
        row_h = imgui.GetTextLineHeightWithSpacing()
        visible_rows = min(len(r.samples), _HIST_VISIBLE_ROWS)
        height = row_h * (visible_rows + _HIST_HEADER_ROWS) + 12.0
        with imgui_ctx.BeginTable(
            f"##{self.id}_hist_{r.frm:X}", n_cols, flags,
            outer_size=imgui.ImVec2(0.0, height)) as ok:
            if not ok:
                return
            imgui.TableSetupColumn(
                "stk", imgui.ImGuiTableColumnFlags_WidthFixed, _HIST_STK_COL_W)
            imgui.TableSetupColumn(
                "xmm", imgui.ImGuiTableColumnFlags_WidthFixed, _HIST_XMM_COL_W)
            imgui.TableSetupColumn(
                "when", imgui.ImGuiTableColumnFlags_WidthFixed,
                _HIST_WHEN_COL_W)
            for name in reg_names:
                imgui.TableSetupColumn(
                    name, imgui.ImGuiTableColumnFlags_WidthFixed,
                    _HIST_REG_COL_W)
            # Freeze the first row so the reg-name header stays visible
            # while scrolling. (Cols=0, Rows=1).
            imgui.TableSetupScrollFreeze(0, 1)
            imgui.TableHeadersRow()
            # Newest first - reverse the ring buffer for display.
            samples = list(reversed(r.samples))
            clipper = imgui.ImGuiListClipper()
            clipper.Begin(len(samples))
            while clipper.Step():
                for i in range(clipper.DisplayStart, clipper.DisplayEnd):
                    self._render_history_row(r.frm, i, samples[i],
                                              reg_names, imgui, imgui_ctx)

    def _render_history_row(self, frm: int, idx: int, s,
                             reg_names, imgui, imgui_ctx) -> None:
        from ..widgets import current_state
        imgui.TableNextRow()
        # ----- stack-icon column -----
        imgui.TableNextColumn()
        # Use Selectable so it's a real interactive item that fires
        # IsItemHovered (Text isn't interactive). The label has a unique
        # row-index suffix so duplicate values can't collide on imgui ID.
        imgui.Selectable(
            f"[S]##{self.id}_si_{frm:X}_{idx}", False,
            flags=imgui.ImGuiSelectableFlags_AllowItemOverlap)
        state = current_state()
        resolver = getattr(state, "_module_resolver", None)
        if imgui.IsItemHovered():
            with imgui_ctx.BeginTooltip() as show_tt:
                if show_tt:
                    self._render_stack_tooltip(s, resolver, imgui)
        # Left-click on [S] opens a persistent popup; the popup hosts
        # clickable_addr widgets so each frame can be copied or sent to
        # the disasm / hex view via its right-click context menu. This
        # complements the hover tooltip (read-only quick peek) with an
        # interactive workflow.
        with imgui_ctx.BeginPopupContextItem(
            f"##{self.id}_sp_{frm:X}_{idx}",
            popup_flags=imgui.ImGuiPopupFlags_MouseButtonLeft) as show_pop:
            if show_pop:
                self._render_stack_popup(frm, idx, s, imgui, imgui_ctx)
        # ----- xmm-icon column -----
        imgui.TableNextColumn()
        if s.xmm:
            imgui.Selectable(
                f"[X]##{self.id}_xi_{frm:X}_{idx}", False,
                flags=imgui.ImGuiSelectableFlags_AllowItemOverlap)
            if imgui.IsItemHovered():
                with imgui_ctx.BeginTooltip() as show_tt:
                    if show_tt:
                        self._render_xmm_tooltip(frm, idx, s, imgui, imgui_ctx)
        else:
            # No XMM captured for this sample (older backend or capture
            # error); render a dimmed placeholder.
            imgui.TextDisabled("-")
        # ----- when column -----
        imgui.TableNextColumn()
        imgui.Text(_format_last_seen_ns(s.when_ns))
        # ----- reg columns -----
        reg_map = dict(s.regs)
        for name in reg_names:
            imgui.TableNextColumn()
            value = reg_map.get(name)
            if value is None:
                imgui.TextDisabled("-")
            else:
                # Every clickable_addr gets a unique id including the row
                # index so two samples with the same register value don't
                # produce conflicting imgui IDs.
                clickable_addr(
                    int(value),
                    id=f"{self.id}_reg_{frm:X}_{idx}_{name}")

    # ----- stack tooltip / popup -----

    def _render_stack_tooltip(self, s, resolver, imgui) -> None:
        """Read-only stack peek shown while the user hovers [S]. Each
        frame is rendered as `module+0xOFFSET (0xRAW)` when the address
        falls in a loaded module, otherwise just the raw hex."""
        n = len(s.stack)
        imgui.Text(f"Stack ({n} frame{'s' if n != 1 else ''}):")
        for j, sa in enumerate(s.stack):
            imgui.Text(f"  [{j:>2}] {_format_stack_frame(sa, resolver)}")

    def _render_stack_popup(self, frm: int, idx: int, s,
                              imgui, imgui_ctx) -> None:
        """Interactive stack popup opened by clicking [S]. Each frame is
        a clickable_addr - left-click copies the formatted address;
        right-click opens the standard go-to-disasm / go-to-hex menu."""
        n = len(s.stack)
        imgui.Text(f"Stack ({n} frame{'s' if n != 1 else ''})  "
                    f"- left-click to copy, right-click for menu")
        imgui.Separator()
        flags = (imgui.ImGuiTableFlags_RowBg
                 | imgui.ImGuiTableFlags_BordersInner
                 | imgui.ImGuiTableFlags_SizingFixedFit)
        with imgui_ctx.BeginTable(
            f"##{self.id}_st_t_{frm:X}_{idx}", 2, flags) as ok:
            if not ok:
                return
            imgui.TableSetupColumn(
                "#", imgui.ImGuiTableColumnFlags_WidthFixed, 32.0)
            imgui.TableSetupColumn(
                "addr", imgui.ImGuiTableColumnFlags_WidthFixed, 340.0)
            for j, sa in enumerate(s.stack):
                imgui.TableNextRow()
                imgui.TableNextColumn()
                imgui.TextDisabled(f"[{j:>2}]")
                imgui.TableNextColumn()
                # Each clickable_addr id is unique within the popup so
                # repeated stack-frame addresses (recursion) don't
                # collide on imgui ID hashing.
                clickable_addr(
                    int(sa),
                    id=f"{self.id}_sf_{frm:X}_{idx}_{j}")

    # ----- xmm tooltip -----

    def _render_xmm_tooltip(self, frm: int, idx: int, s,
                             imgui, imgui_ctx) -> None:
        """Render the XMM table inside an already-open tooltip. Three
        columns: reg | 4 LE-uint32 words (hex) | 4 LE-float interpretation."""
        flags = (imgui.ImGuiTableFlags_BordersInner
                 | imgui.ImGuiTableFlags_RowBg
                 | imgui.ImGuiTableFlags_SizingFixedFit)
        with imgui_ctx.BeginTable(
            f"##{self.id}_xmm_{frm:X}_{idx}", 3, flags) as ok:
            if not ok:
                return
            imgui.TableSetupColumn(
                "reg", imgui.ImGuiTableColumnFlags_WidthFixed, 50.0)
            imgui.TableSetupColumn(
                "hex (LE u32 x4)",
                imgui.ImGuiTableColumnFlags_WidthFixed, 290.0)
            imgui.TableSetupColumn(
                "floats (LE f32 x4)",
                imgui.ImGuiTableColumnFlags_WidthFixed, 290.0)
            imgui.TableHeadersRow()
            for name, buf in s.xmm:
                if len(buf) != 16:
                    imgui.TableNextRow()
                    imgui.TableNextColumn(); imgui.Text(name)
                    imgui.TableNextColumn()
                    imgui.TextDisabled(f"<invalid {len(buf)} bytes>")
                    imgui.TableNextColumn(); imgui.Text("")
                    continue
                u32s = struct.unpack("<4I", buf)
                fs = struct.unpack("<4f", buf)
                imgui.TableNextRow()
                imgui.TableNextColumn(); imgui.Text(name)
                imgui.TableNextColumn()
                imgui.Text(" ".join(f"{u:08X}" for u in u32s))
                imgui.TableNextColumn()
                imgui.Text("  ".join(f"{f:>12.4g}" for f in fs))


__all__ = ["BpHitWindow"]
