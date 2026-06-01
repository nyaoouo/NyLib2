"""Address Resolver tool subwindow.

Parses an address expression (any form accepted by `parse_address`)
and shows a detailed breakdown:

    - The numeric resolved address.
    - Module attribution (name, base, end, offset within module).
    - VirtualQuery page properties (AllocationBase, BaseAddress,
      RegionSize, State, Protect, Type).
    - All exports of the same module whose absolute address falls in
      the same 4 KiB page as the resolved address, sorted by distance.

Opened via Tools -> "Resolve Address..." and tracked as a singleton
subwindow (state.show_address_resolver).
"""
from __future__ import annotations

import typing

from ..formats import AddressFormat, format_address, parse_address
from ..subwindow import Subwindow
from ..widgets import clickable_addr, use_state

if typing.TYPE_CHECKING:
    from ..state import DebugViewState


_STATE_NAMES = {0x10000: "FREE", 0x1000: "COMMIT", 0x2000: "RESERVE"}
_TYPE_NAMES = {0x1000000: "IMAGE", 0x40000: "MAPPED", 0x20000: "PRIVATE"}


def _protect_name(p: int) -> str:
    """Mirror region_header._protect_name with extra protect bits."""
    table = [
        (0x100, "GUARD"),
        (0x80, "WRITECOMBINE"),
        (0x40, "EXEC_RW"),
        (0x20, "EXEC_R"),
        (0x10, "EXEC"),
        (0x04, "RW"),
        (0x02, "R"),
        (0x01, "NOACCESS"),
    ]
    names = [name for bit, name in table if p & bit]
    return "|".join(names) if names else f"0x{p:X}"


class AddressResolverTool(Subwindow):
    """Singleton tool window. Sets `state.show_address_resolver` False
    when its X is clicked so the View/Tools menu checkbox stays in sync."""

    id = "addr_resolver_tool"

    def __init__(self) -> None:
        self._input_text = "0x140000000"
        self._last_input = ""
        # Cached result of the most recent successful resolve:
        #   { 'addr': int,
        #     'mbi':  dict | None     (VirtualQuery, None on failure),
        #     'mod':  (name, base, size, offset) | None,
        #     'exports': list[(name, abs_addr, signed_off_from_addr)],
        #     'error': str | None }
        self._result: dict | None = None

    # ----- Subwindow protocol -----

    def render(self, state: "DebugViewState") -> bool:
        from nylib.pyimgui import imgui
        from nylib.pyimgui.imgui import ctx as imgui_ctx

        title = f"Address Resolver##{state._uid}_addr_res"
        with use_state(state):
            with imgui_ctx.Begin(title, open=True,
                                  flags=imgui.ImGuiWindowFlags_None
                                  ) as (show, window_open):
                if not window_open:
                    state.show_address_resolver = False
                    return False
                if not show:
                    return True
                self._render_input(state, imgui)
                imgui.Separator()
                self._render_result(state, imgui, imgui_ctx)
        return True

    def on_close(self, state: "DebugViewState") -> None:
        state.show_address_resolver = False

    # ----- input row -----

    def _render_input(self, state, imgui) -> None:
        imgui.TextDisabled(
            "Expression: hex, module name, module.dll:Export, "
            "or any of those with + / - arithmetic")
        imgui.SetNextItemWidth(420.0)
        flags = imgui.ImGuiInputTextFlags_EnterReturnsTrue
        changed, text = imgui.InputText(
            f"##addr_res_in_{state._uid}", self._input_text, flags)
        if changed:
            self._input_text = text
            self._resolve(state)
        imgui.SameLine()
        if imgui.Button("Resolve##addr_res_btn"):
            self._resolve(state)
        if not state.resolve_exports:
            imgui.SameLine()
            imgui.TextDisabled(
                "  (exports disabled - View -> Resolve exports)")

    # ----- result panel -----

    def _render_result(self, state, imgui, imgui_ctx) -> None:
        r = self._result
        if r is None:
            imgui.TextDisabled("Enter an expression and press Enter or Resolve.")
            return
        if r.get("error"):
            imgui.TextColored(imgui.ImVec4(1, 0.3, 0.3, 1),
                              f"parse error: {r['error']}")
            return
        addr = r["addr"]
        # ----- resolved address row -----
        imgui.Text("Resolved:")
        imgui.SameLine()
        clickable_addr(addr, id=f"addr_res_addr_{addr:X}")
        imgui.SameLine()
        imgui.TextDisabled(f"= 0x{addr:016X}")
        imgui.Separator()
        # ----- VirtualQuery page info -----
        mbi = r.get("mbi")
        imgui.Text("Page (VirtualQuery):")
        if mbi is None:
            imgui.SameLine()
            imgui.TextDisabled("(query failed or no info)")
        else:
            imgui.Indent()
            imgui.Text("AllocationBase: ")
            imgui.SameLine()
            clickable_addr(int(mbi["AllocationBase"]),
                            id="addr_res_alloc_base")
            imgui.Text("BaseAddress:   ")
            imgui.SameLine()
            clickable_addr(int(mbi["BaseAddress"]),
                            id="addr_res_base_addr")
            imgui.Text(f"RegionSize:    0x{int(mbi['RegionSize']):X}")
            state_n = _STATE_NAMES.get(int(mbi["State"]),
                                        f"0x{int(mbi['State']):X}")
            imgui.Text(f"State:         {state_n}")
            imgui.Text(f"Protect:       "
                       f"{_protect_name(int(mbi['Protect']))}  "
                       f"(0x{int(mbi['Protect']):X})")
            imgui.Text(f"AllocProtect:  "
                       f"{_protect_name(int(mbi['AllocationProtect']))}  "
                       f"(0x{int(mbi['AllocationProtect']):X})")
            type_n = _TYPE_NAMES.get(int(mbi["Type"]),
                                      f"0x{int(mbi['Type']):X}")
            imgui.Text(f"Type:          {type_n}")
            imgui.Unindent()
        imgui.Separator()
        # ----- Module attribution -----
        mod = r.get("mod")
        imgui.Text("Module:")
        if mod is None:
            imgui.SameLine()
            imgui.TextDisabled("  (address not inside any loaded module)")
        else:
            name, base, size, offset = mod
            imgui.Indent()
            imgui.Text(f"Name:    {name}")
            imgui.Text("Base:    ")
            imgui.SameLine()
            clickable_addr(base, id="addr_res_mod_base")
            imgui.Text(f"Size:    0x{size:X}")
            imgui.Text(f"Offset:  +0x{offset:X}  "
                       f"(end: 0x{base + size:016X})")
            imgui.Unindent()
        imgui.Separator()
        # ----- Nearest exports in same 4K page -----
        exports = r.get("exports") or []
        page_start = addr & ~0xFFF
        imgui.Text(f"Exports in same page  (0x{page_start:X} .. "
                    f"0x{page_start + 0xFFF:X}):")
        if not state.resolve_exports:
            imgui.Indent()
            imgui.TextDisabled(
                "Export resolution is disabled. Enable it via "
                "View -> Resolve exports.")
            imgui.Unindent()
        elif not exports:
            imgui.Indent()
            imgui.TextDisabled("(no exports of this module fall in this page)")
            imgui.Unindent()
        else:
            self._render_exports_table(addr, exports, imgui, imgui_ctx)

    def _render_exports_table(self, addr, exports, imgui, imgui_ctx) -> None:
        flags = (imgui.ImGuiTableFlags_RowBg
                 | imgui.ImGuiTableFlags_BordersInner
                 | imgui.ImGuiTableFlags_SizingFixedFit
                 | imgui.ImGuiTableFlags_ScrollY)
        row_h = imgui.GetTextLineHeightWithSpacing()
        h = min(row_h * (1 + len(exports)) + 16.0, row_h * 12)
        with imgui_ctx.BeginTable(
            "##addr_res_exp", 4, flags,
            outer_size=imgui.ImVec2(0.0, h)) as ok:
            if not ok:
                return
            imgui.TableSetupColumn(
                "name",  imgui.ImGuiTableColumnFlags_WidthFixed, 260.0)
            imgui.TableSetupColumn(
                "addr",  imgui.ImGuiTableColumnFlags_WidthFixed, 180.0)
            imgui.TableSetupColumn(
                "delta", imgui.ImGuiTableColumnFlags_WidthFixed,  90.0)
            imgui.TableSetupColumn(
                "side",  imgui.ImGuiTableColumnFlags_WidthFixed,  50.0)
            imgui.TableSetupScrollFreeze(0, 1)
            imgui.TableHeadersRow()
            for i, (name, abs_addr, delta) in enumerate(exports):
                imgui.TableNextRow()
                imgui.TableNextColumn(); imgui.Text(name)
                imgui.TableNextColumn()
                clickable_addr(int(abs_addr),
                                id=f"addr_res_exp_{i}_{abs_addr:X}")
                imgui.TableNextColumn()
                if delta == 0:
                    imgui.Text("=")
                elif delta > 0:
                    imgui.Text(f"+0x{delta:X}")
                else:
                    imgui.Text(f"-0x{-delta:X}")
                imgui.TableNextColumn()
                if delta == 0:
                    imgui.Text("hit")
                elif delta > 0:
                    imgui.TextDisabled("after")
                else:
                    imgui.TextDisabled("before")

    # ----- compute -----

    def _resolve(self, state) -> None:
        text = self._input_text.strip()
        self._last_input = text
        if not text:
            self._result = {"error": "empty input"}
            return
        resolver = getattr(state, "_module_resolver", None)
        addr = parse_address(text, resolver=resolver)
        if addr is None:
            self._result = {
                "error": "could not parse expression "
                         "(unknown module / bad hex / dangling op?)"
            }
            return
        out: dict = {"addr": int(addr), "error": None}
        # VirtualQuery
        out["mbi"] = self._query_page(addr)
        # Module attribution (via resolver - cheap).
        out["mod"] = self._lookup_module(addr, resolver)
        # Nearest exports in the same page.
        try:
            out["exports"] = (resolver.exports_in_page(addr)
                              if resolver is not None else [])
        except Exception:
            out["exports"] = []
        self._result = out

    @staticmethod
    def _query_page(addr: int) -> dict | None:
        """Return MEMORY_BASIC_INFORMATION fields for `addr`, or None
        on failure. Pulled into a dict so the render code doesn't
        depend on the live ctypes struct outliving the query."""
        try:
            from nylib.process import Process
            mbi = Process.current.virtual_query(int(addr))
            return {
                "AllocationBase":   int(mbi.AllocationBase),
                "BaseAddress":      int(mbi.BaseAddress),
                "RegionSize":       int(mbi.RegionSize),
                "State":            int(mbi.State),
                "Protect":          int(mbi.Protect),
                "AllocationProtect": int(mbi.AllocationProtect),
                "Type":             int(mbi.Type),
            }
        except Exception:
            return None

    @staticmethod
    def _lookup_module(addr: int, resolver
                        ) -> tuple[str, int, int, int] | None:
        """Return (name, base, size, offset) using the resolver's
        cached snapshot. None when no module contains the address."""
        if resolver is None:
            return None
        try:
            mod = resolver.lookup(int(addr))
        except Exception:
            return None
        if mod is None:
            return None
        name, offset = mod
        try:
            base = resolver.base_of(name)
        except Exception:
            base = None
        if base is None:
            return None
        # Derive size via _ends (private but exposed-via-len API would
        # require yet another method). We can compute end-base from a
        # second `lookup` at base+something... cheaper to just read
        # from the parallel arrays under the lock. Fall back to 0 if
        # the resolver doesn't expose it.
        size = 0
        try:
            import bisect
            with resolver._lock:                       # noqa: SLF001
                bases = resolver._bases               # noqa: SLF001
                ends = resolver._ends                 # noqa: SLF001
                idx = bisect.bisect_right(bases, base) - 1
                if 0 <= idx < len(bases) and bases[idx] == base:
                    size = ends[idx] - bases[idx]
        except Exception:
            pass
        return name, int(base), int(size), int(offset)


__all__ = ["AddressResolverTool"]
