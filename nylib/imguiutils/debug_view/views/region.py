"""Region header band - one line of VirtualQuery info for the focused cursor."""
from __future__ import annotations

import typing

from ..widgets import clickable_addr

if typing.TYPE_CHECKING:
    from ..state import DebugViewState
    from ..worker import RegionInfo


_STATE_NAMES = {0x10000: "FREE", 0x1000: "COMMIT", 0x2000: "RESERVE"}


def _protect_name(p: int) -> str:
    # Most-significant common bits first; subsetting is good enough for display.
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


def render_region_header(state: "DebugViewState",
                          region: "RegionInfo | None") -> None:
    from nylib.pyimgui import imgui
    from nylib.pyimgui.imgui import ctx as imgui_ctx

    with imgui_ctx.BeginChild(f"##dv{state._uid}_region",
                               imgui.ImVec2(0, state._splitter_mid_h)) as show_child:
        if not show_child:
            return
        if region is None:
            imgui.TextDisabled("(no region info yet)")
            return
        if region.error:
            with imgui_ctx.PushStyleColor(imgui.ImGuiCol_Text,
                                           imgui.ImVec4(1, 0.3, 0.3, 1)):
                imgui.Text(f"[worker error: {region.error}]")
            imgui.SameLine()
        imgui.Text("BaseAddress=")
        imgui.SameLine()
        clickable_addr(region.base, id="rgn_base")
        imgui.SameLine()
        state_name = _STATE_NAMES.get(region.state, f"0x{region.state:X}")
        imgui.Text(
            f" RegionSize=0x{region.size:X}  State={state_name}  "
            f"Protect={_protect_name(region.protect)}  "
            f"ModuleName={region.module_name or '-'}"
        )


__all__ = ["render_region_header"]
