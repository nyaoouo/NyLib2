"""Shared dxtest payload.

Auto-detects which D3D frontend to use by checking which `d3d{9,11,12}.dll`
is loaded in the current process. The same payload is injected into all
three dxtest host EXEs (`dxtest_dx{9,11,12}.exe`).
"""
from __future__ import annotations

import time

from common.payload_common import configure_imports, keep_alive, mark

configure_imports()

import nylib.pyimgui.imgui as imgui
from nylib.pyimgui.imgui import ctx as imgui_ctx

from nylib.process import Process
from nylib import imguiutils
from nylib.imguiutils import DebugViewState


mark("payload_started")


# DX runtime detection: priority order = 12 > 11 > 9 so the highest-version
# wins if multiple runtimes are co-loaded (some apps load several for interop).
_DETECT_ORDER = (
    ("d3d12.dll", "dx12", "Dx12Inbound"),
    ("d3d11.dll", "dx11", "Dx11Inbound"),
    ("d3d9.dll",  "dx9",  "Dx9Inbound"),
)


def _detect_frontend() -> tuple[str, type]:
    """Return (backend_name, InboundClass) by inspecting loaded modules."""
    proc = Process.current
    loaded: set[str] = set()
    for entry in proc.enum_ldr_data():
        try:
            name = entry.BaseDllName.remote_value(proc).lower()
        except Exception:
            continue
        loaded.add(name)
    for dll, backend, inbound_attr in _DETECT_ORDER:
        if dll in loaded:
            module = __import__(f"nylib.pyimgui.{backend}",
                                fromlist=[inbound_attr])
            return backend, getattr(module, inbound_attr)
    raise RuntimeError(
        "No D3D runtime (d3d9/11/12.dll) detected in current process; "
        "cannot pick a pyimgui inbound frontend."
    )


def _host_exe_name() -> str:
    """Return the host EXE's basename (e.g. 'dxtest_dx11.exe')."""
    proc = Process.current
    return proc.base_ldr_data.BaseDllName.remote_value(proc)


def _resolve_exports(exe_name: str) -> tuple[int, int]:
    """Return (dxtest_tick_addr, g_dxtest_tick_addr) inside the host EXE."""
    proc = Process.current
    fn_addr = proc.get_proc_address(exe_name, "dxtest_tick")
    var_addr = proc.get_proc_address(exe_name, "g_dxtest_tick")
    return int(fn_addr), int(var_addr)


backend, InboundCls = _detect_frontend()
exe_name = _host_exe_name()
mark("payload_backend_detected", f"{backend} via {exe_name}")

try:
    tick_fn_addr, tick_var_addr = _resolve_exports(exe_name)
    mark("payload_exports_resolved",
         f"dxtest_tick=0x{tick_fn_addr:X} g_dxtest_tick=0x{tick_var_addr:X}")
except Exception as exc:
    mark("payload_exports_failed", repr(exc))
    tick_fn_addr = tick_var_addr = 0


state = DebugViewState(
    disasm_cursor=tick_fn_addr or 0x140001000,
    hex_cursor=tick_var_addr or tick_fn_addr or 0x140001000,
    update_interval_ms=200,
)


def draw(renderer):
    mark("payload_drawn")
    with imgui_ctx.Begin(f"pyimgui2 {backend} inbound") as (show, _open):
        if show:
            imgui.Text(f"{backend.upper()} inbound render ok")
            imgui.Text(f"isInLogic={renderer.isInLogic}")
    with imgui_ctx.Begin("dxtest debug",
                          flags=imgui.ImGuiWindowFlags_MenuBar) as (show, _open):
        if show:
            imguiutils.render_debug_view(state)
    # Drive nylib.imguiutils.window_manager so the DebugView's Module panel,
    # MessageBox, FileDialog, etc. actually render.
    imguiutils.window_manager.render()


renderer = InboundCls(draw)
for attempt in range(50):
    try:
        renderer.Attach()
        mark("payload_attached")
        break
    except Exception as exc:
        mark("payload_attach_retry", repr(exc))
        time.sleep(0.2)
else:
    raise RuntimeError(f"failed to attach {backend} inbound renderer")

try:
    keep_alive()
finally:
    state.close()
    renderer.Detach()
