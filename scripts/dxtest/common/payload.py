"""Shared dxtest payload.

Auto-detects which D3D frontend to use by checking which `d3d{9,11,12}.dll`
is loaded in the current process. The same payload is injected into all
three dxtest host EXEs (`dxtest_dx{9,11,12}.exe`).
"""
from __future__ import annotations

import os
import time

from common.payload_common import configure_imports, keep_alive, mark

configure_imports()

import nylib.pyimgui
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

# Per-backend flat-table index of the swap chain's Present slot;
# DX12 index 8 is a device-vtable slot, not swap-chain Present.
_PRESENT_METHOD_INDEX = {"dx11": 8, "dx12": 140}


def _detect_frontend():
    """Return (backend_name, InboundClass, frontend_module)."""
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
            return backend, getattr(module, inbound_attr), module
    raise RuntimeError(
        "No D3D runtime (d3d9/11/12.dll) detected in current process; "
        "cannot pick a pyimgui inbound frontend."
    )


def _module_owner(proc, addr: int) -> str:
    """Name of the module whose image contains addr, else its base address."""
    for entry in proc.enum_ldr_data():
        base = int(entry.DllBase)
        size = int(entry.SizeOfImage)
        if base and base <= addr < base + size:
            try:
                return entry.BaseDllName.remote_value(proc)
            except Exception:
                return f"0x{base:X}"
    return "<unknown>"


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


backend, InboundCls, frontend_module = _detect_frontend()
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

# Elapsed seconds (since this payload started) past which a resize was
# requested on the host side; drawn_after_resize is marked once draw() keeps
# being called past that point. Only set by the resize harness.
_resize_at = [float(v) for v in os.environ.get("DXTEST_RESIZE_AT", "").split(",") if v]
_payload_start = time.time()
_resize_marked = False


def draw(renderer):
    global _resize_marked
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
    if _resize_at and not _resize_marked and time.time() - _payload_start > max(_resize_at) + 0.5:
        mark("drawn_after_resize")
        _resize_marked = True


renderer = InboundCls(draw)
_requested_mode = os.environ.get("DXTEST_HOOK_MODE", "").lower()
_method_addr = 0
_method_before = b""
_queue_addr = 0
_queue_before = b""
if _requested_mode and backend in _PRESENT_METHOD_INDEX:
    frontend_module.inbound.Init(getattr(frontend_module.inbound.RenderType, f"D3D{backend[2:]}"))
    _method_addr = frontend_module.inbound.GetMethod(_PRESENT_METHOD_INDEX[backend])
    if backend == "dx12":
        _queue_addr = frontend_module.inbound.GetMethod(54)
_attach_at = float(os.environ.get("DXTEST_ATTACH_AT", "0"))
if _attach_at:
    time.sleep(_attach_at)
if _method_addr:
    _method_before = bytes(Process.current.read_memoryview(_method_addr, 16))
if _queue_addr:
    _queue_before = bytes(Process.current.read_memoryview(_queue_addr, 16))
for attempt in range(50):
    try:
        if _requested_mode and backend in _PRESENT_METHOD_INDEX:
            mode = getattr(nylib.pyimgui.HookMode, {"detours": "Detours", "vtable": "Vtable", "auto": "Auto"}[_requested_mode])
            renderer.Attach(mode)
        else:
            renderer.Attach()
        mark("payload_attached")
        break
    except Exception as exc:
        mark("payload_attach_retry", repr(exc))
        time.sleep(0.2)
else:
    raise RuntimeError(f"failed to attach {backend} inbound renderer")

# Anti-tamper marker: proves an injected run used this worktree's build, not
# a stale main-tree one. Gated like the rest so the default run's marker set
# is unchanged; a harness run sets at least one DXTEST_* var below.
_HARNESS_ENV_VARS = (
    "DXTEST_HOOK_MODE", "DXTEST_ATTACH_AT", "DXTEST_DETACH_AT", "DXTEST_RESIZE_AT",
    "DXTEST_FOREIGN", "DXTEST_DX12_EXTRA_QUEUES", "DXTEST_D3D12_DEBUG",
)
if any(os.environ.get(name) for name in _HARNESS_ENV_VARS):
    mark("nylib_pyimgui_file", str(nylib.pyimgui.__file__))

# Record the selected mode and the full sampled Present prologue around Attach.
if _requested_mode and backend in _PRESENT_METHOD_INDEX:
    method_after = bytes(Process.current.read_memoryview(_method_addr, 16))
    queue_after = bytes(Process.current.read_memoryview(_queue_addr, 16)) if _queue_addr else b""
    mark("hook_mode", f"requested={_requested_mode} selected={renderer.hookMode.name} owner={_module_owner(Process.current, _method_addr)} before={_method_before.hex()} after={method_after.hex()} queue_before={_queue_before.hex()} queue_after={queue_after.hex()}")

# Detach at a fixed elapsed time instead of only at exit, so a foreign hook
# installed earlier (DXTEST_FOREIGN_AT) can be checked across our Detach().
_detach_at = os.environ.get("DXTEST_DETACH_AT")
detached = False
try:
    if _detach_at:
        detach_seconds = float(_detach_at)
        end = time.time() + float(os.environ.get("DXTEST_SECONDS", "10")) + 2.0
        while time.time() < end:
            if not detached and time.time() - _payload_start >= detach_seconds:
                renderer.Detach()
                mark("payload_detached", f"at={time.time() - _payload_start:.1f}s")
                detached = True
            time.sleep(0.05)
    else:
        keep_alive()
finally:
    state.close()
    if not detached:
        renderer.Detach()
