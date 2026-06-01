"""Auto-smoke payload for debug-view v2.

Opens every v2 subwindow programmatically and renders for N frames so
any render-path bug surfaces as a logged exception. Adds a few safe
state mutations (pin/history/session_io). Does NOT click Dump, Scan,
or submit console scripts — those would spawn threads / write files
and pollute the smoke.

Use via:
    inject.py dx11 --test --seconds 15

inject.py picks this file via the DXTEST_PAYLOAD env var when --test is
passed.
"""
from __future__ import annotations

import time
import traceback

from common.payload_common import configure_imports, keep_alive, mark, marker_dir

configure_imports()

import nylib.pyimgui.imgui as imgui
from nylib.pyimgui.imgui import ctx as imgui_ctx

from nylib.process import Process
from nylib import imguiutils
from nylib.imguiutils import DebugViewState


mark("test_started")


_DETECT_ORDER = (
    ("d3d12.dll", "dx12", "Dx12Inbound"),
    ("d3d11.dll", "dx11", "Dx11Inbound"),
    ("d3d9.dll",  "dx9",  "Dx9Inbound"),
)


def _detect_frontend():
    proc = Process.current
    loaded = set()
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
    raise RuntimeError("no D3D runtime detected")


def _host_exe_name():
    proc = Process.current
    return proc.base_ldr_data.BaseDllName.remote_value(proc)


def _resolve_exports(exe_name):
    proc = Process.current
    fn = proc.get_proc_address(exe_name, "dxtest_tick")
    var = proc.get_proc_address(exe_name, "g_dxtest_tick")
    return int(fn), int(var)


backend, InboundCls = _detect_frontend()
exe_name = _host_exe_name()
tick_fn_addr, tick_var_addr = _resolve_exports(exe_name)
mark("test_setup",
     f"backend={backend} exe={exe_name} fn=0x{tick_fn_addr:X} var=0x{tick_var_addr:X}")


state = DebugViewState(
    disasm_cursor=tick_fn_addr,
    hex_cursor=tick_var_addr,
    update_interval_ms=200,
)

# Open every v1.5 + v2 singleton on init. Each is auto-synced via
# _sync_singleton_subwindow in render_debug_view.
state.show_module_panel = True
state.show_bp_panel = True
state.show_address_resolver = True
state.show_pinned_panel = True
state.show_history_panel = True
state.show_pattern_scan = True
state.show_dump_module = True
state.show_python_console = True

# Spawn one multi-instance dialog of each kind for render coverage.
# Search opens with default scope (window).
state.open_search_dialog()
# Run Script needs a real file path; write a tiny stub to the per-run
# marker dir (cleaned by inject.py on each run). NOT executed — the
# dialog just renders the source preview + Run button.
_tmp_script = marker_dir() / "_test_run_script_stub.py"
_tmp_script.write_text(
    "# autosmoke stub - never executed by the test\nprint('would run')\n",
    encoding="utf-8",
)
state.open_run_script_dialog(str(_tmp_script))

# Safe state mutations exercising the v2 nav APIs.
state.pin_address(tick_fn_addr, label="dxtest_tick")
state.pin_address(tick_var_addr, label="g_dxtest_tick")
state.goto_disasm(tick_fn_addr)
state.goto_hex(tick_var_addr)
state.goto_disasm(tick_fn_addr + 0x100)

mark("test_state_initialized",
     f"pinned={len(state.pinned_addresses)} history={len(state.history)} "
     f"subwindows={len(state._subwindows)}")


_frame_counter = [0]
_scheduled = {}  # frame -> bool (done)
_render_errors = []


def _once(frame, name, fn):
    """Run fn() exactly once at the given frame; mark on success, log + mark on failure."""
    key = (frame, name)
    if _frame_counter[0] < frame or _scheduled.get(key):
        return
    _scheduled[key] = True
    try:
        fn()
        mark(f"test_action_{name}")
    except Exception as exc:
        tb = traceback.format_exc()
        mark(f"test_action_{name}_FAILED", f"{type(exc).__name__}: {exc}\n{tb}")


def _toggle_pin():
    state.toggle_pinned(tick_fn_addr)
    state.toggle_pinned(tick_fn_addr)


def _session_io_roundtrip():
    from nylib.imguiutils.debug_view.session_io import to_json, from_json
    text = to_json(state)
    from_json(state, text)


def _open_second_search():
    state.open_search_dialog()


def draw(renderer):
    f = _frame_counter[0]
    _frame_counter[0] += 1
    # Compatibility with inject.py's `drew=` check, which looks for
    # the `payload_drawn` marker. Write it on the first frame so the
    # tooling's success gate works in --test mode too.
    if f == 0:
        mark("payload_drawn")
    try:
        with imgui_ctx.Begin("v2 auto-smoke",
                              flags=imgui.ImGuiWindowFlags_MenuBar) as (show, _open):
            if show:
                imgui.Text(f"frame={f}  backend={backend}")
                imgui.Text(f"pinned={len(state.pinned_addresses)}  "
                            f"history={len(state.history)}  "
                            f"subwindows={len(state._subwindows)}  "
                            f"errors={len(_render_errors)}")
                imguiutils.render_debug_view(state)
        # Drive window_manager (FileDialog / MessageBox).
        imguiutils.window_manager.render()
    except Exception as exc:
        tb = traceback.format_exc()
        _render_errors.append((f, type(exc).__name__, str(exc)))
        mark(f"test_render_error_frame_{f}",
             f"{type(exc).__name__}: {exc}\n{tb}")
    # Scheduled mutations.
    _once(30, "toggle_pin", _toggle_pin)
    _once(60, "session_io_roundtrip", _session_io_roundtrip)
    _once(90, "open_second_search", _open_second_search)
    if f == 120 and not _scheduled.get((120, "ok")):
        _scheduled[(120, "ok")] = True
        if _render_errors:
            mark("test_render_errors_seen",
                 f"{len(_render_errors)} errors; first: {_render_errors[0]}")
        else:
            mark("test_120_frames_no_render_errors")


renderer = InboundCls(draw)
for attempt in range(50):
    try:
        renderer.Attach()
        mark("test_attached")
        break
    except Exception as exc:
        mark("test_attach_retry", repr(exc))
        time.sleep(0.2)
else:
    raise RuntimeError(f"failed to attach {backend} inbound renderer")


try:
    keep_alive()
finally:
    state.close()
    renderer.Detach()
    mark("test_finished",
         f"frames={_frame_counter[0]} render_errors={len(_render_errors)}")
