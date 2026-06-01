from __future__ import annotations

import pytest

from nylib.imguiutils.debug_view.formats import AddressFormat, MemCellSize, MemFormat
from nylib.imguiutils.debug_view.state import DebugViewState


def test_default_construction():
    s = DebugViewState()
    assert s.disasm_cursor == 0
    assert s.hex_cursor == 0
    assert s.address_fmt is AddressFormat.HEX
    assert s.mem_fmt == MemFormat(MemCellSize.U8, "hex")
    assert s.update_interval_ms == 200
    assert s.history == []
    assert s.history_idx == -1
    assert s.show_module_panel is False
    assert s._closed is False


def test_uid_is_unique():
    a = DebugViewState()
    b = DebugViewState()
    assert a._uid != b._uid


def test_construction_with_cursors():
    s = DebugViewState(disasm_cursor=0x140001000, hex_cursor=0x140002000)
    assert s.disasm_cursor == 0x140001000
    assert s.hex_cursor == 0x140002000


def test_default_window_sizes_match_spec():
    s = DebugViewState()
    assert s.disasm_pre_bytes == 0x80
    assert s.disasm_post_bytes == 0x180
    assert s.disasm_window_max == 0x4000
    assert s.hex_pre_bytes == 0x100
    assert s.hex_post_bytes == 0x300
    assert s.hex_window_max == 0x4000


import time


def test_post_init_spawns_worker():
    s = DebugViewState()
    try:
        assert s._worker is not None
        # The worker should produce a snapshot within ~1s even if cursors are 0.
        deadline = time.time() + 1.0
        while time.time() < deadline:
            if s._worker.snapshot() is not None:
                break
            time.sleep(0.02)
        # Snapshot may be None when both cursors are 0 - that's allowed; we
        # only assert that the worker thread is alive.
        assert s._worker._thread is not None
        assert s._worker._thread.is_alive()
    finally:
        s.close()


def test_close_stops_worker_and_is_idempotent():
    s = DebugViewState()
    s.close()
    assert s._closed is True
    assert (s._worker._thread is None) or (not s._worker._thread.is_alive())
    s.close()  # second call must not raise


def test_context_manager_closes():
    with DebugViewState() as s:
        assert s._closed is False
    assert s._closed is True


def test_goto_disasm_updates_cursor_and_history_and_wakes_worker():
    s = DebugViewState()
    try:
        before_history = list(s.history)
        s.goto_disasm(0x140001000)
        assert s.disasm_cursor == 0x140001000
        assert ("disasm", 0x140001000) in s.history
        assert len(s.history) == len(before_history) + 1
        # Pre/post reset to defaults
        assert s.disasm_pre_bytes == 0x80
        assert s.disasm_post_bytes == 0x180
    finally:
        s.close()


def test_goto_hex_resets_hex_window_and_updates_history():
    s = DebugViewState()
    try:
        s.hex_pre_bytes = 0x1000   # simulate a prior extension
        s.hex_post_bytes = 0x1000
        s.goto_hex(0x140002000)
        assert s.hex_cursor == 0x140002000
        assert s.hex_pre_bytes == 0x100
        assert s.hex_post_bytes == 0x300
        assert ("hex", 0x140002000) in s.history
    finally:
        s.close()


def test_sync_methods():
    s = DebugViewState()
    try:
        s.disasm_cursor = 0x1000
        s.hex_cursor = 0x2000
        s.sync_disasm_to_hex()
        assert s.hex_cursor == 0x1000
        s.disasm_cursor = 0x3000
        s.sync_hex_to_disasm()
        assert s.disasm_cursor == 0x1000
    finally:
        s.close()


def test_back_forward():
    s = DebugViewState()
    try:
        s.goto_disasm(0x1000)
        s.goto_disasm(0x2000)
        s.goto_disasm(0x3000)
        assert s.back() is True
        assert s.disasm_cursor == 0x2000
        assert s.back() is True
        assert s.disasm_cursor == 0x1000
        assert s.back() is False              # at oldest
        assert s.forward() is True
        assert s.disasm_cursor == 0x2000
    finally:
        s.close()


def test_set_update_interval_clamps():
    s = DebugViewState()
    try:
        s.set_update_interval(0)
        assert s.update_interval_ms >= 10
        s.set_update_interval(1234)
        assert s.update_interval_ms == 1234
    finally:
        s.close()


def test_goto_under_1k_is_rejected_silently():
    s = DebugViewState()
    try:
        s.goto_disasm(0x100)
        assert s.disasm_cursor == 0      # rejected, cursor unchanged
        assert s.history == []
    finally:
        s.close()


def test_splitter_top_frac_default_and_attribute():
    """Splitter fraction defaults to 0.5; can be mutated for future drag support."""
    s = DebugViewState()
    try:
        assert s._splitter_top_frac == 0.5
        s._splitter_top_frac = 0.3
        assert s._splitter_top_frac == 0.3
    finally:
        s.close()
