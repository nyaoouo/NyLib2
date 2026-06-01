"""Programmatic JSON serialize / deserialize of DebugViewState.

No file I/O. No File menu entry. Callers decide where the bytes go.

Schema: see docs/superpowers/specs/2026-05-29-debug-view-v2-design.md s5.2.
"""
from __future__ import annotations

import json
import logging
import typing

from .formats import AddressFormat, MemCellSize, MemFormat

if typing.TYPE_CHECKING:
    from .state import DebugViewState

_SCHEMA = "nylib.debug_view.session"
_VERSION = 1
_log = logging.getLogger("nylib.imguiutils.debug_view.session_io")

# Known top-level keys (used by strict=True unknown-key check).
_KNOWN_KEYS = {"schema", "version", "cursors", "formats", "options",
               "splitter", "pinned", "history"}

# Known options keys.
_KNOWN_OPTIONS = {
    "update_interval_ms",
    "resolve_exports",
    "show_module_panel",
    "show_bp_panel",
    "show_address_resolver",
    "show_pinned_panel",
    "show_history_panel",
    "show_pattern_scan",
    "show_dump_module",
    "show_python_console",
}


def _hex(addr: int) -> str:
    return f"0x{int(addr):X}"


def _parse_addr(value) -> int:
    """Accept either int or hex string. Raises ValueError on garbage."""
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        s = value.strip()
        if s.lower().startswith("0x"):
            return int(s, 16)
        return int(s)
    raise ValueError(f"address must be int or hex string, got {type(value).__name__}")


def to_dict(state: "DebugViewState") -> dict:
    """Serialize navigation-relevant state to a JSON-safe dict."""
    pinned: list[dict] = []
    for entry in getattr(state, "pinned_addresses", []) or []:
        pinned.append({
            "addr": _hex(entry.addr),
            "label": entry.label,
        })
    history_entries = []
    history = getattr(state, "history", []) or []
    for where, addr in list(history):
        history_entries.append([where, _hex(addr)])
    mem_radix = "hex" if state.mem_fmt.radix == "hex" else "dec"
    return {
        "schema": _SCHEMA,
        "version": _VERSION,
        "cursors": {
            "disasm": _hex(state.disasm_cursor),
            "hex": _hex(state.hex_cursor),
            "focused_view": state.focused_view,
        },
        "formats": {
            "address": state.address_fmt.name.lower(),
            "mem": {
                "cell": int(state.mem_fmt.cell),
                "radix": mem_radix,
            },
        },
        "options": {
            "update_interval_ms": int(state.update_interval_ms),
            "resolve_exports": bool(state.resolve_exports),
            "show_module_panel": bool(state.show_module_panel),
            "show_bp_panel": bool(state.show_bp_panel),
            "show_address_resolver": bool(getattr(state, "show_address_resolver", False)),
            "show_pinned_panel": bool(getattr(state, "show_pinned_panel", False)),
            "show_history_panel": bool(getattr(state, "show_history_panel", False)),
            "show_pattern_scan": bool(getattr(state, "show_pattern_scan", False)),
            "show_dump_module": bool(getattr(state, "show_dump_module", False)),
            "show_python_console": bool(getattr(state, "show_python_console", False)),
        },
        "splitter": {
            "top_frac": float(state._splitter_top_frac),
            "mid_h": float(state._splitter_mid_h),
        },
        "pinned": pinned,
        "history": {
            "entries": history_entries,
            "index": int(state.history_idx),
        },
    }


def from_dict(state: "DebugViewState", data: dict, *,
              strict: bool = False) -> None:
    """Apply `data` to `state` in place. Preserves state identity
    (worker / subwindows / recorders all untouched).
    """
    if not isinstance(data, dict):
        raise ValueError(f"data must be dict, got {type(data).__name__}")
    schema = data.get("schema")
    if schema != _SCHEMA:
        raise ValueError(f"schema mismatch: expected {_SCHEMA!r}, got {schema!r}")
    version = data.get("version")
    if version != _VERSION:
        raise ValueError(f"version mismatch: expected {_VERSION}, got {version!r}")

    if strict:
        unknown = set(data.keys()) - _KNOWN_KEYS
        if unknown:
            raise ValueError(f"unknown top-level key(s): {sorted(unknown)}")

    # ----- cursors -----
    cursors = data.get("cursors") or {}
    if "disasm" in cursors:
        try:
            state.disasm_cursor = _parse_addr(cursors["disasm"])
        except (ValueError, TypeError) as exc:
            if strict:
                raise ValueError(f"cursors.disasm: {exc}")
    if "hex" in cursors:
        try:
            state.hex_cursor = _parse_addr(cursors["hex"])
        except (ValueError, TypeError) as exc:
            if strict:
                raise ValueError(f"cursors.hex: {exc}")
    if "focused_view" in cursors:
        fv = cursors["focused_view"]
        if fv in ("disasm", "hex", None):
            state.focused_view = fv
        elif strict:
            raise ValueError(f"cursors.focused_view: invalid {fv!r}")

    # ----- formats -----
    formats = data.get("formats") or {}
    if "address" in formats:
        try:
            state.address_fmt = AddressFormat[formats["address"].upper()]
        except (KeyError, AttributeError) as exc:
            if strict:
                raise ValueError(f"formats.address: {exc}")
    mem = formats.get("mem") if isinstance(formats.get("mem"), dict) else {}
    cell = mem.get("cell")
    radix = mem.get("radix")
    if cell is not None or radix is not None:
        try:
            new_cell = MemCellSize(int(cell)) if cell is not None else state.mem_fmt.cell
            new_radix = radix if radix in ("hex", "dec") else state.mem_fmt.radix
            state.mem_fmt = MemFormat(new_cell, new_radix)
        except (ValueError, TypeError) as exc:
            if strict:
                raise ValueError(f"formats.mem: {exc}")

    # ----- options -----
    options = data.get("options") or {}
    if strict:
        unknown_opts = set(options.keys()) - _KNOWN_OPTIONS
        if unknown_opts:
            raise ValueError(f"unknown option key(s): {sorted(unknown_opts)}")
    for key in _KNOWN_OPTIONS:
        if key not in options:
            continue
        try:
            value = options[key]
            if key == "update_interval_ms":
                state.update_interval_ms = max(10, int(value))
            else:
                setattr(state, key, bool(value))
        except (ValueError, TypeError) as exc:
            if strict:
                raise ValueError(f"options.{key}: {exc}")

    # ----- splitter -----
    splitter = data.get("splitter") or {}
    if "top_frac" in splitter:
        try:
            state._splitter_top_frac = float(splitter["top_frac"])
        except (ValueError, TypeError) as exc:
            if strict:
                raise ValueError(f"splitter.top_frac: {exc}")
    if "mid_h" in splitter:
        try:
            state._splitter_mid_h = float(splitter["mid_h"])
        except (ValueError, TypeError) as exc:
            if strict:
                raise ValueError(f"splitter.mid_h: {exc}")

    # ----- pinned -----
    pinned_in = data.get("pinned")
    if pinned_in is not None:
        try:
            from .nav.pinned import PinnedEntry
        except ImportError:
            PinnedEntry = None
        new_pinned = []
        new_set = set()
        for i, entry in enumerate(pinned_in):
            try:
                addr = _parse_addr(entry["addr"])
                label = entry.get("label")
                if PinnedEntry is not None:
                    new_pinned.append(PinnedEntry(addr=addr, label=label))
                new_set.add(addr)
            except (KeyError, ValueError, TypeError) as exc:
                if strict:
                    raise ValueError(f"pinned[{i}]: {exc}")
                _log.warning("session_io: skipping pinned[%d]: %s", i, exc)
        if hasattr(state, "pinned_addresses"):
            state.pinned_addresses = new_pinned
        if hasattr(state, "_pinned_set"):
            state._pinned_set = new_set

    # ----- history -----
    history = data.get("history") or {}
    entries = history.get("entries")
    if entries is not None:
        new_entries = []
        for i, item in enumerate(entries):
            try:
                where, addr = item[0], _parse_addr(item[1])
                if where not in ("disasm", "hex"):
                    raise ValueError(f"bad where {where!r}")
                new_entries.append((where, addr))
            except (IndexError, ValueError, TypeError, KeyError) as exc:
                if strict:
                    raise ValueError(f"history.entries[{i}]: {exc}")
                _log.warning("session_io: skipping history[%d]: %s", i, exc)
        # Replace history in place, preserving deque if present.
        import collections
        if isinstance(state.history, collections.deque):
            state.history.clear()
            state.history.extend(new_entries)
        else:
            state.history = new_entries
    if "index" in history:
        try:
            state.history_idx = int(history["index"])
        except (ValueError, TypeError) as exc:
            if strict:
                raise ValueError(f"history.index: {exc}")


def to_json(state: "DebugViewState") -> str:
    return json.dumps(to_dict(state), indent=2)


def from_json(state: "DebugViewState", text: str, *,
              strict: bool = False) -> None:
    from_dict(state, json.loads(text), strict=strict)


__all__ = ["to_dict", "from_dict", "to_json", "from_json"]
