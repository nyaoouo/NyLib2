"""Cached module-base/size + export-table lookup.

The naive path - walk `Process.current.enum_ldr_data()` per query, plus
re-walk the export directory of every module each time - is fine for a
one-off goto-box parse but expensive when a render frame needs to
format hundreds of stack frames as `module:export+offset`. This module
provides a `ModuleResolver` that:

- Snapshots all loaded modules into a sorted `(base, end, name)` array.
  Module list refresh is throttled to `refresh_interval_s` seconds.
- Loads each module's export table LAZILY on first lookup; the result
  is cached per-base until the module disappears from the next snapshot.
- Answers `lookup(addr) -> (name, offset)` in O(log N) via bisect.
- Answers `lookup_export(addr) -> (mod, sym, offset)` in
  O(log N + log M) where M is exports-per-module. Returns None when no
  export "owns" the address - the offset cap is the smaller of the
  next export's RVA and `max_export_offset`. This stops nonsense
  renderings like `mygame.exe:winmain+0x10000` when WinMain is the
  module's only export and the address is actually in some other
  function 64 KB later.
- Answers `base_of(name)` / `export_addr(mod, sym)` in O(1).
- Thread-safe: a single lock guards snapshot read/write + the per-base
  export cache.

The resolver fails open: any per-module export read failure (bad PE,
unmapped memory) leaves an empty export list for that base. A lookup
that misses returns None and callers fall back to plain module+offset
or raw hex.

Config knobs (constructor-only, but `set_resolve_exports` allows live
toggling):
    resolve_exports     - master switch; when False, export caches stay
                          empty and lookup_export / export_addr always
                          return None. Cheap.
    max_export_offset   - upper bound on offset-from-export when the
                          module has only sparse exports. Default 0x10000
                          (64 KB) which fits most functions but rejects
                          obviously-wrong attributions.
    refresh_interval_s  - module-list re-enumeration throttle.
"""
from __future__ import annotations

import bisect
import threading
import time
import typing


REFRESH_INTERVAL_S = 1.0
MAX_EXPORT_OFFSET = 0x10000


class ModuleResolver:
    """Thread-safe cached lookup of loaded-module ranges + per-module
    export tables.

    `proc` is optional; when omitted, `Process.current` is enumerated.
    Tests can pass a stub with an `enum_ldr_data()` method that yields
    objects with `DllBase`, `SizeOfImage`, and a `BaseDllName` whose
    `.remote_value(proc)` returns the module's base name.

    Tests can also inject a fake `read_exports(base)` callable via the
    keyword-only `_read_exports` argument so unit tests don't have to
    fabricate a real PE in memory.
    """

    def __init__(self, proc: typing.Any = None,
                 refresh_interval_s: float = REFRESH_INTERVAL_S,
                 resolve_exports: bool = True,
                 max_export_offset: int = MAX_EXPORT_OFFSET,
                 *,
                 _read_exports: typing.Callable[[int], typing.Any] | None = None,
                 ) -> None:
        self._proc = proc
        self._refresh_interval_s = float(refresh_interval_s)
        self._resolve_exports = bool(resolve_exports)
        self._max_export_offset = int(max_export_offset)
        self._lock = threading.Lock()
        # Module-list snapshot. Parallel arrays sorted by base.
        self._bases: list[int] = []
        self._ends: list[int] = []
        self._names: list[str] = []
        # Lowercase-name -> base for O(1) `base_of`.
        self._name_to_base: dict[str, int] = {}
        # Per-base export caches; keyed by base (not name) so two
        # modules with the same name don't collide and to make
        # invalidation natural (unload -> base disappears).
        #   _exports_by_addr[base] = sorted [(rva, sym), ...]
        #   _exports_by_name[base] = {sym_lower: rva}
        self._exports_by_addr: dict[int, list[tuple[int, str]]] = {}
        self._exports_by_name: dict[int, dict[str, int]] = {}
        self._last_refresh_t = 0.0
        self._refresh_count = 0
        self._export_load_count = 0
        # Read-exports injection point. Late binding so importing this
        # module doesn't force a winutils import chain in pure-Python
        # test environments.
        self._read_exports_fn: typing.Callable[[int], typing.Any] | None = _read_exports

    # ----- public api -----

    def lookup(self, addr: int) -> tuple[str, int] | None:
        """Return (module_name, offset_into_module) for `addr`, or None
        when no loaded module contains it."""
        with self._lock:
            self._maybe_refresh()
            return self._lookup_locked(int(addr))

    def base_of(self, name: str) -> int | None:
        """Return the base address of the module named `name`
        (case-insensitive), or None when not loaded."""
        with self._lock:
            self._maybe_refresh()
            return self._name_to_base.get(name.lower())

    def size_of(self, name: str) -> int | None:
        """Return the size (image size) of the module named `name`
        (case-insensitive), or None when not loaded."""
        with self._lock:
            self._maybe_refresh()
            base = self._name_to_base.get(name.lower())
            if base is None:
                return None
            try:
                idx = self._bases.index(base)
            except ValueError:
                return None
            return self._ends[idx] - self._bases[idx]

    def modules_snapshot(self) -> list[dict]:
        """Return a list of dicts describing the currently-loaded modules.
        Each dict has keys: name, base, size. Sorted by base."""
        with self._lock:
            self._maybe_refresh()
            return [
                {"name": self._names[i],
                 "base": self._bases[i],
                 "size": self._ends[i] - self._bases[i]}
                for i in range(len(self._bases))
            ]

    def lookup_export(self, addr: int) -> tuple[str, str, int] | None:
        """Return (module_name, export_name, offset_from_export) for
        `addr`, or None when:
          - the address is not inside any loaded module;
          - export resolution is disabled;
          - the containing module has no exports; or
          - the offset from the nearest preceding export would exceed
            the bound (next-export RVA, capped by `max_export_offset`).
        The "no nearest export" condition is the user-reported guard
        against attributions like `xxx.exe:winmain+0x10000` when the
        address really isn't WinMain anymore.
        """
        with self._lock:
            self._maybe_refresh()
            if not self._resolve_exports:
                return None
            mod = self._lookup_locked(int(addr))
            if mod is None:
                return None
            mod_name, mod_off = mod
            # The bisect on _bases above already located the module;
            # re-derive its base from name_to_base for the export cache
            # key (cheap dict lookup).
            base = self._name_to_base.get(mod_name.lower())
            if base is None:
                return None
            self._ensure_exports_loaded_locked(base)
            exports = self._exports_by_addr.get(base, [])
            if not exports:
                return None
            rvas = [e[0] for e in exports]
            ex_idx = bisect.bisect_right(rvas, mod_off) - 1
            if ex_idx < 0:
                return None
            ex_rva, ex_name = exports[ex_idx]
            offset = mod_off - ex_rva
            # Bound: distance to next export, or max_export_offset when
            # this is the last export in the module.
            if ex_idx + 1 < len(exports):
                bound = exports[ex_idx + 1][0] - ex_rva
            else:
                bound = self._max_export_offset
            if offset > bound:
                return None
            return mod_name, ex_name, offset

    def exports_in_page(self, addr: int,
                          page_size: int = 0x1000
                          ) -> list[tuple[str, int, int]]:
        """Return all exports of the module containing `addr` whose
        absolute address falls in the same `page_size`-aligned page.

        Each entry is `(name, abs_addr, signed_offset_from_addr)`,
        sorted by absolute distance from `addr` (nearest first). When
        export resolution is disabled, the address isn't in any module,
        or that module exports nothing in the page, returns []."""
        with self._lock:
            self._maybe_refresh()
            if not self._resolve_exports:
                return []
            mod = self._lookup_locked(int(addr))
            if mod is None:
                return []
            mod_name, _mod_off = mod
            base = self._name_to_base.get(mod_name.lower())
            if base is None:
                return []
            self._ensure_exports_loaded_locked(base)
            exports = self._exports_by_addr.get(base, [])
            if not exports:
                return []
            page_mask = ~(int(page_size) - 1) & 0xFFFFFFFFFFFFFFFF
            page_start = int(addr) & page_mask
            page_end = page_start + int(page_size)
            out: list[tuple[str, int, int]] = []
            for rva, name in exports:
                abs_addr = base + rva
                if page_start <= abs_addr < page_end:
                    out.append((name, abs_addr, abs_addr - int(addr)))
            out.sort(key=lambda t: abs(t[2]))
            return out

    def export_addr(self, mod_name: str, sym_name: str) -> int | None:
        """Return the absolute address of module `mod_name`'s export
        `sym_name` (both case-insensitive), or None when the module
        isn't loaded, the symbol isn't exported, or export resolution
        is disabled."""
        with self._lock:
            self._maybe_refresh()
            if not self._resolve_exports:
                return None
            base = self._name_to_base.get(mod_name.lower())
            if base is None:
                return None
            self._ensure_exports_loaded_locked(base)
            rva = self._exports_by_name.get(base, {}).get(sym_name.lower())
            if rva is None:
                return None
            return base + rva

    def invalidate(self) -> None:
        """Force a refresh on the next query. Does NOT drop cached
        export tables; they're invalidated only when a module
        disappears from the next snapshot (their base no longer
        matches)."""
        with self._lock:
            self._last_refresh_t = 0.0

    def set_resolve_exports(self, enabled: bool) -> None:
        """Live-toggle the export resolution. When turned off, in-flight
        and future lookups return None for the export form; the module
        list is unaffected. When turned back on, export tables are
        re-loaded lazily on first lookup per module."""
        with self._lock:
            self._resolve_exports = bool(enabled)
            if not self._resolve_exports:
                # Drop cached exports to free memory; they re-load
                # lazily next time the flag flips back on.
                self._exports_by_addr.clear()
                self._exports_by_name.clear()

    def resolve_exports(self) -> bool:
        with self._lock:
            return self._resolve_exports

    def refresh_count(self) -> int:
        """Number of times the module-list snapshot has been
        (re)populated. For tests + diagnostics."""
        with self._lock:
            return self._refresh_count

    def export_load_count(self) -> int:
        """Number of per-module export-table walks performed (lazy)."""
        with self._lock:
            return self._export_load_count

    def __len__(self) -> int:
        with self._lock:
            return len(self._bases)

    # ----- internals -----

    def _lookup_locked(self, addr: int) -> tuple[str, int] | None:
        if not self._bases:
            return None
        idx = bisect.bisect_right(self._bases, addr) - 1
        if idx < 0:
            return None
        base = self._bases[idx]
        end = self._ends[idx]
        if addr >= end:
            return None
        return self._names[idx], addr - base

    def _maybe_refresh(self) -> None:
        """Caller must hold the lock."""
        now = time.monotonic()
        if (self._last_refresh_t != 0.0
                and now - self._last_refresh_t < self._refresh_interval_s):
            return
        self._refresh_locked()
        self._last_refresh_t = now

    def _refresh_locked(self) -> None:
        """Caller must hold the lock. Replaces the snapshot atomically.
        Drops cached export tables for modules that no longer exist."""
        proc = self._proc
        if proc is None:
            from nylib.process import Process
            proc = Process.current
        try:
            entries = list(proc.enum_ldr_data())
        except Exception:
            return    # keep previous snapshot
        triples: list[tuple[int, int, str]] = []
        for entry in entries:
            try:
                base = int(entry.DllBase or 0)
                size = int(entry.SizeOfImage or 0)
                name = entry.BaseDllName.remote_value(proc)
            except Exception:
                continue
            if base and size and name:
                triples.append((base, base + size, name))
        triples.sort(key=lambda t: t[0])
        self._bases = [t[0] for t in triples]
        self._ends = [t[1] for t in triples]
        self._names = [t[2] for t in triples]
        self._name_to_base = {t[2].lower(): t[0] for t in triples}
        # Drop cached exports for modules that disappeared.
        live_bases = {t[0] for t in triples}
        for stale_base in [b for b in self._exports_by_addr if b not in live_bases]:
            self._exports_by_addr.pop(stale_base, None)
            self._exports_by_name.pop(stale_base, None)
        self._refresh_count += 1

    def _ensure_exports_loaded_locked(self, base: int) -> None:
        """Caller must hold the lock. Loads (and caches) the export
        table of the module at `base` on first access. Subsequent calls
        for the same `base` are O(1) until the module is unloaded."""
        if base in self._exports_by_addr:
            return
        if self._read_exports_fn is None:
            # Late-bind the real walker. Failure to import keeps the
            # cache empty - lookups simply return None.
            try:
                from nylib.winutils.pe_exports import read_exports
                self._read_exports_fn = read_exports
            except Exception:
                self._exports_by_addr[base] = []
                self._exports_by_name[base] = {}
                self._export_load_count += 1
                return
        try:
            entries = self._read_exports_fn(base) or []
        except Exception:
            entries = []
        addr_list: list[tuple[int, str]] = []
        name_map: dict[str, int] = {}
        for e in entries:
            # `read_exports` returns Export(rva, name, ordinal, address, forwarder).
            # Skip forwarders (their "rva" points to a string, not code).
            forwarder = getattr(e, "forwarder", "") or ""
            if forwarder:
                continue
            rva = int(getattr(e, "rva", 0) or 0)
            if rva <= 0:
                continue
            sym_name = getattr(e, "name", "") or ""
            ordinal = int(getattr(e, "ordinal", 0) or 0)
            display = sym_name if sym_name else f"#ord{ordinal}"
            addr_list.append((rva, display))
            if sym_name:
                name_map[sym_name.lower()] = rva
        addr_list.sort(key=lambda x: x[0])
        self._exports_by_addr[base] = addr_list
        self._exports_by_name[base] = name_map
        self._export_load_count += 1


__all__ = [
    "ModuleResolver",
    "REFRESH_INTERVAL_S",
    "MAX_EXPORT_OFFSET",
]
