"""DebugViewState - caller-owned typed state container.

Owns the per-view MemWorker. Render code reads state attributes; user
code mutates state via control methods (goto_*, sync_*, back/forward,
close, ...). All mutations from user code are safe; the worker reads
state attributes opportunistically (a torn read just produces one extra
frame of staleness).
"""
from __future__ import annotations

import collections
import dataclasses
import itertools
import typing

if typing.TYPE_CHECKING:
    from .bp.dialog import BpPrefill

from .formats import AddressFormat, MemCellSize, MemFormat
from .module_cache import ModuleResolver
from .worker import MemWorker

_uid_counter = itertools.count(1)


def find_breakpoint_by_handle(handle: int):
    """Look up a BP by handle in the global registry. Returns None if not found."""
    from nylib.winutils.breakpoint import list_breakpoints
    for bp in list_breakpoints():
        if bp.handle == handle:
            return bp
    return None

_NULL_GUARD = 0x1000   # reject goto below this; avoids tripping NULL guard pages


@dataclasses.dataclass
class DebugViewState:
    disasm_cursor: int = 0
    hex_cursor: int = 0
    focused_view: typing.Literal["disasm", "hex", None] = None
    address_fmt: AddressFormat = AddressFormat.HEX
    mem_fmt: MemFormat = dataclasses.field(
        default_factory=lambda: MemFormat(MemCellSize.U8, "hex")
    )
    update_interval_ms: int = 200
    disasm_pre_bytes: int = 0          # cursor row is the FIRST decoded
    disasm_post_bytes: int = 0x200
    disasm_window_max: int = 0x4000
    hex_pre_bytes: int = 0             # cursor is the FIRST row shown
    hex_post_bytes: int = 0x400
    hex_window_max: int = 0x4000
    history: typing.Any = dataclasses.field(
        default_factory=lambda: collections.deque(maxlen=1024),
    )
    history_idx: int = -1
    show_module_panel: bool = False
    show_bp_panel: bool = False
    default_bp_stack_frames: int = 32
    default_bp_backend: typing.Literal["veh", "debugger"] = "veh"
    # When True, the module cache also walks each module's PE export
    # table (lazily, on first per-module lookup). Default is OFF for
    # perf: PE export walks across a typical process's 50-200 modules
    # add measurable cost. The user flips it on via View -> "Resolve
    # exports" when they want richer module:export+offset attribution
    # in stack tooltips and the address resolver tool.
    resolve_exports: bool = False
    show_address_resolver: bool = False
    show_pinned_panel: bool = False
    show_history_panel: bool = False
    show_pattern_scan: bool = False
    show_dump_module: bool = False
    show_python_console: bool = False
    _uid: int = dataclasses.field(init=False, default=0)
    _worker: typing.Any = dataclasses.field(init=False, default=None, repr=False)
    _module_resolver: ModuleResolver = dataclasses.field(
        init=False, default=None, repr=False,
    )
    _wm_handles: dict[str, int] = dataclasses.field(init=False, default_factory=dict, repr=False)
    _closed: bool = dataclasses.field(init=False, default=False)
    _subwindows: list = dataclasses.field(init=False, default_factory=list, repr=False)
    bp_recorders: dict[int, typing.Any] = dataclasses.field(
        init=False, default_factory=dict, repr=False,
    )
    _dialog_counter: int = dataclasses.field(init=False, default=0, repr=False)
    pinned_addresses: list = dataclasses.field(
        init=False, default_factory=list, repr=False,
    )
    _pinned_set: set = dataclasses.field(
        init=False, default_factory=set, repr=False,
    )
    _splitter_top_h: float = 240.0
    _splitter_top_frac: float = 0.5    # disasm pane fraction of (avail - _splitter_mid_h); hex gets the rest
    _splitter_mid_h: float = 24.0
    _extend_down: bool = dataclasses.field(init=False, default=False)
    _copy_log: collections.deque = dataclasses.field(
        init=False, default_factory=lambda: collections.deque(maxlen=16), repr=False,
    )

    # ----- lifecycle -----

    def __post_init__(self) -> None:
        self._uid = next(_uid_counter)
        self._module_resolver = ModuleResolver(
            resolve_exports=self.resolve_exports)
        self._worker = MemWorker(self)
        self._worker.start()

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        # Notify subwindows (best-effort; never raise) then clear.
        for sw in list(self._subwindows):
            try:
                sw.on_close(self)
            except Exception:
                pass
        self._subwindows.clear()
        # Clear recorder bookkeeping (BPs themselves stay installed
        # in the global registry per spec section 6.7).
        self.bp_recorders.clear()
        # Stop the worker last.
        try:
            self._worker.stop(timeout=2.0)
        except Exception:
            pass

    def __enter__(self) -> "DebugViewState":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def __del__(self):                              # best-effort cleanup
        try:
            self.close()
        except Exception:
            pass

    # ----- control methods -----

    @property
    def worker_tid(self) -> int:
        return getattr(self._worker, "tid", 0)

    @property
    def module_resolver(self) -> ModuleResolver:
        """Cached module-base/size + export lookup. Shared across all
        rendering within this DebugViewState (one per view = one cache)."""
        return self._module_resolver

    def set_resolve_exports(self, enabled: bool) -> None:
        """Live-toggle export resolution. Mirrors the bool onto the
        underlying ModuleResolver, which drops its export caches when
        flipped off (so the next 'on' rebuild is fresh and lazy)."""
        self.resolve_exports = bool(enabled)
        if self._module_resolver is not None:
            self._module_resolver.set_resolve_exports(self.resolve_exports)

    def request_refresh(self) -> None:
        if self._worker is not None:
            self._worker.request_refresh()

    def _next_dialog_id(self) -> int:
        """Return a fresh monotonic dialog id for subwindow titles."""
        self._dialog_counter += 1
        return self._dialog_counter

    def toggle_bp_panel(self) -> None:
        """Toggle the BP manager panel singleton."""
        self.show_bp_panel = not self.show_bp_panel

    def pin_address(self, addr: int, label: str | None = None) -> None:
        """Pin `addr`, creating a new PinnedEntry or updating the
        existing one's label.

        Idempotent on the address; if already pinned, only the label
        is updated."""
        addr = int(addr)
        for entry in self.pinned_addresses:
            if entry.addr == addr:
                entry.label = label
                return
        from .nav.pinned import PinnedEntry
        self.pinned_addresses.append(PinnedEntry(addr=addr, label=label))
        self._pinned_set.add(addr)

    def unpin_address(self, addr: int) -> bool:
        """Remove the pinned entry for `addr`. Returns True if removed,
        False if not present."""
        addr = int(addr)
        for i, entry in enumerate(self.pinned_addresses):
            if entry.addr == addr:
                del self.pinned_addresses[i]
                self._pinned_set.discard(addr)
                return True
        return False

    def is_pinned(self, addr: int) -> bool:
        """O(1) pin check via the mirror set."""
        return int(addr) in self._pinned_set

    def toggle_pinned(self, addr: int,
                      label: str | None = None) -> bool:
        """Flip the pinned state for `addr`. Returns True if now
        pinned, False if now unpinned."""
        if self.is_pinned(addr):
            self.unpin_address(addr)
            return False
        self.pin_address(addr, label=label)
        return True

    def install_bp(self, address: int, size: int, flag: int, *,
                   backend: str | None = None,
                   stack_frames: int | None = None,
                   tids: typing.Sequence[int] | None = None,
                   user_callback: typing.Callable | None = None,
                   ) -> typing.Any:
        """Install a BP attached to a fresh BpHitRecorder + BpHitWindow.

        Returns the underlying nylib.winutils.breakpoint.BreakPoint.
        Raises on install failure (caller's dialog renders the error).
        """
        from nylib.winutils.breakpoint import BreakPoint
        from .bp.recorder import BpHitRecorder
        from .bp.hit_window import BpHitWindow

        recorder = BpHitRecorder(
            state=self, user_callback=user_callback,
            stack_frames=stack_frames if stack_frames is not None
                                       else self.default_bp_stack_frames,
        )
        bp = BreakPoint(
            address, size, recorder, flag,
            backend=backend if backend is not None else self.default_bp_backend,
            tids=tids,
        )
        bp.install()  # raises on failure - caller handles
        self.bp_recorders[bp.handle] = recorder
        self._subwindows.append(BpHitWindow(bp=bp, recorder=recorder))
        return bp

    def uninstall_bp(self, handle: int) -> bool:
        """Uninstall the BP with this handle. Returns True if the recorder
        was known to this view (BP existed and was uninstalled), False
        otherwise. Idempotent: a missing handle returns False without
        raising."""
        from .subwindow import remove_subwindow

        recorder = self.bp_recorders.pop(handle, None)
        if recorder is None:
            return False
        bp = find_breakpoint_by_handle(handle)
        if bp is not None:
            try:
                bp.uninstall()
            except Exception:
                pass
        remove_subwindow(self, f"bp_hit_{handle}")
        return True

    def detach_bp_hit_window(self, handle: int) -> bool:
        """Uninstall the BP from the global registry; keep the recorder
        and hit window so accumulated hits remain visible.

        After detach: the BP no longer fires (no new hits), the recorder
        no longer grows, but the existing hit history is preserved in the
        window. The X button on the hit window will fully clean up.

        Returns True if a BP with this handle was found and uninstalled,
        False otherwise. Idempotent: calling on an already-uninstalled
        handle returns False.
        """
        bp = find_breakpoint_by_handle(handle)
        if bp is None:
            return False
        try:
            bp.uninstall()
        except Exception:
            return False
        return True

    def reopen_bp_hit_window(self, handle: int) -> bool:
        """Push a fresh BpHitWindow for `handle` if one is missing.

        Returns True if a window was added, False if the recorder is
        unknown or a window is already present."""
        from .bp.hit_window import BpHitWindow
        from .subwindow import find_subwindow

        recorder = self.bp_recorders.get(handle)
        if recorder is None:
            return False
        if find_subwindow(self, f"bp_hit_{handle}") is not None:
            return False
        bp = find_breakpoint_by_handle(handle)
        if bp is None:
            return False
        self._subwindows.append(BpHitWindow(bp=bp, recorder=recorder))
        return True

    def push_history(self, where: typing.Literal["disasm", "hex"], addr: int) -> None:
        # Truncate forward entries beyond current idx (browser-style).
        # Deque doesn't support slice deletion; manual pop is required.
        if self.history_idx >= 0 and self.history_idx < len(self.history) - 1:
            while len(self.history) > self.history_idx + 1:
                self.history.pop()
        self.history.append((where, int(addr)))
        # deque auto-drops the leftmost when at maxlen; index clamps to
        # the new last position.
        self.history_idx = len(self.history) - 1

    def goto_disasm(self, addr: int, *, record: bool = True) -> None:
        addr = int(addr)
        if addr < _NULL_GUARD:
            return
        self.disasm_cursor = addr
        self.disasm_pre_bytes = self.__class__.disasm_pre_bytes
        self.disasm_post_bytes = self.__class__.disasm_post_bytes
        if record:
            self.push_history("disasm", addr)
        self.request_refresh()

    def goto_hex(self, addr: int, *, record: bool = True) -> None:
        addr = int(addr)
        if addr < _NULL_GUARD:
            return
        self.hex_cursor = addr
        self.hex_pre_bytes = self.__class__.hex_pre_bytes
        self.hex_post_bytes = self.__class__.hex_post_bytes
        if record:
            self.push_history("hex", addr)
        self.request_refresh()

    def sync_disasm_to_hex(self) -> None:
        self.goto_hex(self.disasm_cursor)

    def sync_hex_to_disasm(self) -> None:
        self.goto_disasm(self.hex_cursor)

    def back(self) -> bool:
        if self.history_idx <= 0:
            return False
        self.history_idx -= 1
        where, addr = self.history[self.history_idx]
        if where == "disasm":
            self.goto_disasm(addr, record=False)
        else:
            self.goto_hex(addr, record=False)
        return True

    def forward(self) -> bool:
        if self.history_idx >= len(self.history) - 1:
            return False
        self.history_idx += 1
        where, addr = self.history[self.history_idx]
        if where == "disasm":
            self.goto_disasm(addr, record=False)
        else:
            self.goto_hex(addr, record=False)
        return True

    def open_bp_dialog(self, prefill: "BpPrefill | None" = None) -> None:
        """Push a fresh BpDialog onto _subwindows, optionally prefilled."""
        from .bp.dialog import BpDialog, BpPrefill
        if prefill is None:
            prefill = BpPrefill(
                backend=self.default_bp_backend,
                stack_frames=self.default_bp_stack_frames,
            )
        else:
            # Honor the prefill's existing backend/stack_frames if set,
            # otherwise inherit from state defaults.
            if prefill.backend == "veh" and self.default_bp_backend != "veh":
                prefill.backend = self.default_bp_backend
            if prefill.stack_frames == 32:
                prefill.stack_frames = self.default_bp_stack_frames
        self._subwindows.append(
            BpDialog(prefill=prefill, dialog_id=self._next_dialog_id()))

    def open_search_dialog(self, *, scope=None, pattern: str = "") -> None:
        """Push a fresh InViewSearchDialog onto _subwindows."""
        from .tools.search import InViewSearchDialog
        self._subwindows.append(InViewSearchDialog(
            dialog_id=self._next_dialog_id(),
            initial_scope=scope, initial_pattern=pattern,
        ))

    def open_run_script_dialog(self, path: str) -> None:
        """Push a fresh RunScriptDialog onto _subwindows."""
        from .tools.run_script import RunScriptDialog
        self._subwindows.append(RunScriptDialog(
            dialog_id=self._next_dialog_id(),
            path=path,
        ))

    def open_hex_editor(self, *, addr: int, current: bytes,
                        cell_bytes: int) -> None:
        """Push a HexEditDialog onto _subwindows for the cell at `addr`."""
        from .edit.hex import HexEditDialog
        self._subwindows.append(HexEditDialog(
            dialog_id=self._next_dialog_id(),
            addr=addr, cell_bytes=cell_bytes,
            current=current, mem_fmt=self.mem_fmt,
        ))

    def open_asm_editor(self, *, addr: int, original_size: int,
                        original_text: str) -> None:
        """Push an AsmEditDialog onto _subwindows for the instruction."""
        from .edit.asm import AsmEditDialog
        self._subwindows.append(AsmEditDialog(
            dialog_id=self._next_dialog_id(),
            addr=addr, original_size=original_size,
            original_text=original_text,
        ))

    def set_update_interval(self, ms: int) -> None:
        self.update_interval_ms = max(10, int(ms))


__all__ = ["DebugViewState"]
