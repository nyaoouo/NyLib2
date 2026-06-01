"""Shared script-exec infrastructure for the Python console + run-script
dialogs.

The per-thread stdio dispatcher wraps sys.stdout / sys.stderr once
(lazy install on first console/run-script open). After install, every
thread's print() goes either to its registered sink (set via
capture_stdio()) or to the original stdout (other threads, including
the render + worker + BP trap threads). Install is process-wide and
NEVER uninstalled, because other code may already hold references to
the wrapped stream objects.
"""
from __future__ import annotations

import contextlib
import logging
import sys
import threading
import time
import traceback
import typing

if typing.TYPE_CHECKING:
    from ..state import DebugViewState

_log = logging.getLogger("nylib.imguiutils.debug_view.tools._script_runner")

_per_thread = threading.local()
_dispatcher_installed = False
_install_lock = threading.Lock()


class _ThreadDispatchStream:
    """File-like wrapper that dispatches per-thread to a registered
    sink, or falls back to the underlying stream."""
    def __init__(self, fallback):
        self._fallback = fallback

    def write(self, s):
        sink = getattr(_per_thread, "sink_stdout", None)
        if sink is not None:
            sink(s)
            return len(s)
        return self._fallback.write(s)

    def flush(self):
        sink = getattr(_per_thread, "sink_stdout", None)
        if sink is None:
            try:
                self._fallback.flush()
            except Exception:
                pass

    def isatty(self):
        try:
            return self._fallback.isatty()
        except Exception:
            return False

    def writelines(self, lines):
        for line in lines:
            self.write(line)


class _ThreadDispatchStreamErr(_ThreadDispatchStream):
    """stderr variant — sink lookup keyed by `sink_stderr`."""
    def write(self, s):
        sink = getattr(_per_thread, "sink_stderr", None)
        if sink is not None:
            sink(s)
            return len(s)
        return self._fallback.write(s)

    def flush(self):
        sink = getattr(_per_thread, "sink_stderr", None)
        if sink is None:
            try:
                self._fallback.flush()
            except Exception:
                pass


def ensure_dispatcher_installed() -> None:
    """Wrap sys.stdout / sys.stderr in the per-thread dispatcher.
    Idempotent. Process-wide. Never uninstalled (in production); in
    test environments where the test runner swaps sys.stdout between
    tests, the isinstance guard re-wraps as needed."""
    global _dispatcher_installed
    if _dispatcher_installed and isinstance(sys.stdout, _ThreadDispatchStream):
        return
    with _install_lock:
        if _dispatcher_installed and isinstance(sys.stdout, _ThreadDispatchStream):
            return
        sys.stdout = _ThreadDispatchStream(sys.stdout)
        sys.stderr = _ThreadDispatchStreamErr(sys.stderr)
        _dispatcher_installed = True


@contextlib.contextmanager
def capture_stdio(on_chunk: typing.Callable[[str, str], None]):
    """Within this thread, route stdout/stderr through `on_chunk(kind, text)`.
    `kind` is 'out' or 'err'. Restores the previous sink on exit."""
    old_out = getattr(_per_thread, "sink_stdout", None)
    old_err = getattr(_per_thread, "sink_stderr", None)
    _per_thread.sink_stdout = lambda s: on_chunk("out", s)
    _per_thread.sink_stderr = lambda s: on_chunk("err", s)
    try:
        yield
    finally:
        _per_thread.sink_stdout = old_out
        _per_thread.sink_stderr = old_err


def make_script_globals(state, cancel_flag: threading.Event) -> dict:
    """Return the globals dict every script sees.

    Minimal by design: only `state` (the DebugViewState) and
    `should_cancel()` (cooperative cancel poll). Scripts import
    anything else they need from stdlib or nylib."""
    return {
        "__builtins__": __builtins__,
        "state": state,
        "should_cancel": cancel_flag.is_set,
    }


class ScriptRun:
    """Single script execution.

    A ScriptRun owns its thread + cancel event + reporting callbacks.
    Construct, then `start()`. The worker thread:
      - registers per-thread stdio sinks via capture_stdio()
      - compiles `source`
      - execs against `make_script_globals(state, cancel_flag)`
      - catches BaseException so script `sys.exit()` doesn't kill host
      - on completion calls `on_done(self)` from the script thread
    """

    def __init__(self, *, source: str, state,
                 on_output: typing.Callable[[str, str], None],
                 on_done: typing.Callable[["ScriptRun"], None],
                 filename: str = "<script>"):
        self.source = source
        self.filename = filename
        self._state = state
        self._on_output = on_output
        self._on_done = on_done
        self._cancel = threading.Event()
        self._thread: typing.Optional[threading.Thread] = None
        self.started_at: typing.Optional[float] = None
        self.finished_at: typing.Optional[float] = None
        self.exception: typing.Optional[BaseException] = None
        self.traceback_text: typing.Optional[str] = None

    def start(self) -> None:
        if self._thread is not None:
            return
        self.started_at = time.monotonic()
        self._thread = threading.Thread(
            target=self._run, name="ScriptRun", daemon=True,
        )
        self._thread.start()

    def cancel(self) -> None:
        self._cancel.set()

    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def join(self, timeout=None) -> None:
        if self._thread is not None:
            self._thread.join(timeout=timeout)

    def _run(self) -> None:
        ensure_dispatcher_installed()
        globs = make_script_globals(self._state, self._cancel)
        with capture_stdio(self._on_output):
            try:
                code = compile(self.source, self.filename, "exec")
                exec(code, globs)
            except BaseException as exc:    # noqa: BLE001
                self.exception = exc
                self.traceback_text = traceback.format_exc()
                try:
                    self._on_output("err", self.traceback_text)
                except Exception:
                    pass
        self.finished_at = time.monotonic()
        try:
            self._on_done(self)
        except Exception:
            _log.exception("ScriptRun on_done callback failed")


__all__ = [
    "make_script_globals",
    "ensure_dispatcher_installed",
    "capture_stdio",
    "ScriptRun",
]
