"""Python Console subwindow.

The Python console exec runs on a dedicated thread. The script
environment contains only `state` (the DebugViewState) and
`should_cancel()` (cooperative cancel poll). Everything else is
standard library or nylib - import what you need.

Because `state` exposes the full DebugViewState, scripts have indirect
access to memory writes (via Process.current reached through imports)
and to BP installation (via state.install_bp).

The [Cancel] button is cooperative: scripts must call
should_cancel() periodically to be interruptible. A `while True: pass`
script will block its thread until the host exits. There is no hard
kill.
"""
from __future__ import annotations

import collections
import queue
import time
import typing

from ..subwindow import Subwindow
from ..widgets import use_state
from ._script_runner import (
    ScriptRun, ensure_dispatcher_installed,
)

if typing.TYPE_CHECKING:
    from ..state import DebugViewState


class PythonConsole(Subwindow):
    """Singleton 'Python Console' subwindow."""
    id = "python_console"

    def __init__(self) -> None:
        ensure_dispatcher_installed()
        self._scrollback: collections.deque = collections.deque(maxlen=10_000)
        self._input_text: str = ""
        self._cmd_history: collections.deque = collections.deque(maxlen=128)
        self._history_pos: int = -1
        self._queue: queue.Queue = queue.Queue()
        self._current_run: typing.Optional[ScriptRun] = None

    # ----- public API used by tests + render -----

    def submit(self, state: "DebugViewState", source: str) -> None:
        """Submit `source` for execution. If a run is in flight,
        appends an inline warning to scrollback and does NOT start a
        new run."""
        if self._current_run is not None and self._current_run.is_running():
            self._scrollback.append(
                ("err", "[!] a script is already running; cancel it first\n")
            )
            return
        # Echo the prompt.
        for i, line in enumerate(source.splitlines() or [""]):
            prefix = ">>>" if i == 0 else "..."
            self._scrollback.append(("prompt", f"{prefix} {line}\n"))
        # Append to command history.
        if source.strip():
            self._cmd_history.append(source)
            self._history_pos = -1
        # Build the run.
        def _on_output(kind: str, text: str) -> None:
            self._queue.put((kind, text))
        def _on_done(_run: ScriptRun) -> None:
            self._queue.put(("done", ""))
        run = ScriptRun(
            source=source, state=state,
            on_output=_on_output, on_done=_on_done,
            filename="<console>",
        )
        self._current_run = run
        run.start()
        # Drain any output that arrived synchronously (e.g. in tests using
        # a synchronous _SyncRun stub). For real async runs this is a no-op.
        self._drain_queue()

    def cancel_current(self) -> None:
        if self._current_run is not None:
            self._current_run.cancel()

    def clear(self) -> None:
        self._scrollback.clear()

    def _history_step(self, direction: int) -> typing.Optional[str]:
        """direction=-1 means up arrow (older); +1 means down (newer)."""
        if not self._cmd_history:
            return None
        if direction < 0:
            if self._history_pos < 0:
                self._history_pos = len(self._cmd_history) - 1
            else:
                self._history_pos = max(0, self._history_pos - 1)
            return self._cmd_history[self._history_pos]
        else:
            if self._history_pos < 0:
                return None
            self._history_pos += 1
            if self._history_pos >= len(self._cmd_history):
                self._history_pos = -1
                return ""
            return self._cmd_history[self._history_pos]

    def _drain_queue(self) -> None:
        while True:
            try:
                kind, text = self._queue.get_nowait()
            except queue.Empty:
                break
            if kind == "done":
                # Mark current run as no longer current; keep object
                # for status display.
                continue
            self._scrollback.append((kind, text))

    # ----- Subwindow protocol -----

    def render(self, state: "DebugViewState") -> bool:
        from nylib.pyimgui import imgui
        from nylib.pyimgui.imgui import ctx as imgui_ctx

        self._drain_queue()
        title = f"Python Console##dv{state._uid}_pyc"
        with use_state(state):
            with imgui_ctx.Begin(title, open=True) as (show, window_open):
                if not window_open:
                    state.show_python_console = False
                    return False
                if not show:
                    return True
                # Scrollback child (autoscroll).
                with imgui_ctx.BeginChild(
                    f"##dv{state._uid}_pyc_sb",
                    imgui.ImVec2(0, -120.0)
                ) as show_sb:
                    if show_sb:
                        for kind, text in list(self._scrollback):
                            if kind == "err":
                                imgui.TextColored(
                                    imgui.ImVec4(1, 0.3, 0.3, 1), text)
                            elif kind == "prompt":
                                imgui.TextColored(
                                    imgui.ImVec4(0.6, 0.6, 0.6, 1), text)
                            else:
                                imgui.TextUnformatted(text)
                        if imgui.GetScrollY() >= imgui.GetScrollMaxY() - 10:
                            imgui.SetScrollHereY(1.0)
                # Multiline input + run/cancel/clear. pyimgui2's
                # InputTextMultiline wrapper manages the buffer
                # dynamically via the CallbackResize hook, so no
                # buf_size positional is needed (unlike raw ImGui).
                _, self._input_text = imgui.InputTextMultiline(
                    "##dv_pyc_input",
                    self._input_text,
                    imgui.ImVec2(0, 60.0),
                )
                io = imgui.GetIO()
                ctrl_enter = (io.KeyCtrl
                              and imgui.IsKeyPressed(imgui.ImGuiKey_Enter))
                if imgui.Button("Run##pyc_run") or ctrl_enter:
                    if self._input_text.strip():
                        self.submit(state, self._input_text)
                        self._input_text = ""
                imgui.SameLine()
                if imgui.Button("Cancel##pyc_cancel"):
                    self.cancel_current()
                imgui.SameLine()
                if imgui.Button("Clear##pyc_clear"):
                    self.clear()
                imgui.SameLine()
                # Status.
                run = self._current_run
                if run is None:
                    imgui.Text("Status: idle")
                elif run.is_running():
                    elapsed = time.monotonic() - (run.started_at or time.monotonic())
                    imgui.Text(f"Status: running {elapsed:.1f}s")
                elif run.exception is not None:
                    imgui.TextColored(
                        imgui.ImVec4(1, 0.3, 0.3, 1),
                        f"Status: errored - {type(run.exception).__name__}: {run.exception}",
                    )
                else:
                    dur = (run.finished_at or 0) - (run.started_at or 0)
                    imgui.Text(f"Status: done {dur:.1f}s")
        return True


__all__ = ["PythonConsole"]
