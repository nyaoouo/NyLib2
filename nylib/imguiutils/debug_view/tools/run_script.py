"""Run Script dialog: file-driven exec sharing the console's runner
infra. Multi-instance."""
from __future__ import annotations

import collections
import queue
import time
import typing

from ..subwindow import Subwindow
from ..widgets import use_state
from ._script_runner import ScriptRun, ensure_dispatcher_installed

if typing.TYPE_CHECKING:
    from ..state import DebugViewState


class RunScriptDialog(Subwindow):
    """Multi-instance 'Run Script' dialog. File path + Reload + Run."""

    def __init__(self, dialog_id: int, path: str):
        ensure_dispatcher_installed()
        self.dialog_id = dialog_id
        self.id = f"run_script_{dialog_id}"
        self._path = path
        self._source = ""
        self._scrollback: collections.deque = collections.deque(maxlen=10_000)
        self._queue: queue.Queue = queue.Queue()
        self._current_run: typing.Optional[ScriptRun] = None
        self._error: typing.Optional[str] = None
        self._show_source: bool = False

    # ----- public API used by tests + render -----

    def reload(self) -> None:
        try:
            with open(self._path, "r", encoding="utf-8") as f:
                self._source = f.read()
            self._error = None
        except Exception as exc:
            self._error = repr(exc)

    def run(self, state: "DebugViewState") -> None:
        if self._current_run is not None and self._current_run.is_running():
            self._scrollback.append(
                ("err", "[!] previous run still in flight; cancel first\n"))
            return
        if not self._source:
            self.reload()
        if self._error is not None or not self._source:
            self._scrollback.append(("err", f"[!] cannot run: {self._error}\n"))
            return
        def _on_output(kind: str, text: str) -> None:
            self._queue.put((kind, text))
        def _on_done(_run: ScriptRun) -> None:
            self._queue.put(("done", ""))
        run = ScriptRun(
            source=self._source, state=state,
            on_output=_on_output, on_done=_on_done,
            filename=self._path or "<script>",
        )
        self._current_run = run
        run.start()
        self._drain_queue()

    def cancel(self) -> None:
        if self._current_run is not None:
            self._current_run.cancel()

    def _drain_queue(self) -> None:
        while True:
            try:
                kind, text = self._queue.get_nowait()
            except queue.Empty:
                break
            if kind == "done":
                continue
            self._scrollback.append((kind, text))

    # ----- Subwindow protocol -----

    def render(self, state: "DebugViewState") -> bool:
        from nylib.pyimgui import imgui
        from nylib.pyimgui.imgui import ctx as imgui_ctx

        self._drain_queue()
        title = f"Run Script##dv{state._uid}_rs_{self.dialog_id}"
        with use_state(state):
            with imgui_ctx.Begin(title, open=True) as (show, window_open):
                if not window_open:
                    if self._current_run is not None and self._current_run.is_running():
                        from nylib.imguiutils.message_box import MessageBox
                        result = MessageBox.show(
                            "A script is still running. Cancel it and close?",
                            title="Confirm",
                            buttons=("Yes", "No"),
                        )
                        if result == "Yes":
                            self.cancel()
                            return False
                        return True
                    return False
                if not show:
                    return True
                imgui.Text(f"File: {self._path}")
                imgui.SameLine()
                if imgui.Button("Reload##rs_reload"):
                    self.reload()
                if self._error is not None:
                    imgui.TextColored(
                        imgui.ImVec4(1, 0.3, 0.3, 1),
                        f"error: {self._error}",
                    )
                if imgui.CollapsingHeader("Source##rs_src_hdr"):
                    imgui.TextUnformatted(self._source[:8192])
                # Output area.
                with imgui_ctx.BeginChild(
                    f"##dv{state._uid}_rs_{self.dialog_id}_out",
                    imgui.ImVec2(0, -60.0),
                ) as show_out:
                    if show_out:
                        for kind, text in list(self._scrollback):
                            if kind == "err":
                                imgui.TextColored(
                                    imgui.ImVec4(1, 0.3, 0.3, 1), text)
                            else:
                                imgui.TextUnformatted(text)
                        if imgui.GetScrollY() >= imgui.GetScrollMaxY() - 10:
                            imgui.SetScrollHereY(1.0)
                if imgui.Button("Run##rs_run"):
                    self.run(state)
                imgui.SameLine()
                if imgui.Button("Cancel##rs_cancel"):
                    self.cancel()
                imgui.SameLine()
                run = self._current_run
                if run is None:
                    imgui.Text("Status: ready")
                elif run.is_running():
                    elapsed = time.monotonic() - (run.started_at or time.monotonic())
                    imgui.Text(f"Status: running {elapsed:.1f}s")
                elif run.exception is not None:
                    imgui.TextColored(
                        imgui.ImVec4(1, 0.3, 0.3, 1),
                        f"Status: errored - {type(run.exception).__name__}",
                    )
                else:
                    dur = (run.finished_at or 0) - (run.started_at or 0)
                    imgui.Text(f"Status: done {dur:.1f}s")
        return True


__all__ = ["RunScriptDialog"]
