import pathlib

from .alerts import Alerts
from .utils import PushDisabledButtonStyle
from ..pyimgui import imgui
from ..pyimgui.imgui import ctx as imgui_ctx

PATH_SEP = "/"  # os.path.sep


class FileDialog:
    def __init__(self, title, filters: list[tuple[str, str]] = None, on_ok=None, on_cancel=None, initial_dir=None, ask_save_file=False, select_dir=False):
        self.title = title
        self.filters = filters
        self._on_ok = on_ok
        self._on_cancel = on_cancel
        self.ask_save_file = ask_save_file
        self.select_dir = select_dir

        self.input = ''
        self.input_filter = ''
        self.selected_filter = 0
        self.dir = pathlib.Path(initial_dir or '.').resolve()

        self._loaded_dir = None

        self.history = [self.dir]
        self.history_ptr = 0

        self.dirs = []
        self.files = []
        self.filtered_files = []
        self.filtered_dirs = []

        self.alerts = Alerts()

    def go_path(self, path, push_history=True):
        path = pathlib.Path(path).resolve()
        if not path.exists():
            self.alerts.add(f"Path {path} does not exist", Alerts.ERROR)
            return
        if not path.is_dir(): path = path.parent
        self.dir = path
        self.input = ''
        self.input_filter = ''
        if push_history:
            self.history = [self.dir] + self.history[self.history_ptr:]
            self.history_ptr = 0

    def go_back(self):
        if self.history_ptr + 1 < len(self.history):
            self.history_ptr += 1
            self.go_path(self.history[self.history_ptr], push_history=False)

    def go_forward(self):
        if self.history_ptr > 0:
            self.history_ptr -= 1
            self.go_path(self.history[self.history_ptr], push_history=False)

    def update_path(self):
        if self._loaded_dir == self.dir: return
        self._loaded_dir = self.dir
        self.dirs.clear()
        self.files.clear()
        for p in self.dir.iterdir():
            try:
                if p.is_dir():
                    self.dirs.append(p)
                else:
                    self.files.append(p)
            except Exception:
                self.files.append(p)
        self.update_filter()

    def update_filter(self):
        if self.input_filter:
            self.filtered_files = [f for f in self.files if self.input_filter in f.name]
            self.filtered_dirs = [d for d in self.dirs if self.input_filter in d.name]
        else:
            self.filtered_files = self.files
            self.filtered_dirs = self.dirs
        if self.filters and self.selected_filter <= len(self.filters):
            allowed = self.filters[self.selected_filter - 1][1]
            self.filtered_files = [f for f in self.filtered_files if f.suffix == allowed]

    def on_ok(self, fp):
        if fp.is_dir() and not self.select_dir:
            self.go_path(fp)
            return
        if self.ask_save_file:
            if fp.exists():
                self.alerts.add(f"File {fp} already exists", Alerts.ERROR)  # todo: ask to overwrite
                return
        elif not fp.exists():
            self.alerts.add(f"File {fp} does not exist", Alerts.ERROR)
            return
        if self._on_ok:
            self._on_ok(fp)

    def on_cancel(self):
        if self._on_cancel:
            self._on_cancel()

    def render(self):
        with imgui_ctx.Begin(self.title, True, imgui.ImGuiWindowFlags_NoDocking) as (show, window_open):
            if not window_open:
                self.on_cancel()
                return False
            if not show:
                return True
            imgui.BringWindowToFocusFront(imgui.GetCurrentWindow())
            imgui.SetWindowSize(imgui.ImVec2(400, 300), imgui.ImGuiCond_FirstUseEver)
            self.update_path()
            want_submit = False
            with imgui_ctx.PushStyleVar(imgui.ImGuiStyleVar_ItemSpacing, imgui.ImVec2(3, 3)):
                color_disabled = imgui.ImVec4(0.5, 0.5, 0.5, 1)
                if self.history_ptr + 1 < len(self.history):
                    if imgui.Button('<') or imgui.IsKeyPressed(imgui.ImGuiKey_AppBack):
                        self.go_back()
                else:
                    with PushDisabledButtonStyle(color_disabled):
                        imgui.Button('<')
                imgui.SameLine()
                if self.history_ptr > 0:
                    if imgui.Button('>') or imgui.IsKeyPressed(imgui.ImGuiKey_AppForward):
                        self.go_forward()
                else:
                    with PushDisabledButtonStyle(color_disabled):
                        imgui.Button('>')
                imgui.SameLine()
                for lv, p in enumerate(self.dir.parts[:-1]):
                    if imgui.Button(f"{p}{PATH_SEP}##sel_dir_{lv}"):
                        self.go_path(self.dir.parents[-1 - lv])
                    imgui.SameLine()
                imgui.Text(self.dir.parts[-1])
                imgui.SameLine()

            changed, self.input_filter = imgui.InputText('##filter', self.input_filter)
            if changed:
                self.update_filter()
            with imgui_ctx.BeginChild('##files', imgui.ImVec2(0, -imgui.GetFrameHeightWithSpacing() * 2), child_flags=imgui.ImGuiChildFlags_Border):
                for i, d in enumerate(self.filtered_dirs):
                    if imgui.Selectable(f"[D] {d.name}{PATH_SEP}##sel_dir_{i}", False, imgui.ImGuiSelectableFlags_AllowDoubleClick):
                        if self.input == d.name:
                            self.go_path(d)
                        else:
                            self.input = d.name
                for i, f in enumerate(self.filtered_files):
                    if imgui.Selectable(f"[F] {f.name}##sel_file_{i}", False, imgui.ImGuiSelectableFlags_AllowDoubleClick):
                        if self.input == f.name:
                            want_submit = True
                        else:
                            self.input = f.name
            want_submit_, self.input = imgui.InputText('##input', self.input, imgui.ImGuiInputTextFlags_EnterReturnsTrue)
            want_submit |= want_submit_
            imgui.SameLine()
            if imgui.Button('OK') or want_submit:
                self.on_ok(self.dir / self.input)
            imgui.SameLine()
            if imgui.Button('Cancel'):
                self.on_cancel()
            self.alerts.render()
            return True
