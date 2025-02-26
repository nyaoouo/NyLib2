import pathlib
import re

from .alerts import Alerts
from .utils import PushDisabledButtonStyle
from ..pyimgui import imgui
from ..pyimgui.imgui import ctx as imgui_ctx
from ..utils.handles import Handles

PATH_SEP = "/"  # os.path.sep

color_disabled = imgui.ImVec4(0.5, 0.5, 0.5, 1)

handles = Handles()


def window_file_name_matcher(pattern):
    pattern = re.escape(pattern).replace(r'\*', '.*').replace(r'\?', '.')
    return re.compile("^" + pattern + "$", re.IGNORECASE).match


basic_filter = "All Files(*)", None


class FileDialog:
    def __init__(self, title=None, filters: list[tuple[str, str]] = None, on_ok=None, on_cancel=None, initial_dir=None, initial_value=None, ask_save_file=False, select_dir=False):
        self.handle = handles.get()
        self.title = (title or "") + f"###__file_dialog_{self.handle}"

        self.filters = [(f"{fn}({pattern})", window_file_name_matcher(pattern)) for fn, pattern in filters] if filters else []
        self.filters.append(basic_filter)
        self._on_ok = on_ok
        self._on_cancel = on_cancel
        self.ask_save_file = ask_save_file
        self.select_dir = select_dir

        self.input = initial_value or ''
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

    def __free_handle(self):
        if self.handle:
            handles.free(self.handle)
            self.handle = None

    def __del__(self):
        self.__free_handle()

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
            if matcher := self.filters[self.selected_filter][1]:
                self.filtered_files = [f for f in self.filtered_files if matcher(f.name)]

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
        self.__free_handle()
        if self._on_ok:
            self._on_ok(fp)

    def on_cancel(self):
        self.__free_handle()
        if self._on_cancel:
            self._on_cancel()

    def render(self):
        if not self.handle: return False
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
            max_filter_width = max(imgui.CalcTextSize(desc).x for desc, _ in self.filters) + 20
            with imgui_ctx.PushItemWidth(max_filter_width):
                self.selected_filter = self.selected_filter if self.selected_filter < len(self.filters) else 0
                with imgui_ctx.BeginCombo('##preset_filter', self.filters[self.selected_filter][0]) as show:
                    if show:
                        for i, (desc, _) in enumerate(self.filters):
                            if imgui.Selectable(f"{desc}##sel_preset_filter_{i}", i == self.selected_filter):
                                self.selected_filter = i
                                self.update_filter()
            imgui.SameLine()
            style = imgui.GetStyle()
            other_width = imgui.CalcTextSize('OKCancel').x + style.ItemSpacing.x * 4 + style.FramePadding.x * 6
            with imgui_ctx.PushItemWidth(imgui.GetWindowWidth() - other_width - max_filter_width):
                want_submit_, self.input = imgui.InputText('##input', self.input, imgui.ImGuiInputTextFlags_EnterReturnsTrue)
            want_submit |= want_submit_
            imgui.SameLine()
            if self.input:
                if imgui.Button('OK') or want_submit:
                    self.on_ok(self.dir / self.input)
            else:
                with PushDisabledButtonStyle(color_disabled):
                    imgui.Button('OK')
            imgui.SameLine()
            if imgui.Button('Cancel'):
                self.on_cancel()
            self.alerts.render()
            return True
