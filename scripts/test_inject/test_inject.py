import contextlib
import os
import pathlib
import threading
import typing

from nylib.process import Process
from nylib.winutils import enable_privilege, iter_processes
from nylib.winutils.pipe_rpc import RpcClient
from nylib.winutils.python_loader import run_script

from nylib.pyimgui import Dx11Window, imgui
from nylib.pyimgui.imgui import ctx as imgui_ctx


class SelectProcess:
    def __init__(self, callback: typing.Callable[[int], ...]):
        self.callback = callback
        self.process_list = None
        self.show_process_list = None
        self.load_thread = None
        self.filter_text = ""

        self.refresh()

    def load_process_list(self):
        self.process_list = [(process.szExeFile.decode('utf-8', 'ignore'), process.th32ProcessID) for process in iter_processes()]
        self.update_show_process_list()

    def can_refresh(self):
        return self.load_thread is None or not self.load_thread.is_alive()

    def refresh(self):
        if self.can_refresh():
            self.show_process_list = None
            self.process_list = None
            self.load_thread = threading.Thread(target=self.load_process_list)
            self.load_thread.start()

    def update_show_process_list(self):
        if self.filter_text:
            self.show_process_list = [(name, pid) for name, pid in self.process_list if self.filter_text.lower() in name.lower()]
        else:
            self.show_process_list = self.process_list

    def __call__(self):
        imgui.SetNextWindowSize(imgui.ImVec2(400, 300), imgui.ImGuiCond_FirstUseEver)
        with imgui_ctx.Begin("Select Process") as (show, window_open):
            if not window_open:
                self.callback(-1)
            if show:
                if self.show_process_list is None:
                    return imgui.Text("Loading...")
                if self.can_refresh() and imgui.Button("Refresh"):
                    return self.refresh()
                imgui.SameLine()
                changed, self.filter_text = imgui.InputText("Filter", self.filter_text)
                if changed:
                    self.update_show_process_list()

                with imgui_ctx.BeginTable("ProcessTable", 3, imgui.ImGuiTableFlags_ScrollY):
                    imgui.TableSetupScrollFreeze(0, 1)
                    imgui.TableSetupColumn("Name")
                    imgui.TableSetupColumn("PID")
                    imgui.TableSetupColumn("-")
                    imgui.TableHeadersRow()
                    for name, pid in self.show_process_list:
                        imgui.TableNextRow()
                        imgui.TableSetColumnIndex(0)
                        imgui.Text(name)
                        imgui.TableSetColumnIndex(1)
                        imgui.Text(str(pid))
                        imgui.TableSetColumnIndex(2)
                        if imgui.Button(f"Select##{name}_{pid}"):
                            self.callback(pid)


class Gui:
    instance: 'Gui'
    target_process: Process = None
    target_rpc: RpcClient = None
    select_script_path: pathlib.Path = None

    def __init__(self):
        Gui.instance = self
        self.wnd = Dx11Window(self.draw)

        self.im_font = None
        self.is_init = False

        self.select_script_view_path = pathlib.Path.cwd()

        self._select_process = None

    def init_draw(self):
        from nylib.pyimgui import imgui
        io = imgui.GetIO()
        io.IniFilename = None
        font_dir = pathlib.Path(os.environ['WINDIR']) / 'fonts'
        if (font_file := font_dir / 'msyh.ttc').is_file():
            self.im_font = io.Fonts.AddFontFromFileTTF(str(font_file), 16, None, io.Fonts.GetGlyphRangesChineseFull())
            io.Fonts.Build()
            self.wnd.InvalidateDeviceObjects()
        self.is_init = True

    def on_select_process(self, pid):
        print("Selected process:", pid)
        if pid > 0:
            self.target_process = Process(pid)
            self.target_rpc = RpcClient(f"\\\\.\\pipe\\GamePipe-pid-{self.target_process.process_id}")
        self._select_process = None

    def render_main(self):
        viewport = imgui.GetMainViewport()
        cls = imgui.ImGuiWindowClass()
        cls.DockNodeFlagsOverrideSet = imgui.ImGuiDockNodeFlags_NoDocking
        imgui.SetNextWindowClass(cls)
        imgui.SetNextWindowPos(viewport.Pos)
        imgui.SetNextWindowSize(viewport.Size)
        with imgui_ctx.Begin(
                "##FullWindow",
                flags=imgui.ImGuiWindowFlags_NoDecoration | imgui.ImGuiWindowFlags_NoMove | imgui.ImGuiWindowFlags_NoSavedSettings | imgui.ImGuiWindowFlags_NoBringToFrontOnFocus
        ) as (show, window_open):
            if not window_open:
                self.wnd.Close()
            if show:
                if self.target_process is None:
                    btn_text = "Select Process"
                else:
                    btn_text = f"Selected: {self.target_process.process_id}"
                if imgui.Button(btn_text) and self._select_process is None:
                    self._select_process = SelectProcess(self.on_select_process)
                if self.target_process is None: return

                try:
                    self.target_process.get_ldr_data('python_loader.dll')
                except KeyError as e:
                    if imgui.Button("Inject"):
                        threading.Thread(target=run_script, args=(self.target_process, "./inject_main.py")).start()
                    return

                if self.select_script_path is not None:
                    if not self.select_script_path.is_file():
                        self.select_script_path = None
                    else:
                        imgui.Text(f"Selected script: {self.select_script_path}")
                        imgui.SameLine()
                        if imgui.Button("Run"):
                            threading.Thread(target=self.target_rpc.rpc.run_script, args=(str(self.select_script_path),)).start()

                if not self.select_script_view_path.is_dir():
                    self.select_script_view_path = pathlib.Path.cwd()
                _files = []
                _dirs = []
                for p in self.select_script_view_path.iterdir():
                    if p.is_dir():
                        _dirs.append(p)
                    else:
                        _files.append(p)
                with imgui_ctx.BeginChild("SelectScriptView"):
                    if self.select_script_view_path.parent != self.select_script_view_path:
                        if imgui.Button(".."):
                            self.select_script_view_path = self.select_script_view_path.parent
                    for p in _dirs:
                        if imgui.Button(f"{p.name}/"):
                            self.select_script_view_path = p
                    for p in _files:
                        if imgui.Button(p.name):
                            self.select_script_path = p.resolve()

    def draw(self):
        if not self.is_init:
            self.wnd.CallBeforeFrameOnce(self.init_draw)
        with imgui_ctx.PushFont(self.im_font) if self.im_font else contextlib.nullcontext():
            self.render_main()
            if self._select_process:
                self._select_process()

    def serve(self):
        self.wnd.Serve()


def main():
    # process = Process.from_name("ChronoArk.exe")
    # run_script(process, "./inject_main.py")

    Gui().serve()


if __name__ == '__main__':
    enable_privilege()
    main()
