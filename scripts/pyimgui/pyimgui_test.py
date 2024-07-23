import contextlib
import io
import os
import pathlib
import threading


def get_cat_image(dst):
    import urllib.request
    url = 'https://cataas.com/cat'
    with urllib.request.urlopen(url) as response:
        with open(dst, 'wb') as f:
            f.write(response.read())


def test():
    import cProfile
    import pstats
    import pyimgui
    import pyimgui.imgui as imgui
    import pyimgui.imgui.ctx as imgui_ctx
    class TestWindow:
        def __init__(self):
            self.show_about_window = False
            self.show_debug_log_window = False
            self.show_demo_window = False
            self.show_id_stack_tool_window = False
            self.show_metrics_window = False

            self.profiler = None
            self.profile_string = None

            self.font = None
            self.test_string = 'Hello, world!'
            self.test_image = None
            self.test_image_path = None
            self.is_init = False

            self.get_test_image()

        def get_test_image(self, force_reload=False):
            self.test_image_path = './auto_src/cat.jpg'
            try:
                if force_reload or not os.path.isfile(self.test_image_path):
                    get_cat_image(self.test_image_path)
            except Exception as e:
                print(f"Failed to get cat image: {e}")
                self.test_image_path = None

        def do_init(self):
            io = imgui.GetIO()
            font_dir = pathlib.Path(os.environ['WINDIR']) / 'fonts'
            if (font_file := font_dir / 'msyh.ttc').is_file():
                self.font = io.Fonts.AddFontFromFileTTF(str(font_file), 16, None, io.Fonts.GetGlyphRangesChineseFull())
                io.Fonts.Build()
                wnd.InvalidateDeviceObjects()
            if self.test_image_path:
                self.test_image = wnd.CreateTexture(self.test_image_path)
            self.is_init = True

        def __call__(self):
            if not self.is_init:
                return wnd.CallBeforeFrameOnce(self.do_init)
            with imgui_ctx.PushFont(self.font) if self.font else contextlib.nullcontext():
                if self.show_about_window:
                    self.show_about_window = imgui.ShowAboutWindow()
                if self.show_debug_log_window:
                    self.show_debug_log_window = imgui.ShowDebugLogWindow()
                if self.show_demo_window:
                    self.show_demo_window = imgui.ShowDemoWindow()
                if self.show_id_stack_tool_window:
                    self.show_id_stack_tool_window = imgui.ShowIDStackToolWindow()
                if self.show_metrics_window:
                    self.show_metrics_window = imgui.ShowMetricsWindow()

                imgui_io = imgui.GetIO()
                if self.profile_string:
                    with imgui_ctx.Begin("Profiler result") as (show, window_open):
                        if not window_open:
                            self.profile_string = None
                        elif show:
                            imgui.Text(self.profile_string)
                viewport = imgui.GetMainViewport()
                cls = imgui.ImGuiWindowClass()
                cls.DockNodeFlagsOverrideSet = imgui.ImGuiDockNodeFlags_NoDocking
                imgui.SetNextWindowClass(cls)
                imgui.SetNextWindowPos(viewport.Pos)
                imgui.SetNextWindowSize(viewport.Size)
                with imgui_ctx.Begin(
                        # f"Hello, world (fps: {imgui_io.Framerate:.1f}) ###HelloWorld",
                        "##FullWindow",
                        flags=imgui.ImGuiWindowFlags_NoDecoration | imgui.ImGuiWindowFlags_NoMove | imgui.ImGuiWindowFlags_NoSavedSettings | imgui.ImGuiWindowFlags_NoBringToFrontOnFocus
                ) as (show, window_open):
                    if not window_open:
                        wnd.Close()
                    if show:
                        if not self.profiler:
                            if imgui.Button("Start profiler"):
                                self.profiler = cProfile.Profile()
                                self.profiler.enable()
                        else:
                            if imgui.Button("Stop profiler"):
                                self.profiler.disable()
                                # self.profiler.print_stats()
                                buf = io.StringIO()
                                pstats.Stats(self.profiler, stream=buf).sort_stats(pstats.SortKey.CUMULATIVE).print_stats()
                                self.profile_string = buf.getvalue()
                                self.profiler = None
                        if self.test_image:
                            img_h = 200
                            img_w = self.test_image.width * img_h // self.test_image.height
                            clicked = imgui.ImageButton("##img_button", self.test_image.handle, imgui.ImVec2(img_w, img_h))
                            if (t_ := getattr(self, 'update_img_thread', None)) and t_.is_alive():
                                imgui.Text("Updating cat image...")
                            elif imgui.Button("new cat image (or click image)") or clicked:
                                def work():
                                    self.get_test_image(force_reload=True)
                                    wnd.CallBeforeFrameOnce(lambda: setattr(self, 'test_image', wnd.CreateTexture(self.test_image_path)))
                                    # self.test_image.LoadTextureFromFile(self.test_image_path)

                                self.update_img_thread = t_ = threading.Thread(target=work)
                                t_.start()

                        imgui.Text("中文字符")
                        imgui.Text("This is another useful text.")
                        imgui.Text(f"{self.show_about_window=}")
                        window_size = imgui.GetWindowSize()
                        imgui.Text(f"Window size: {window_size.x}, {window_size.y}")
                        window_pos = imgui.GetWindowPos()
                        imgui.Text(f"Window pos: {window_pos.x}, {window_pos.y}")
                        if imgui.CollapsingHeader("Test"):
                            _, wnd.ClearColor = imgui.ColorEdit4("Clear color", wnd.ClearColor)
                            changed, self.test_string = imgui.InputText("Test string", self.test_string)
                            imgui.Text(f"Test string: {self.test_string}")
                        changed, self.show_about_window = imgui.Checkbox("Show about window", self.show_about_window)
                        changed, self.show_debug_log_window = imgui.Checkbox("Show debug log window", self.show_debug_log_window)
                        changed, self.show_demo_window = imgui.Checkbox("Show demo window", self.show_demo_window)
                        changed, self.show_id_stack_tool_window = imgui.Checkbox("Show ID stack tool window", self.show_id_stack_tool_window)
                        changed, self.show_metrics_window = imgui.Checkbox("Show metrics window", self.show_metrics_window)

    wnd = pyimgui.Dx11Window(TestWindow())
    wnd.Serve()

    return TestWindow()


if __name__ == '__main__':
    test()
