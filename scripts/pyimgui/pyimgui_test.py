import contextlib
import io
import os
import pathlib
import threading
import time


def get_cat_image(dst, cb=None):
    import urllib.request
    url = 'https://cataas.com/cat'
    with urllib.request.urlopen(url) as response:
        chunk = 128
        content_length = response.getheader('Content-Length')
        content_length = int(content_length) if content_length else None
        if cb:
            cb(0, content_length)
        with open(dst, 'wb') as f:
            while True:
                read_chunk_start = time.time()
                data = response.read(chunk)
                if not data:
                    break
                read_chunk_used = time.time() - read_chunk_start
                if read_chunk_used < 0.5:
                    chunk *= 2
                elif read_chunk_used > 2:
                    chunk //= 2
                f.write(data)
                if cb:
                    cb(f.tell(), content_length)
            if content_length and f.tell() != content_length:
                raise ValueError(f"Downloaded file size mismatch: {f.tell()} != {content_length}")
            if cb:
                cb(f.tell(), content_length)
    return dst


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

            self.load_progress = None
            threading.Thread(target=self.get_test_image).start()

        def get_test_image(self, force_reload=False):
            self.test_image_path = './auto_src/cat.jpg'
            self.load_progress = "0 (unknown total)"
            try:
                if force_reload or not os.path.isfile(self.test_image_path):
                    def _cb(cur, total):
                        if total:
                            self.load_progress = cur / total
                        else:
                            self.load_progress = f"(N/A) {cur}/?"

                    get_cat_image(self.test_image_path, _cb)
            except Exception as e:
                print(f"Failed to get cat image: {e}")
                self.test_image_path = None
            else:
                wnd.CallBeforeFrameOnce(lambda: setattr(self, 'test_image', wnd.CreateTexture(self.test_image_path)))
            finally:
                self.load_progress = None

        def do_init(self):
            io = imgui.GetIO()
            font_dir = pathlib.Path(os.environ['WINDIR']) / 'fonts'
            if (font_file := font_dir / 'msyh.ttc').is_file():
                self.font = io.Fonts.AddFontFromFileTTF(str(font_file), 16, None, io.Fonts.GetGlyphRangesChineseFull())
                io.Fonts.Build()
                wnd.InvalidateDeviceObjects()
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

                        clicked = False
                        if self.test_image:
                            img_h = 200
                            img_w = self.test_image.width * img_h // self.test_image.height
                            clicked = imgui.ImageButton("##img_button", self.test_image.handle, imgui.ImVec2(img_w, img_h))
                        if self.load_progress is not None:
                            if isinstance(self.load_progress, float):
                                imgui.ProgressBar(self.load_progress, imgui.ImVec2(200, 0), f"Updating cat image: {self.load_progress:.2%}")
                            else:
                                imgui.Text(f"Updating cat image: {self.load_progress}")
                        elif imgui.Button("new cat image (or click image)") or clicked:
                            threading.Thread(target=self.get_test_image, args=(True,)).start()

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
