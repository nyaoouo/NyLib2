import contextlib
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
    import pyimgui
    import pyimgui.imgui as imgui
    import pyimgui.imgui.ctx as imgui_ctx

    show_windows = [False, False, False, False, False]
    datas = {
        'test_string': 'Hello, world!',
    }

    def init_func():
        io = imgui.GetIO()
        font_dir = pathlib.Path(os.environ['WINDIR']) / 'fonts'
        if (font_file := font_dir / 'msyh.ttc').is_file():
            datas['font'] = io.Fonts.AddFontFromFileTTF(str(font_file), 16, None, io.Fonts.GetGlyphRangesChineseFull())
            io.Fonts.Build()
            wnd.InvalidateDeviceObjects()
        if cat_img_path:
            datas['test_image'] = wnd.CreateTexture(cat_img_path)
        datas['is_init'] = True

    def draw_func():
        if not datas.get('is_init', False):
            wnd.CallBeforeFrameOnce(init_func)
        with imgui_ctx.PushFont(im_font) if (im_font := datas.get('font')) else contextlib.nullcontext():
            if show_windows[0]:
                show_windows[0] = imgui.ShowAboutWindow()
            if show_windows[1]:
                show_windows[1] = imgui.ShowDebugLogWindow()
            if show_windows[2]:
                show_windows[2] = imgui.ShowDemoWindow()
            if show_windows[3]:
                show_windows[3] = imgui.ShowIDStackToolWindow()
            if show_windows[4]:
                show_windows[4] = imgui.ShowMetricsWindow()
            io = imgui.GetIO()
            with imgui_ctx.Begin(
                    f"Hello, world (fps: {io.Framerate:.1f}) ###HelloWorld",
            ) as (show, window_open):
                if not window_open:
                    wnd.Close()
                if show:
                    if 'Profiler' not in datas:
                        if imgui.Button("Start profiler"):
                            import cProfile
                            datas['Profiler'] = pr = cProfile.Profile()
                            pr.enable()
                    else:
                        if imgui.Button("Stop profiler"):
                            import pstats
                            pr = datas.pop('Profiler')
                            pr.disable()
                            pstats.Stats(pr).sort_stats(pstats.SortKey.CUMULATIVE).print_stats()
                    if img := datas.get('test_image'):
                        img_h = 200
                        img_w = img.width * img_h // img.height
                        imgui.Image(datas['test_image'].handle, imgui.ImVec2(img_w, img_h))
                        if (t_ := datas.get('update_img_thread')) and t_.is_alive():
                            imgui.Text("Updating cat image...")
                        elif imgui.Button("new cat image"):
                            def work():
                                get_cat_image(cat_img_path)
                                wnd.CallBeforeFrameOnce(lambda: datas.update({'test_image': wnd.CreateTexture(cat_img_path)}))

                            datas['update_img_thread'] = t_ = threading.Thread(target=work)
                            t_.start()

                    imgui.Text("中文字符")
                    imgui.Text("This is another useful text.")
                    imgui.Text(f"{show_windows=}")
                    window_size = imgui.GetWindowSize()
                    imgui.Text(f"Window size: {window_size.x}, {window_size.y}")
                    window_pos = imgui.GetWindowPos()
                    imgui.Text(f"Window pos: {window_pos.x}, {window_pos.y}")
                    if imgui.CollapsingHeader("Test"):
                        _, wnd.ClearColor = imgui.ColorEdit4("Clear color", wnd.ClearColor)
                        changed, datas['test_string'] = imgui.InputText("Test string", datas['test_string'])
                        imgui.Text(f"Test string: {datas['test_string']}")
                    changed, show_windows[0] = imgui.Checkbox("Show about window", show_windows[0])
                    changed, show_windows[1] = imgui.Checkbox("Show debug log window", show_windows[1])
                    changed, show_windows[2] = imgui.Checkbox("Show demo window", show_windows[2])
                    changed, show_windows[3] = imgui.Checkbox("Show ID stack tool window", show_windows[3])
                    changed, show_windows[4] = imgui.Checkbox("Show metrics window", show_windows[4])

    try:
        get_cat_image('./auto_src/cat.jpg')
        cat_img_path = './auto_src/cat.jpg'
    except Exception as e:
        print(f"Failed to get cat image: {e}")
        cat_img_path = None

    wnd = pyimgui.Dx11Window(draw_func)
    wnd.Serve()


if __name__ == '__main__':
    test()
