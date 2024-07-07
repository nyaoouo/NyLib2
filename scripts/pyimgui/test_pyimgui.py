def test():
    import pyimgui.detours as detours
    print(detours.DetourTransactionBegin)
    import pyimgui.imgui as imgui
    import pyimgui.imgui.ctx as imgui_ctx
    print(imgui.ImDrawFlags_(0).name, imgui.ImDrawFlags_None.value)
    vec = imgui.ImColor(1., 2., 3., 4.)
    print(f"{vec.Value.x=}, {vec.Value.y=}, {vec.Value.z=}, {vec.Value.w=}")
    vec.SetHSV(0.5, 0.5, 0.5)
    print(f"{vec.Value.x=}, {vec.Value.y=}, {vec.Value.z=}, {vec.Value.w=}")

    show_windows = [False, False, False, False, False]
    datas = {
        'test_string': 'Hello, world!',
    }

    def draw_func(wnd):
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
        with imgui_ctx.Begin("Hello, world") as (show, window_open):
            if not window_open:
                wnd.Close()
            if show:
                imgui.Text("This is another useful text.")
                imgui.Text(f"{show_windows=}")
                window_size = imgui.GetWindowSize()
                imgui.Text(f"Window size: {window_size.x}, {window_size.y}")
                window_pos = imgui.GetWindowPos()
                imgui.Text(f"Window pos: {window_pos.x}, {window_pos.y}")
                if imgui.CollapsingHeader("Test"):
                    _, wnd.clear_color = imgui.ColorEdit4("Clear color", wnd.clear_color)
                    changed, datas['test_string'] = imgui.InputText("Test string", datas['test_string'])
                    imgui.Text(f"Test string: {datas['test_string']}")
                changed, show_windows[0] = imgui.Checkbox("Show about window", show_windows[0])
                changed, show_windows[1] = imgui.Checkbox("Show debug log window", show_windows[1])
                changed, show_windows[2] = imgui.Checkbox("Show demo window", show_windows[2])
                changed, show_windows[3] = imgui.Checkbox("Show ID stack tool window", show_windows[3])
                changed, show_windows[4] = imgui.Checkbox("Show metrics window", show_windows[4])

    import pyimgui
    pyimgui.Dx11ImguiWindow(draw_func).Serve()

if __name__ == '__main__':
    test()
