import argparse
import contextlib
import importlib
import math
import os
import pathlib


FRONTENDS = {
    'dx9': ('pyimgui.dx9', 'Dx9Window'),
    'dx10': ('pyimgui.dx10', 'Dx10Window'),
    'dx11': ('pyimgui.dx11', 'Dx11Window'),
    'dx12': ('pyimgui.dx12', 'Dx12Window'),
    'gl3': ('pyimgui.gl3', 'Gl3Window'),
    'vk': ('pyimgui.vk', 'VkWindow'),
}


def make_test_image(dst):
    dst = pathlib.Path(dst)
    dst.parent.mkdir(parents=True, exist_ok=True)
    width, height = 96, 64
    with open(dst, 'wb') as f:
        f.write(f'P6\n{width} {height}\n255\n'.encode('ascii'))
        for y in range(height):
            for x in range(width):
                f.write(bytes((x * 255 // width, y * 255 // height, 180)))
    return dst


def load_frontend(frontend):
    module_name, window_name = FRONTENDS[frontend]
    return importlib.import_module(module_name), window_name


class DemoState:
    def __init__(self, frontend, auto_close_frames=0):
        self.frontend = frontend
        self.auto_close_frames = auto_close_frames
        self.frames = 0
        self.is_init = False
        self.font = None
        self.test_image = None
        self.texture_error = ''
        self.font_error = ''

        self.show_about_window = False
        self.show_debug_log_window = False
        self.show_demo_window = False
        self.show_id_stack_tool_window = False
        self.show_metrics_window = False

        self.counter = 0
        self.enabled = True
        self.radio_value = 0
        self.slider_float = 0.35
        self.slider_int = 4
        self.drag_float = 1.0
        self.input_float = 2.5
        self.input_int = 7
        self.test_string = 'Hello, pyimgui2!'
        self.multi_line = 'Line one\nLine two'
        self.color = None
        self.combo_items = ['alpha', 'beta', 'gamma', 'delta']
        self.combo_selected = 'alpha'
        self.list_index = 1
        self.selectable_index = 0
        self.vector2 = [0.2, 0.8]
        self.vector3 = [0.1, 0.5, 0.9]
        self.table_rows = 12
        self.progress = 0.0
        self.plot_values = [math.sin(i * 0.18) for i in range(96)]

    def do_init(self):
        import pyimgui.imgui as imgui

        self.is_init = True
        self.color = self.wnd.ClearColor
        io = imgui.GetIO()

        font_dir = pathlib.Path(os.environ.get('WINDIR', r'C:\Windows')) / 'fonts'
        if (font_file := font_dir / 'msyh.ttc').is_file():
            try:
                self.font = io.Fonts.AddFontFromFileTTF(str(font_file), 16, None, io.Fonts.GetGlyphRangesChineseFull())
                io.Fonts.Build()
                if hasattr(self.wnd, 'InvalidateDeviceObjects'):
                    self.wnd.InvalidateDeviceObjects()
            except Exception as exc:
                self.font_error = repr(exc)

        if hasattr(self.wnd, 'CreateTexture'):
            try:
                image_path = make_test_image(pathlib.Path(__file__).parent / 'auto_src' / 'pyimgui2_test.ppm')
                self.test_image = self.wnd.CreateTexture(str(image_path))
            except Exception as exc:
                self.texture_error = repr(exc)
        if hasattr(self.wnd, 'UpdateTrayIconInfo'):
            self.wnd.UpdateTrayIconInfo(f'pyimgui2 {self.frontend}')

    def __call__(self, wnd):
        import pyimgui.imgui as imgui
        import pyimgui.imgui.ctx as imgui_ctx

        self.wnd = wnd
        self.frames += 1
        if not self.is_init:
            return self.wnd.CallBeforeFrameOnce(self.do_init)

        with imgui_ctx.PushFont(self.font) if self.font else contextlib.nullcontext():
            self.draw_auxiliary_windows(imgui)
            self.draw_main_window(imgui, imgui_ctx, wnd)

        if self.auto_close_frames and self.frames >= self.auto_close_frames:
            self.wnd.Close()

    def draw_auxiliary_windows(self, imgui):
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

    def draw_main_window(self, imgui, imgui_ctx, wnd):
        viewport = imgui.GetMainViewport()
        window_class = imgui.ImGuiWindowClass()
        window_class.DockNodeFlagsOverrideSet = imgui.ImGuiDockNodeFlags_NoDocking
        imgui.SetNextWindowClass(window_class)
        imgui.SetNextWindowPos(viewport.Pos)
        imgui.SetNextWindowSize(viewport.Size)
        flags = (
            imgui.ImGuiWindowFlags_NoDecoration |
            imgui.ImGuiWindowFlags_NoMove |
            imgui.ImGuiWindowFlags_NoSavedSettings |
            imgui.ImGuiWindowFlags_NoBringToFrontOnFocus |
            imgui.ImGuiWindowFlags_MenuBar
        )
        with imgui_ctx.Begin('##FullWindow', flags=flags) as (show, window_open):
            if not window_open:
                self.wnd.Close()
            if not show:
                return

            self.draw_menu_bar(imgui, wnd)
            imgui.Text(f'frontend: {self.frontend}')
            imgui.Text(f'fps: {imgui.GetIO().Framerate:.1f}')
            imgui.Text(f'frame: {self.frames}')
            imgui.Text('中文字符 / direct Dear ImGui pybind wrapper')
            if self.font_error:
                imgui.Text(f'font error: {self.font_error}')
            if self.texture_error:
                imgui.Text(f'texture error: {self.texture_error}')

            with imgui_ctx.BeginTabBar('##main_tabs') as show_tabbar:
                if show_tabbar:
                    self.draw_inputs_tab(imgui, imgui_ctx)
                    self.draw_selectors_tab(imgui, imgui_ctx)
                    self.draw_tables_tab(imgui, imgui_ctx)
                    self.draw_drawing_tab(imgui, imgui_ctx)
                    self.draw_popups_tab(imgui, imgui_ctx)

    def draw_menu_bar(self, imgui, wnd):
        import pyimgui.imgui.ctx as imgui_ctx

        with imgui_ctx.BeginMenuBar() as show_menu_bar:
            if not show_menu_bar:
                return
            with imgui_ctx.BeginMenu('Window') as show_window_menu:
                if show_window_menu:
                    if imgui.MenuItem('HideToTray', ''):
                        wnd.HideToTray()
                    if imgui.MenuItem('Close', ''):
                        wnd.Close()
            with imgui_ctx.BeginMenu('Tools') as show_tools_menu:
                if show_tools_menu:
                    if imgui.MenuItem('Show demo', ''):
                        self.show_demo_window = not self.show_demo_window
                    if imgui.MenuItem('Show metrics', ''):
                        self.show_metrics_window = not self.show_metrics_window
                    if imgui.MenuItem('Show debug log', ''):
                        self.show_debug_log_window = not self.show_debug_log_window
                    if imgui.MenuItem('Show about', ''):
                        self.show_about_window = not self.show_about_window

    def draw_inputs_tab(self, imgui, imgui_ctx):
        with imgui_ctx.BeginTabItem('Inputs') as (show_tab, _):
            if not show_tab:
                return
            with imgui_ctx.PushID('inputs'), imgui_ctx.PushItemWidth(360):
                with imgui_ctx.BeginGroup():
                    if imgui.Button('Button'):
                        self.counter += 1
                    imgui.SameLine()
                    imgui.Text(f'counter={self.counter}')
                    _, self.enabled = imgui.Checkbox('Enabled', self.enabled)
                    with imgui_ctx.BeginDisabled(not self.enabled):
                        imgui.Button('Disabled scope sample')
                    _, self.radio_value = imgui.RadioButton('Mode A', self.radio_value, 0)
                    imgui.SameLine()
                    _, self.radio_value = imgui.RadioButton('Mode B', self.radio_value, 1)
                with imgui_ctx.PushStyleColor(imgui.ImGuiCol_Text, imgui.ImVec4(0.8, 0.95, 1.0, 1.0)):
                    imgui.Text('PushStyleColor context sample')
                _, self.slider_float = imgui.SliderFloat('SliderFloat', self.slider_float, 0.0, 1.0)
                _, self.slider_int = imgui.SliderInt('SliderInt', self.slider_int, 0, 10)
                _, self.drag_float = imgui.DragFloat('DragFloat', self.drag_float, 0.02, -2.0, 2.0)
                _, self.input_float = imgui.InputFloat('InputFloat', self.input_float)
                _, self.input_int = imgui.InputInt('InputInt', self.input_int)
                _, self.vector2 = imgui.SliderFloat2('SliderFloat2', self.vector2, 0.0, 1.0)
                _, self.vector3 = imgui.InputFloat3('InputFloat3', self.vector3)
                _, self.test_string = imgui.InputText('InputText', self.test_string)
                if hasattr(imgui, 'InputTextMultiline'):
                    _, self.multi_line = imgui.InputTextMultiline('InputTextMultiline', self.multi_line, imgui.ImVec2(360, 80))
                _, self.wnd.ClearColor = imgui.ColorEdit4('Clear color', self.wnd.ClearColor)

    def draw_selectors_tab(self, imgui, imgui_ctx):
        with imgui_ctx.BeginTabItem('Selectors') as (show_tab, _):
            if not show_tab:
                return
            with imgui_ctx.BeginCombo('Combo', self.combo_selected) as show_combo:
                if show_combo:
                    for item in self.combo_items:
                        if imgui.Selectable(item, item == self.combo_selected):
                            self.combo_selected = item
            _, self.list_index = imgui.ListBox('ListBox', self.list_index, self.combo_items, 4)
            with imgui_ctx.BeginListBox('BeginListBox', imgui.ImVec2(240, 100)) as show_list_box:
                if show_list_box:
                    for idx, item in enumerate(self.combo_items):
                        if imgui.Selectable(f'list {idx}: {item}', idx == self.selectable_index):
                            self.selectable_index = idx
            if imgui.TreeNode('TreeNode'):
                imgui.Bullet()
                imgui.SameLine()
                imgui.Text('Tree child A')
                imgui.Bullet()
                imgui.SameLine()
                imgui.Text('Tree child B')
                imgui.TreePop()
            if imgui.CollapsingHeader('Selectable rows'):
                for idx, item in enumerate(self.combo_items):
                    if imgui.Selectable(f'{idx}: {item}', idx == self.selectable_index):
                        self.selectable_index = idx
                    with imgui_ctx.BeginItemTooltip() as show_tooltip:
                        if not show_tooltip:
                            continue
                        imgui.Text(f'select {item}')

    def draw_tables_tab(self, imgui, imgui_ctx):
        with imgui_ctx.BeginTabItem('Tables') as (show_tab, _):
            if not show_tab:
                return
            flags = imgui.ImGuiTableFlags_Borders | imgui.ImGuiTableFlags_RowBg | imgui.ImGuiTableFlags_Resizable
            with imgui_ctx.BeginTable('test_table', 3, flags=flags) as show_table:
                if show_table:
                    for row in range(self.table_rows):
                        imgui.TableNextRow()
                        for col in range(3):
                            imgui.TableNextColumn()
                            imgui.Text(f'R{row} C{col}')

    def draw_drawing_tab(self, imgui, imgui_ctx):
        with imgui_ctx.BeginTabItem('Drawing') as (opened, _):
            if not opened:
                return
            try:
                self.progress = (self.progress + 0.0025) % 1.0
                imgui.ProgressBar(self.progress, imgui.ImVec2(320, 0), f'{self.progress:.0%}')
                imgui.PlotLines('PlotLines', self.plot_values, len(self.plot_values), 0, '', -1.0, 1.0, imgui.ImVec2(360, 80), 4)
            except Exception as exc:
                imgui.Text(f'plot/progress error: {exc!r}')
            if self.test_image:
                image_height = 96
                image_width = self.test_image.width * image_height // self.test_image.height
                imgui.ImageButton('##img_button', self.test_image.handle, imgui.ImVec2(image_width, image_height))
            text_size = imgui.CalcTextSize(self.test_string)
            draw_list = imgui.GetWindowDrawList()
            pos = imgui.GetCursorScreenPos()
            imgui.Text(self.test_string)
            draw_list.AddRect(pos, imgui.ImVec2(pos.x + text_size.x, pos.y + text_size.y), imgui.GetColorU32(imgui.ImVec4(1, 0, 0, 1)))
            polyline = [
                imgui.ImVec2(pos.x, pos.y + text_size.y + 10),
                imgui.ImVec2(pos.x + 50, pos.y + text_size.y + 28),
                imgui.ImVec2(pos.x + 110, pos.y + text_size.y + 12),
                imgui.ImVec2(pos.x + 170, pos.y + text_size.y + 32),
            ]
            draw_list.AddPolyline(polyline, len(polyline), imgui.GetColorU32(imgui.ImVec4(0.2, 0.8, 1.0, 1)), 0, 2.0)

    def draw_popups_tab(self, imgui, imgui_ctx):
        with imgui_ctx.BeginTabItem('Popups') as (opened, _):
            if not opened:
                return
            if imgui.Button('Open popup'):
                imgui.OpenPopup('Control popup')
            with imgui_ctx.BeginPopup('Control popup') as show_popup:
                if show_popup:
                    imgui.Text('Popup content')
                    if imgui.Button('Close popup'):
                        imgui.CloseCurrentPopup()


def test(frontend='dx11', auto_close_frames=None):
    import pyimgui

    frontend = frontend.lower()
    if frontend not in FRONTENDS:
        raise ValueError(f'unknown frontend: {frontend}')

    module, window_name = load_frontend(frontend)
    window_cls = getattr(module, window_name)
    assert getattr(pyimgui, window_name) is window_cls

    if frontend == 'dx10':
        print('dx10 standalone Serve is currently a placeholder; import/lazy smoke passed')
        return None

    if auto_close_frames is None:
        auto_close_frames = int(os.environ.get('PYIMGUI_TEST_AUTO_CLOSE_FRAMES', '0') or 0)
    wnd = window_cls(DemoState(frontend, auto_close_frames=auto_close_frames))
    wnd.title = f'pyimgui2 {frontend} frontend demo'
    wnd.Serve()
    return wnd


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--frontend', choices=(*FRONTENDS.keys(), 'all'), default=os.environ.get('PYIMGUI_TEST_FRONTEND', 'dx11'))
    parser.add_argument('--auto-close-frames', type=int, default=None)
    args = parser.parse_args()

    if args.frontend == 'all':
        auto_close_frames = args.auto_close_frames
        if auto_close_frames is None:
            auto_close_frames = int(os.environ.get('PYIMGUI_TEST_AUTO_CLOSE_FRAMES', '120') or 120)
        for frontend in FRONTENDS:
            test(frontend, auto_close_frames=auto_close_frames)
    else:
        test(args.frontend, auto_close_frames=args.auto_close_frames)


if __name__ == '__main__':
    main()