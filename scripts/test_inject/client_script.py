import typing


def reload_all(prefix):
    import sys
    import importlib
    modules = [module for name, module in sys.modules.items() if name == prefix or name.startswith(prefix + '.')]
    for module in modules:
        importlib.reload(module)


reload_all('nylib.imguiutils')
reload_all('nylib.mono')
from nylib.mono import *
from nylib.mono.imgui_inspect import MonoInspector

from nylib.pyimgui import imgui
from nylib.pyimgui.imgui import ctx as imgui_ctx
from nylib import imguiutils

mono = Mono()


class PythonView:
    def render_threads(self):
        import threading
        import traceback
        for tid, frame in sys._current_frames().items():
            _thread = threading._active.get(tid)
            if imgui.CollapsingHeader(_thread.name if _thread else 'Thread-%d' % tid, imgui.ImGuiTreeNodeFlags_DefaultOpen):
                imgui.Text(f'tid: {tid}')
                # format stack
                for filename, lineno, name, line in traceback.extract_stack(frame):
                    imgui.Text(f'{filename}:{lineno} {name} {line}')

    def render(self):
        with imgui_ctx.BeginTabBar("##tabs") as show_tabbar:
            if show_tabbar:
                with imgui_ctx.BeginTabItem("threads") as (show_tab, _):
                    if show_tab:
                        self.render_threads()


class MonoInspect:
    def __init__(self):
        self.inspector = MonoInspector(mono)
        self.py_view = PythonView()
        self.display = True

    def __call__(self):
        if imgui.IsKeyPressed(imgui.ImGuiKey_Insert):
            self.display = not self.display
        if not self.display: return
        with imguiutils.BeginFullScreenBackGround("##BGWindow") as (show, window_open):
            # with imgui_ctx.Begin("apis") as (show, window_open):
            if not window_open:
                to_remove = []
                for k in draw_funcs:
                    if draw_funcs[k] is self:
                        to_remove.append(k)
                for k in to_remove:
                    draw_funcs.pop(k, None)
                return
            if not show: return
            with imgui_ctx.BeginTabBar("##tabs") as show_tabbar:
                if show_tabbar:
                    with imgui_ctx.BeginTabItem("Mono") as (show_tab, _):
                        if show_tab:
                            self.inspector.render()
                    with imgui_ctx.BeginTabItem("Python") as (show_tab, _):
                        if show_tab:
                            self.py_view.render()


import sys

draw_funcs = sys._gui_.draw_funcs
draw_funcs['BGWindow'] = MonoInspect()
