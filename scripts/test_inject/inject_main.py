import contextlib
import os
import pathlib
import sys
import threading
import traceback
import typing
from nylib.winutils.pipe_rpc import RpcServer

if typing.TYPE_CHECKING:
    from nylib.pyimgui import imgui

_T = typing.TypeVar('_T')


class Gui(typing.Generic[_T]):
    last_io: 'imgui.ImGuiIO' = None

    def __init__(self, wnd_T=typing.Type[_T]):
        self.wnd = wnd_T(self.draw)

        self.im_font = None
        self.is_init = False

        self.draw_funcs = {}

    def init_draw(self):
        print('init_draw')
        from nylib.pyimgui import imgui
        io = imgui.GetIO()
        io.IniFilename = None
        io.ConfigFlags = io.ConfigFlags & ~ imgui.ImGuiConfigFlags_ViewportsEnable  # disable multi-window
        font_dir = pathlib.Path(os.environ['WINDIR']) / 'fonts'
        if (font_file := font_dir / 'msyh.ttc').is_file():
            self.im_font = io.Fonts.AddFontFromFileTTF(str(font_file), 16, None, io.Fonts.GetGlyphRangesChineseFull())
            io.Fonts.Build()
            self.wnd.InvalidateDeviceObjects()
        self.is_init = True

    def draw(self):
        if not self.is_init:
            self.wnd.CallBeforeFrameOnce(self.init_draw)
        from nylib.pyimgui.imgui import ctx
        with ctx.PushFont(self.im_font) if self.im_font else contextlib.nullcontext():
            for name, draw_func in self.draw_funcs.items():
                try:
                    draw_func()
                except Exception as e:
                    print(f'Error in draw_func {name}:')
                    traceback.print_exc()

    def attach(self):
        self.wnd.Attach()


def main():
    print('Hello, world!')
    print(f'python version: {sys.version}')
    print('sys.executable:', sys.executable)
    print('os.getcwd():', os.getcwd())
    print('__file__:', __file__)

    import ctypes.wintypes
    if ctypes.windll.kernel32.GetModuleHandleW('d3d11.dll'):
        from nylib.pyimgui import Dx11Inbound
        setattr(sys, '_gui_', gui := Gui(Dx11Inbound))
    elif ctypes.windll.kernel32.GetModuleHandleW('d3d12.dll'):
        from nylib.pyimgui import Dx12Inbound
        setattr(sys, '_gui_', gui := Gui(Dx12Inbound))
    else:
        raise RuntimeError('No supported graphics API found')

    threading.Timer(.5, gui.attach).start()

    def run_script(path):
        with open(path, 'r', encoding='utf-8') as f:
            code = compile(f.read(), path, 'exec')
        try:
            exec(code, namespace := {'__file__': path})
        except Exception:
            traceback.print_exc()
            raise
        return namespace.get('res')

    RpcServer(rf'\\.\\pipe\\GamePipe-pid-{os.getpid()}', {
        'run_script': run_script,
    }).serve()


main()
