import typing

from ..pyimgui import imgui
from ..pyimgui.imgui import ctx as imgui_ctx
from ..utils.handles import Handles

handles = Handles()

OK_CANCEL = [('OK', True), ('Cancel', False)]
YES_NO = [('Yes', True), ('No', False)]
OK = [('OK', None)]
YES_NO_CANCEL = [('Yes', True), ('No', False), ('Cancel', None)]
NO_BUTTON = []


class MessageBox:
    def __init__(self, message: str | typing.Callable, title: str = None, buttons: list[tuple[str, typing.Any]] = None, callback: callable = None):
        self.handle = handles.get()
        self.title = (title or "") + f"###__message_box_{self.handle}"

        self.message = message
        self.buttons = buttons or OK_CANCEL
        self.callback = callback

        if isinstance(self.message, str):
            self.render_message = self.render_text_message
        else:
            self.render_message = self.render_custom_message

    def __free_handle(self):
        if self.handle:
            handles.free(self.handle)

    def __del__(self):
        self.__free_handle()

    def _call_callback(self, value=None):
        self.__free_handle()
        self.handle = None
        if self.callback:
            self.callback(value)

    def render_text_message(self):
        imgui.Text(self.message)

    def render_custom_message(self):
        self.message()

    def render(self):
        if not self.handle: return False
        flags = imgui.ImGuiWindowFlags_NoDocking | imgui.ImGuiWindowFlags_NoResize | imgui.ImGuiWindowFlags_AlwaysAutoResize
        with imgui_ctx.Begin(self.title, None if self.buttons else True, flags) as (show, window_open):
            if not window_open:
                self._call_callback(None)
                return False
            if not show:
                return True
            imgui.BringWindowToFocusFront(imgui.GetCurrentWindow())
            self.render_message()
            for text, value in self.buttons:
                if imgui.Button(text):
                    self._call_callback(value)
                    return False
                imgui.SameLine()
        return True
