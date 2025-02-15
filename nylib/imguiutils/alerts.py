import dataclasses
import time

from nylib.pyimgui import imgui
from nylib.pyimgui.imgui import ctx as imgui_ctx


class Alerts:
    DEBUG = 0
    INFO = 1
    WARNING = 2
    ERROR = 3

    TOP_LEFT = 10
    TOP_CENTER = 11
    TOP_RIGHT = 12

    # outline/text color, background color, background color hovered
    COLORS = {
        DEBUG: (imgui.ImVec4(0, 0, 0, 1), imgui.ImVec4(0.3, 0.3, 0.3, .5), imgui.ImVec4(0.3, 0.3, 0.3, .75)),
        INFO: (imgui.ImVec4(0, 1, 0, 1), imgui.ImVec4(0, 0.3, 0, .5), imgui.ImVec4(0, 0.3, 0, .75)),
        WARNING: (imgui.ImVec4(1, 1, 0, 1), imgui.ImVec4(0.3, 0.3, 0, .5), imgui.ImVec4(0.3, 0.3, 0, .75)),
        ERROR: (imgui.ImVec4(1, 0, 0, 1), imgui.ImVec4(0.3, 0, 0, .5), imgui.ImVec4(0.3, 0, 0, .75)),
    }

    @dataclasses.dataclass
    class _Alert:
        msg: str
        size: imgui.ImVec2
        level: int
        timeout: float
        dismissible: bool
        is_hovered: bool = False

    def __init__(self, pop_at=TOP_RIGHT, margin=5):
        self.alerts = []
        self.pop_at = pop_at
        self.margin = margin

    def add(self, msg, level=INFO, timeout=5., dismissible=True):
        self.alerts.append(self._Alert(msg, imgui.CalcTextSize(msg), level, timeout + time.time() if timeout > 0 else 0, dismissible))

    def render(self):
        if not self.alerts: return
        pos = imgui.GetWindowPos()
        vmin = imgui.GetWindowContentRegionMin()
        pos.x += vmin.x
        pos.y += vmin.y

        size = imgui.GetWindowSize()
        padding = imgui.GetStyle().FramePadding
        padding_item = imgui.GetStyle().ItemSpacing
        padding.x += padding_item.x
        padding.y += padding_item.y
        max_text_width = max(a.size.x for a in self.alerts) + padding.x * 2

        match self.pop_at:
            case Alerts.TOP_LEFT:
                pos.x += self.margin
                pos.y += self.margin
            case Alerts.TOP_CENTER:
                pos.x += (size.x - max_text_width) / 2
                pos.y += self.margin
            # case Alerts.TOP_RIGHT:
            case _:  # default
                pos.x += size.x - max_text_width - self.margin
                pos.y += self.margin
        to_remove = []
        now = time.time()
        for i, a in enumerate(self.alerts):
            imgui.SetCursorScreenPos(pos)
            col_line, col_bg, col_bg_hover = self.COLORS[a.level if a.level in self.COLORS else self.INFO]
            with imgui_ctx.PushStyleColor(imgui.ImGuiCol_Text, col_line):
                with imgui_ctx.PushStyleColor(imgui.ImGuiCol_Border, col_line):
                    with imgui_ctx.PushStyleColor(imgui.ImGuiCol_ChildBg, col_bg_hover if a.is_hovered else col_bg):
                        a_size = imgui.ImVec2(max_text_width, a.size.y + padding.y * 2 + 3)
                        with imgui_ctx.BeginChild(f"alert_{i}", a_size, child_flags=imgui.ImGuiChildFlags_Border):
                            imgui.Text(a.msg)
                            if a.dismissible and imgui.IsItemHovered():
                                a.is_hovered = True
                                if imgui.IsMouseClicked(0):
                                    to_remove.append(i)
                            else:
                                a.is_hovered = False
            if a.timeout and a.timeout < now:
                to_remove.append(i)
            pos.y += a_size.y + self.margin
        for i in reversed(to_remove):
            self.alerts.pop(i)
