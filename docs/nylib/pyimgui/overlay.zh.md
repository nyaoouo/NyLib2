> 本文档为 overlay.md 的中文阅读副本；英文版为权威来源（canonical）。

<!-- dt:meta v="1" lang="zh" source="overlay.md" -->

<!-- dt:section id="__preamble__" hash="3cca6bcb6d6f" -->
# 覆盖层模式

`overlay = True` 在 `Dx11Window`/`Dx12Window` 上会将一个独立窗口转变为无框桌面画布，它在整个显示器上绘制（或在另一个窗口的客户端区域上），而不是在自己有边框的窗口内。该画布允许鼠标点击穿过它传递到后面的任何内容，除非你正在与其 ImGui 窗口之一交互 - 这是 ESP 或 HUD 叠加层的常见形式。

<!-- dt:section id="monitor-mode-0" hash="a6435686445e" -->
## 监视器模式

未设置目标时，画布覆盖一个监视器：

```python
from nylib.pyimgui import Dx11Window
from nylib.pyimgui import imgui
import nylib.pyimgui.esp as esp

def render(wnd):
    cam = esp.Camera.from_pov(location=(0.0, 0.0, 500.0), rotation=(0.0, 0.0, 0.0), fov=90.0)
    dl = esp.get_canvas_draw_list()
    screen = esp.world_to_screen(cam, (100.0, 0.0, 0.0))
    if screen is not None:
        esp.add_text_outlined(dl, screen, esp.Rgba(255, 0, 0), "target")
    imgui.Begin("Overlay")
    imgui.Text("drawn on the desktop")
    imgui.End()

wnd = Dx11Window(render)
wnd.overlay = True
wnd.Serve()
```

`overlayMonitor`（默认为0，主监视器）从`GetMonitors()`中选择画布覆盖的监视器。

<!-- dt:section id="target-mode-0" hash="9c430834a5c1" -->
## 目标模式

将 `overlayTarget` 设置为跟随一个窗口：对于固定目标使用 `int` HWND，或使用一个可调用的"查找器"（例如 `WindowQuery`），返回 HWND、0 或 `None`：

```python
from nylib.pyimgui import Dx11Window, WindowQuery

def found(hwnd):
    print("target found:", hwnd)

def lost():
    print("target lost")

def render(wnd):
    pass  # draw relative to wnd.targetHwnd's client area

wnd = Dx11Window(render)
wnd.overlay = True
wnd.overlayTarget = WindowQuery(exe="notepad.exe")
wnd.targetFoundCallback = found
wnd.targetLostCallback = lost
wnd.Serve()
```

画布每帧跟踪目标窗口的客户端区域，在找到/丢失时触发 `targetFoundCallback`/`targetLostCallback`，并将当前窗口暴露为 `targetHwnd`/`targetPid`（当没有目标时都为 0）。当目标被最小化或以其他方式隐藏时，画布会隐藏，渲染回调以低速率继续运行而不是停止，这样您的状态保持活着。

<!-- dt:section id="z-order-0" hash="a8ff50464be3" -->
## Z 顺序

`overlayZOrder` 决定画布相对于被跟踪目标的位置
（在监视器模式下被忽略，其中画布始终在顶部）：

- `AboveTarget`（默认）：画布保持直接位于目标的
  顶级窗口上方，因此另一个应用程序被带到目标前面时会覆盖
  叠加层；如果目标本身是始终在顶部的，则会将画布
  直接保持在其上方。
- `Topmost`：画布始终保持在顶部并位于目标上方，即使
  另一个应用程序位于目标前面。

在 `Topmost` 中（以及在监视器模式中）画布会把自己放回到
成为前台窗口的始终在顶部的窗口上方，因此两个这样的窗口
可以在一帧内交换位置。Z 顺序每帧检查一次，因此
切换应用程序可以在单个帧内覆盖或取消覆盖画布。

<!-- dt:section id="click-through-and-input-0" hash="2276d9712b9c" -->
## 点击穿透和输入

`inputPolicy`（与入站模式共享，见[inbound.md](inbound.md)）决定鼠标输入是否到达画布或传递给下方窗口：

- `Auto`（默认）：除非最后一帧想要捕获鼠标（悬停或与 ImGui 窗口交互），否则传递；在画布外开始的拖动，即使稍后跨越 ImGui 窗口也继续传递，直到释放每个按住的按钮；点击捕获的区域将画布置于前台。
- `CaptureAll`：永不传递。
- `PassAll`：始终传递；ImGui 仍看到光标位置但忽略按钮、滚轮、按键和游戏手柄，如入站模式，在切换到它时释放它持有的任何内容。

按键转到前台窗口，在任何策略下：叠加层不能从游戏中取走按键，也不能将其交给游戏。点击叠加层窗口使叠加层成为前台窗口，所以按键然后转到叠加层——而不是游戏——直到你点击回游戏；在 `PassAll` 下叠加层忽略它们，但游戏仍不获得它们。叠加层仅在它是前台窗口时读取游戏手柄（在 `PassAll` 下不读）；当你点击进叠加层时游戏中已持有的控制器按钮在下一帧读作新按下，可以立即激活任何具有焦点的小部件。

当弹出窗口打开时，整个画布捕获鼠标输入——即使在任何 ImGui 窗口外——直到弹出窗口关闭，所以为游戏准备的点击首先关闭弹出窗口并将焦点转到叠加层。保持渲染回调快速：一个缓慢的会延迟被卡住的捕获何时能被释放。

<!-- dt:section id="dpi-0" hash="9d7125a03ef4" -->
## DPI

`overlayDpiAware`（默认为 `True`）：画布和每个放置查询
（监视器矩形、目标矩形、光标）使用物理像素，无论进程本身的
DPI 感知如何。将其设置为 `False` 以改为使用 `Serve()` 线程的
当前 DPI 上下文。

<!-- dt:section id="knobs-0" hash="11f8ee62e32e" -->
## 参数

- `overlay`（布尔值，默认 `False`）：在 `Serve()` 之前设置，以叠加层
  模式而非普通窗口运行。
- `overlayTarget`（默认 `None`）：`None` 表示监视器模式，一个 `int` HWND
  表示固定目标，或一个查找器可调用对象。
- `overlayMonitor`（int，默认 `0`）：`GetMonitors()` 中的索引，用于
  监视器模式。
- `overlayZOrder`（`OverlayZOrder`，默认 `AboveTarget`）：参见上文的 Z 顺序。
- `overlayDpiAware`（布尔值，默认 `True`）：参见上文的 DPI。
- `targetFoundCallback` / `targetLostCallback`：每次目标被找到/丢失时
  各调用一次。
- `targetHwnd` / `targetPid`（只读）：当前目标，无目标时为 0。
- `inputPolicy`（`InputPolicy`，默认 `Auto`）：参见上文的 Click-through。
