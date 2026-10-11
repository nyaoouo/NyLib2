> 本文档为 inbound.md 的中文阅读副本；英文版为权威来源（canonical）。

<!-- dt:meta v="1" lang="zh" source="inbound.md" -->

<!-- dt:section id="__preamble__" hash="5be877390b9d" -->
# 入站覆盖层

在另一个进程自己的 D3D/GL/VK 渲染器内绘制，原地挂钩（不需要
额外的交换链）- 典型的 ESP/训练器覆盖层形状。从目标进程内部
运行此程序（例如注入的 Python）。

<!-- dt:section id="attach-0" hash="ff52ff0e0b63" -->
## 附加

```python
import time
import nylib.pyimgui as pyimgui

def render(renderer):
    ...  # imgui.Begin / draw calls, same callback shape as index.md

renderer = pyimgui.CreateInbound(render)
renderer.Attach()
renderer.inputPolicy = pyimgui.InputPolicy.PassAll
time.sleep(3)
renderer.Detach()
```

`CreateInbound(renderCallback, frontend=None)` 从进程中已加载的任何单个 `d3d9/10/11/12.dll` 选择前端；当加载了多个 D3D 运行时时，传递 `frontend=`（`'dx9'`、`'dx10'`、`'dx11'`、`'dx12'`、`'gl3'`、`'vk'` 之一）（否则会抛出异常并列出已加载的集合），或直接构造类（`Dx11Inbound`、`Dx12Inbound`、...）。`Attach()` 安装钩子并开始调用 `renderCallback`；`Detach()` 移除它。

你的 `renderCallback` 总是在拥有游戏呈现调用的线程上运行 - 只能从那里调用 `pyimgui`/`pyimgui.esp`，不能从其他线程调用。

<!-- dt:section id="knobs-0" hash="9c55b1d9a68b" -->
## 常用设置

- `inputPolicy` （`pyimgui.InputPolicy.Auto`/`CaptureAll`/`PassAll`，默认
  `Auto`）：`Auto` 仅在 ImGui 自身需要时才捕获鼠标/键盘
  （`io.WantCaptureMouse`/`WantCaptureKeyboard`）；`CaptureAll` 总是捕获；
  `PassAll` 从不调用 ImGui 的按钮、滚轮或键盘处理程序，所以游戏获得它们而
  ImGui 不获得（它仍然能看到其他一切，包括光标移动）。
- `viewportsEnable` （仅适用于 `Dx11Inbound`/`Dx12Inbound`，默认 `True`）：
  设置为 `False` 以将 ImGui 窗口保持在游戏窗口内，而不是作为独立的 OS 窗口
  浮动。
