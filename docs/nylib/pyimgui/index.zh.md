> 本文档为 index.md 的中文阅读副本；英文版为权威来源（canonical）。

<!-- dt:meta v="1" lang="zh" source="index.md" -->

<!-- dt:section id="__preamble__" hash="8ed673a10f0f" -->
# nylib.pyimgui

Dear ImGui 1.91.5-docking 的 Python 直接绑定，包含 DX9/DX10/DX11/DX12/
GL3/VK 前端。每个前端都有一个独立窗口类和一个注入的
"inbound" 类，用于在另一个进程自己的渲染器内进行绘制（参见
[inbound.md](inbound.md)）。

<!-- dt:section id="build-0" hash="b7381ce1ed6c" -->
## 构建

编译后的 `.pyd` 是特定于 CPython-ABI 的，不附带在发布中；从一个签出的版本构建它：

```bash
.\.venv\Scripts\python.exe scripts\pyimgui2\pyimgui_generate.py --skip --skip-stubs
```

查看仓库 [readme.md](../../../readme.md) 获取完整的构建/安装矩阵。

<!-- dt:section id="minimal-standalone-window-0" hash="ed028d3ab092" -->
## 最小的独立窗口

```python
from nylib.pyimgui import Dx11Window
from nylib.pyimgui import imgui
from nylib.pyimgui.imgui import ctx as imgui_ctx

def render(wnd):
    with imgui_ctx.Begin("Hello") as (show, _open):
        if show:
            imgui.Text("from nylib.pyimgui")
            if imgui.Button("Close"):
                wnd.Close()

wnd = Dx11Window(render)
wnd.Serve()
```

`imgui` 一对一镜像 C++ Dear ImGui API（`imgui.Begin`、`imgui.Button` 等）。
`imgui.ctx` 将 `Begin*`/`End*` 对包装为上下文管理器，总是
调用匹配的 `End*`，即使发生异常。`CallBeforeFrameOnce(fn)`
将 `fn` 加入队列以运行一次，在下一帧之前 - 对于从
回调内部进行的一次性设置很方便。`Close()` 在当前帧之后
结束 `Serve()`。

构建会将其输出复制到 `nylib/`，所以这些文档导入
`nylib.pyimgui`。当 `scripts/pyimgui2` 在 `sys.path` 上时，
相同的扩展也可以作为顶层 `pyimgui` 导入（演示就是这样做的）；
每个进程使用一个名称，永远不要同时使用两个。

<!-- dt:section id="next-0" hash="e866af0038ba" -->
## 下一步

- [inbound.md](inbound.md) - 在另一个进程自己的 D3D/GL/VK 渲染器内绘制。
- [esp.md](esp.md) - 世界到屏幕投影和 ESP 绘制辅助工具。
- overlay 模式（`Dx11Window.overlay = True`，无框架桌面叠加层）：稍后记录。
