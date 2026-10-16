> 本文档为 index.md 的中文阅读副本；英文版为权威来源（canonical）。

<!-- dt:meta v="1" lang="zh" source="index.md" -->

<!-- dt:section id="__preamble__" hash="de89338dd055" -->
# nylib.pyimgui

直接 Dear ImGui 1.91.5-docking 的 Python 绑定，具有 DX9/DX10/DX11/DX12/
GL3/VK 前端。每个前端都有一个独立窗口类和一个注入的 "inbound" 类，
用于在另一个进程自己的渲染器内绘制（参见
[inbound.md](inbound.md)）。

关键词: Dear ImGui, imgui, pyimgui, Dx9Window, Dx11Window, Dx12Window, Dx11Inbound, Dx12Inbound, inbound, overlay, ESP, DirectX, DX11, DX12, OpenGL3, Vulkan, render hook, in-process overlay, pybind11

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

<!-- dt:section id="gamepad-0" hash="25597a36b3ea" -->
## 手柄

`gamepadPolicy` (`pyimgui.GamepadPolicy`，默认 `WhenForeground`) 控制 ImGui 是否读取已连接的手柄。在默认情况下，ImGui 仅在其绘制所用的窗口为前台窗口时读取手柄，因此后台窗口默认不再对控制器做出反应；`Always` 每帧读取手柄，`Never` 则不读取；`NavEnableGamepad` 无论如何都保持启用。在 `inputPolicy = PassAll` 下，Inbound 和叠加层永远不读取手柄，无论 `gamepadPolicy` 怎么说。对于 `Always`，ImGui 也会在无人观察的帧上读取手柄——例如当叠加层的目标被最小化时——因此按键可以激活视线外的获焦小部件。当门打开时，如果手柄按钮已经被按住——例如窗口变成前台窗口——ImGui 会在该帧看到一次新的按键。

<!-- dt:section id="fonts-0" hash="b888623e8df0" -->
## 字体

`win32_font` 通过 DirectWrite 查找系统字体，并把它们加载进 ImGui 的
字体图集（font atlas）。`AutoInstall(locale=None, size_pixels=16.0)` 为每种
文字（拉丁文、该 locale 的文字、其他 CJK 与非拉丁文字、emoji）各选一个字体，
合并成一个 `ImFont`；`AutoInstallChain(families, ...)` 按顺序合并指定的
字体族；`AutoInstallFamily(family, ...)` 把一个字体族放在自动链的最前面。
三者都返回合并后的 `ImFont`，没有任何匹配时返回 `None`。

图集属于 ImGui 上下文，而上下文由 `Serve()`（或 inbound 钩子）创建，
所以要在 `CallBeforeFrameOnce` 里安装字体；它可以在 `Serve()` 之前就排入队列：

```python
from nylib.pyimgui import Dx11Window, win32_font

fonts = {}

def load_fonts():
    fonts['ui'] = win32_font.AutoInstall(locale='zh-CN', size_pixels=16.0)

wnd = Dx11Window(render)
wnd.CallBeforeFrameOnce(load_fonts)
wnd.Serve()
```

在没有上下文时安装，或在渲染回调内部（`NewFrame()` 与 `Render()` 之间）
安装，会抛出 `RuntimeError`。只能在渲染线程上安装：从其他线程调用不会被
检测出来，并且会与帧发生竞争。在第一帧之前安装的字体是图集中的第一个字体，
会成为默认字体；用 `imgui_ctx.PushFont(font)` 可以为一段代码切换字体。
在第一帧之后安装的字体需要调用 `wnd.InvalidateDeviceObjects()`，让后端上传
重建后的图集纹理。这个调用只记录一个请求，在下一帧开始前才执行，所以在渲染回调
里调用也是安全的；请在安装字体的同一个 `CallBeforeFrameOnce` 回调里调用它，
这样不会有任何一帧用旧纹理绘制。

每个文字的字体都会贡献它的全部字形，所以图集随 `size_pixels` 增长：
`AutoInstall(locale='zh-CN')` 在 16 px 时约为 4096x4096（64 MiB），24 px 时
4096x8192（128 MiB），32 px 时 4096x16384（256 MiB）。后端按每像素 4 字节上传
图集，而 D3D11/D3D12 只保证单个纹理能有 128 MiB，所以默认把安装限制在每边
16384 像素、总共 128 MiB 以内。超过边长上限的安装会先加宽图集；如果图集仍然
超出某个上限，这次安装会移除它添加的字体并抛出 `RuntimeError`。
`win32_font.SetAtlasLimits(max_side=None, max_mib=None)` 修改本进程的上限
（`None` 表示保持该项不变），`GetAtlasLimits()` 返回 `(max_side, max_mib)`：
在显存足够的 GPU 上需要更大的 CJK 字号时调大 `max_mib`，在 DX10 下设置
`max_side=8192`。

<!-- dt:section id="next-0" hash="03f1565c2acf" -->
## 下一步

- [inbound.md](inbound.md) - 在另一个进程自己的 D3D/GL/VK 渲染器内绘制。
- [esp.md](esp.md) - 世界到屏幕投影和 ESP 绘制辅助工具。
- [overlay.md](overlay.md) - 无框架桌面叠加层（`Dx11Window.overlay = True`）。
