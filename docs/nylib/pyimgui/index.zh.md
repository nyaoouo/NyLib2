> 本文档为 index.md 的中文阅读副本；英文版为权威来源（canonical）。

<!-- dt:meta v="1" lang="zh" source="index.md" -->

<!-- dt:section id="__preamble__" hash="7166dbebea27" -->
# nylib.pyimgui

直接 Dear ImGui 1.91.5-docking 的 Python 绑定，具有 DX9/DX10/DX11/DX12/
GL3/VK 前端。每个前端都有一个独立窗口类和一个注入的 "inbound" 类，
用于在另一个进程自己的渲染器内绘制（参见
[inbound.md](inbound.md)）。

关键词: Dear ImGui, imgui, pyimgui, Dx9Window, Dx11Window, Dx12Window, Dx11Inbound, Dx12Inbound, inbound, overlay, ESP, DirectX, DX11, DX12, OpenGL3, Vulkan, render hook, in-process overlay, pybind11, texture, CreateTextureFromPixels, DecodeImage, grayscale, mipmap, sampler

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

<!-- dt:section id="textures-0" hash="1a4b09708557" -->
## 纹理

`CreateTexture(filename)` 和 `CreateTextureFromPixels(width, height,
pixels)` 存在于 DX11 和 DX12 渲染器上（`Dx11Window`/`Dx12Window`，
独立或叠加模式，以及 `Dx11Inbound`/`Dx12Inbound`）；两种后端都还接受
`mips=False`。DX9、DX10、GL3 和 VK 都没有这两个方法：请检查
`hasattr(renderer, 'CreateTexture')` 并做好回退，例如回退到绘制一个
纯色矩形。两种后端返回的对象共享相同的成员：
`handle`（ImGui 纹理 id）、`width`、`height`、`size`、`mipLevels`、
`bool()` 和 `FreeTexture()`；DX12 还有 `LoadTextureFromFile`。

```python
# needs: running pyimgui window
import pathlib
from nylib.pyimgui import Dx11Window, imgui
import nylib.pyimgui as pyimgui

textures = {}

def make_ppm(path, width, height, rgb=(200, 120, 40)):
    header = f'P6\n{width} {height}\n255\n'.encode('ascii')
    path.write_bytes(header + bytes(rgb) * (width * height))

def load_textures(wnd):
    path = pathlib.Path('texture_demo.ppm')
    make_ppm(path, 64, 64)
    textures['file'] = wnd.CreateTexture(str(path))
    textures['gray'] = wnd.CreateTexture(
        str(path), transform=pyimgui.TextureTransform.GrayscaleBT709)
    textures['pixels'] = wnd.CreateTextureFromPixels(2, 2, bytes((
        255, 0, 0, 255, 0, 255, 0, 255,
        0, 0, 255, 255, 255, 255, 255, 255,
    )))

def render(wnd):
    for tex in textures.values():
        imgui.Image(tex.handle, imgui.ImVec2(64, 64))
        imgui.SameLine()

wnd = Dx11Window(render)
wnd.CallBeforeFrameOnce(lambda: load_textures(wnd))
wnd.Serve()
```

时机：渲染器的设备必须已经存在。那是在 `Serve()` 运行期间（无论是在
`CallBeforeFrameOnce` 还是在渲染回调中），对于 inbound 渲染器则是在
其第一帧之后。否则，包括在回调从 `Serve()` 中抛出异常之后，创建会
抛出 `RuntimeError`。`CallBeforeFrameOnce` 可以在 `Serve()` 之前排队，
如上面的示例所示。

线程：在渲染线程上创建纹理，无论是在 `CallBeforeFrameOnce` 中还是在
渲染回调中都可以；并不要求必须使用 `CallBeforeFrameOnce`。从其他线程
调用会抛出 `RuntimeError`（"render thread"）。解码则可以在任何地方
进行：`pyimgui.DecodeImage(path)` 可以在任何线程上运行，释放 GIL 且
不需要窗口，因此可以让工作线程负责解码，渲染线程只调用
`CreateTextureFromPixels`。每次创建和解码调用都会在解码和上传期间
释放 GIL，因此其他 Python 线程可以继续运行。绘制只能发生在渲染回调
中。DX12 的上传会等待其 GPU 拷贝完成，因此每帧的上传次数要保持
较小。

```python
# needs: running pyimgui window
import pathlib
import queue
import threading
from nylib.pyimgui import Dx11Window, imgui
import nylib.pyimgui as pyimgui

def make_ppm(path, width, height, rgb):
    header = f'P6\n{width} {height}\n255\n'.encode('ascii')
    path.write_bytes(header + bytes(rgb) * (width * height))

paths = []
for i, rgb in enumerate([(200, 60, 60), (60, 200, 60), (60, 60, 200)]):
    p = pathlib.Path(f'tile_{i}.ppm')
    make_ppm(p, 32, 32, rgb)
    paths.append(p)

decoded = queue.Queue()

def worker():
    for p in paths:
        decoded.put(pyimgui.DecodeImage(str(p)))

threading.Thread(target=worker, daemon=True).start()
textures = []

def render(wnd):
    for _ in range(2):
        try:
            img = decoded.get_nowait()
        except queue.Empty:
            break
        textures.append(
            wnd.CreateTextureFromPixels(img.width, img.height, img.pixels))
    for tex in textures:
        imgui.Image(tex.handle, imgui.ImVec2(32, 32))
        imgui.SameLine()

wnd = Dx11Window(render)
wnd.Serve()
```

不要在 `CallBeforeFrameOnce` 的回调内部重新把自己排队：在其中排队的
回调会在同一帧内运行，因此一个不断重新排队自身的回调永远不会让出
一帧。应该像上面的示例那样，把工作分散到渲染回调的多个帧中完成。

生命周期：在绘制期间保持返回对象存活，因为 `handle` 只是一个普通的
int。丢弃它，或调用 `FreeTexture()`，会在下一个帧边界释放它；在
DX12 上则要等到 GPU 使用完毕之后才释放。调用 `FreeTexture()` 之后，
该对象为 falsy 且不会绘制任何内容。纹理属于单个会话：一旦 `Serve()`
返回或抛出异常，或者 inbound 渲染器被销毁，再读取 `handle` 就会
抛出 `RuntimeError`，因此新会话需要创建新的纹理。
`InvalidateDeviceObjects()`（在字体变化之后调用）不会影响纹理。DX12
最多同时持有 4094 个存活的纹理；超过这个数量，创建会抛出
`RuntimeError`。DX12 的 `LoadTextureFromFile` 会改变 `handle`，
DX12 的 `UpdatePixels` 也一样。

格式与内存：`pixels` 是每个像素 4 字节、按 `format` 指定的通道顺序
排列，第 0 行在顶部，存放在一个 C 连续的缓冲区中（`bytes`、
`bytearray`、`memoryview`、`array.array`，或 numpy）；默认的
`format=pyimgui.TextureFormat.RGBA8` 是非预乘 alpha。
`format=pyimgui.TextureFormat.BGRA8` 在相同布局下交换红、蓝两个
字节；设备不支持 BGRA8 采样时，创建会抛出 `RuntimeError`。
`premultiplied=True` 用于记录颜色已经预先乘以 alpha——绘制时需要
配合下文的 `SetTextureBlend`——并且在 `mips=True` 时会把 mip 链的
生成方式切换为简单的 2x2 平均，而不是默认的按 alpha 加权的过滤器；
两者都可以通过 `tex.format` 和 `tex.premultiplied` 读回。紧密排列
的行需要恰好 `width*height*4` 字节；使用 `rowPitch=n` 时，每行间隔
`n` 字节，缓冲区至少需要 `n*height` 字节。过短的缓冲区会在读取任何
内容之前就抛出 `ValueError`。一张 4096x4096 的纹理在每像素 4 字节
下占用 64 MiB，`mips=True` 会额外增加大约三分之一；单边最多为
16384 px，与上文字体图集的限制一致。

绘制：`imgui.Image`、`dl.AddImage`、`dl.AddImageQuad`（旋转或斜切
四边形，支持逐角 UV），以及 `esp.add_image_triangle`（任意带纹理的
三角形，例如把裁剪后的多边形绘制为扇形；参见
[esp.md](esp.md)）。UV (0, 0) 对应左上角的像素。预乘纹理（见下文）
需要在同一绘制列表上用 `SetTextureBlend(dl, pyimgui.TextureBlend.Premultiplied)`
和 `ResetTextureBlend(dl)` 包裹其绘制调用；该作用域可以与下文的
采样器作用域组合使用——每次调用只改变自己的那一半状态，保留另一半。
只在该作用域内绘制预乘纹理，非预乘（直通）alpha 的纹理（包括文本和
形状）应留在作用域之外，并且需要自己对任何 ImGui 的着色（tint）做
预乘（`(r*a, g*a, b*a, a)`）。

```python
# needs: running pyimgui window
from nylib.pyimgui import Dx11Window, imgui
import nylib.pyimgui as pyimgui

tinted = {}

def load_tinted(wnd):
    # one orange texel at ~63% alpha, already multiplied into the colour,
    # in BGRA8 byte order
    texel = bytes((25, 75, 126, 160))
    tinted['tex'] = wnd.CreateTextureFromPixels(
        1, 1, texel, format=pyimgui.TextureFormat.BGRA8, premultiplied=True)

def render(wnd):
    if 'tex' not in tinted:
        return
    dl = imgui.GetBackgroundDrawList()
    wnd.SetTextureBlend(dl, pyimgui.TextureBlend.Premultiplied)
    dl.AddImage(tinted['tex'].handle, imgui.ImVec2(40, 40), imgui.ImVec2(104, 104))
    wnd.ResetTextureBlend(dl)

wnd = Dx11Window(render)
wnd.CallBeforeFrameOnce(lambda: load_tinted(wnd))
wnd.Serve()
```

采样：默认情况下，每个纹理在两种后端上都只在 mip 0 上进行双线性
采样。两种后端都在创建时额外支持 `mips=True`，以及一个逐次绘制的采样器
作用域：用
`SetTextureSampler(dl, pyimgui.TextureFilter.Point/Linear/Anisotropic)`
和同一绘制列表上的 `ResetTextureSampler(dl)` 包裹绘制调用。`Point`
能让放大后的像素保持清晰，`Linear` 是跨 mip 的三线性过滤，
`Anisotropic` 适合以较浅角度观察的拉伸图像。文本应留在 `Point`
作用域之外，因为它在该作用域内会失去抗锯齿效果。该作用域不支持
嵌套：`Reset` 会恢复到后端的默认设置。

```python
# needs: running pyimgui window
import pathlib
from nylib.pyimgui import Dx11Window, imgui
import nylib.pyimgui as pyimgui

minimap = {}

def make_ppm(path, width, height, rgb=(80, 140, 90)):
    header = f'P6\n{width} {height}\n255\n'.encode('ascii')
    path.write_bytes(header + bytes(rgb) * (width * height))

def load_minimap(wnd):
    path = pathlib.Path('minimap_demo.ppm')
    make_ppm(path, 128, 128)
    minimap['tex'] = wnd.CreateTexture(str(path), mips=True)

def render(wnd):
    if 'tex' not in minimap:
        return
    dl = imgui.GetBackgroundDrawList()
    wnd.SetTextureSampler(dl, pyimgui.TextureFilter.Linear)
    dl.AddImageQuad(
        minimap['tex'].handle,
        imgui.ImVec2(40, 40), imgui.ImVec2(140, 60),
        imgui.ImVec2(120, 160), imgui.ImVec2(20, 140),
    )
    wnd.ResetTextureSampler(dl)

wnd = Dx11Window(render)
wnd.CallBeforeFrameOnce(lambda: load_minimap(wnd))
wnd.Serve()
```

大图：内存占用遵循上面的格式规则（4096x4096 时为 64 MiB，再加上
`mips` 带来的约三分之一额外占用）。当纹理被绘制得远小于其尺寸时，
在默认采样器下会出现锯齿；`mips=True` 配合 `Linear` 或
`Anisotropic` 作用域可以避免这个问题。丢弃纹理会在下一个帧边界释放
它，因此缓存可以丢弃它不再显示的内容。对于非常大的图像，可以考虑
分块（tiling）：使用多个较小的纹理，随视图变化而创建和丢弃。

灰度：在 `CreateTexture`、DX12 的 `LoadTextureFromFile` 和
`DecodeImage` 上使用
`transform=pyimgui.TextureTransform.GrayscaleBT709` 会在上传之前
对图像进行一次转换：在存储的 8 位值上计算
`Y = (2126 R + 7152 G + 722 B + 5000) // 10000`，输出
`(Y, Y, Y, A)`。对于普通的 sRGB 图像，这是 BT.709 的亮度(luma)，
而不是线性亮度。alpha 和尺寸保持不变，mipmap 会在转换之后生成，
不指定 `transform` 则什么都不会改变。

更新像素：`tex.UpdatePixels(pixels, *, rowPitch=0, rect=None)` 用
一个同样尺寸的新缓冲区替换纹理的像素，像素和 `rowPitch` 的规则与
`CreateTextureFromPixels` 相同。`rect=(x, y, w, h)` 则只更新该矩形
区域，要求纹理创建时使用 `mips=False`（`mips=True` 的纹理会抛出
`ValueError`）；这时 `pixels` 和 `rowPitch` 遵循同样的规则，但针对
的是一张 `w` x `h` 的图像，矩形超出 `0 <= x`、`0 <= y`、`w >= 1`、
`h >= 1`、`x + w <= width`、`y + h <= height` 的范围同样会抛出
`ValueError`。只能在渲染线程上调用，即在渲染回调或
`CallBeforeFrameOnce` 中；在其他线程调用、对空的或已释放的纹理调用、
或在会话结束之后调用，都会抛出 `RuntimeError`；缓冲区尺寸与纹理的
宽高不符时抛出 `ValueError`。用 `mips=True` 创建的纹理会根据新像素
重建整条 mip 链。DX11 原地更新并保持 `handle` 不变，所以本帧中更早
记录的绘制也会显示新像素，矩形更新也是如此；DX12 每次调用都会上传
一张新纹理并改变 `handle`，所以本帧中更早记录的绘制仍显示旧像素——
请在绘制时再读取 `handle`。DX12 没有更便宜的局部更新路径：即使是
`rect` 更新，也会把整张纹理拷贝进一个新的资源和插槽并等待这次拷贝
完成，和一次完整更新的开销完全相同。

```python
# needs: running pyimgui window
import pathlib
from nylib.pyimgui import Dx11Window, imgui

live = {}
colors = [(200, 60, 60), (60, 200, 60), (60, 60, 200)]

def make_ppm(path, width, height, rgb):
    header = f'P6\n{width} {height}\n255\n'.encode('ascii')
    path.write_bytes(header + bytes(rgb) * (width * height))

def load_live(wnd):
    path = pathlib.Path('update_demo.ppm')
    make_ppm(path, 64, 64, colors[0])
    live['tex'] = wnd.CreateTexture(str(path))

def render(wnd):
    if 'tex' not in live:
        return
    frame = imgui.GetFrameCount()
    if frame % 30 == 0:
        rgb = colors[(frame // 30) % len(colors)]
        live['tex'].UpdatePixels(bytes(rgb + (255,)) * (64 * 64))
    imgui.Image(live['tex'].handle, imgui.ImVec2(64, 64))

wnd = Dx11Window(render)
wnd.CallBeforeFrameOnce(lambda: load_live(wnd))
wnd.Serve()
```

<!-- dt:section id="next-0" hash="03f1565c2acf" -->
## 下一步

- [inbound.md](inbound.md) - 在另一个进程自己的 D3D/GL/VK 渲染器内绘制。
- [esp.md](esp.md) - 世界到屏幕投影和 ESP 绘制辅助工具。
- [overlay.md](overlay.md) - 无框架桌面叠加层（`Dx11Window.overlay = True`）。
