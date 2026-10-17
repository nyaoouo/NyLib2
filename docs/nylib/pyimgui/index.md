# nylib.pyimgui

Direct Dear ImGui 1.91.5-docking bindings for Python, with DX9/DX10/DX11/DX12/
GL3/VK frontends. Each frontend has a standalone-window class and an injected
"inbound" class for drawing inside another process's own renderer (see
[inbound.md](inbound.md)).

Keywords: Dear ImGui, imgui, pyimgui, Dx9Window, Dx11Window, Dx12Window, Dx11Inbound, Dx12Inbound, inbound, overlay, ESP, DirectX, DX11, DX12, OpenGL3, Vulkan, render hook, in-process overlay, pybind11, texture, CreateTextureFromPixels, DecodeImage, grayscale, mipmap, sampler

## Build

The compiled `.pyd` is CPython-ABI-specific and not shipped; build it from a
checkout:

```bash
.\.venv\Scripts\python.exe scripts\pyimgui2\pyimgui_generate.py --skip --skip-stubs
```

See the repo [readme.md](../../../readme.md) for the full build/install matrix.

## Minimal standalone window

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

`imgui` mirrors the C++ Dear ImGui API 1:1 (`imgui.Begin`, `imgui.Button`, ...).
`imgui.ctx` wraps the `Begin*`/`End*` pairs as context managers that always
call the matching `End*`, even on an exception. `CallBeforeFrameOnce(fn)`
queues `fn` to run once, before the next frame - handy for one-time setup from
inside the callback. `Close()` ends `Serve()` after the current frame.

The build copies its outputs into `nylib/`, so these docs import
`nylib.pyimgui`. The same extension is also importable as a top-level `pyimgui`
when `scripts/pyimgui2` is on `sys.path` (the demo does this); use one name per
process, never both.

## Gamepad

`gamepadPolicy` (`pyimgui.GamepadPolicy`, default `WhenForeground`) controls
whether ImGui reads a connected gamepad. Under the default, ImGui reads the
gamepad only while the window it draws into is the foreground window, so a
background window no longer reacts to a controller by default; `Always`
reads the gamepad on every frame, and `Never` on none; `NavEnableGamepad`
stays on regardless. Inbound and the overlay never read the gamepad under
`inputPolicy = PassAll`, whatever `gamepadPolicy` says. With `Always`, ImGui
also reads the gamepad on frames nobody sees - for example while an overlay's
target is minimized - so a press can activate a focused widget out of sight.
When the gate opens while a pad button is already held - for example the
window becomes foreground - ImGui sees a fresh press on that frame.

## Fonts

`win32_font` finds system fonts through DirectWrite and loads them into ImGui's
font atlas. `AutoInstall(locale=None, size_pixels=16.0)` merges one font per
script (Latin, the locale's script, the other CJK and non-Latin scripts, emoji)
into a single `ImFont`; `AutoInstallChain(families, ...)` merges the named
families in order; `AutoInstallFamily(family, ...)` puts one family in front of
the automatic chain. Each returns the merged `ImFont`, or `None` when nothing
matched.

The atlas belongs to the ImGui context, which `Serve()` (or the inbound hook)
creates, so install fonts from `CallBeforeFrameOnce`; it can be queued before
`Serve()`:

```python
from nylib.pyimgui import Dx11Window, win32_font

fonts = {}

def load_fonts():
    fonts['ui'] = win32_font.AutoInstall(locale='zh-CN', size_pixels=16.0)

wnd = Dx11Window(render)
wnd.CallBeforeFrameOnce(load_fonts)
wnd.Serve()
```

An install with no context, or from inside the render callback (between
`NewFrame()` and `Render()`), raises `RuntimeError`. Install only on the render
thread: a call from another thread is not detected and races the frame.
Installed before the first frame, the font is the first in the atlas and
becomes the default font; use `imgui_ctx.PushFont(font)` to switch fonts for a
block. A font installed after the first frame needs
`wnd.InvalidateDeviceObjects()` so the backend uploads the rebuilt atlas
texture. The call only records a request, which is applied right before the
next frame starts, so calling it from the render callback is safe too; call it
in the same `CallBeforeFrameOnce` callback as the install so that no frame is
drawn with the old texture.

Every script font contributes all of its glyphs, so the atlas grows with
`size_pixels`: `AutoInstall(locale='zh-CN')` is about 4096x4096 (64 MiB) at
16 px, 4096x8192 (128 MiB) at 24 px and 4096x16384 (256 MiB) at 32 px. The
backends upload the atlas at 4 bytes per pixel and D3D11/D3D12 only guarantee
128 MiB per texture, so installs are limited to 16384 pixels per side and
128 MiB by default. An install over the side limit first widens the atlas; if
the atlas still breaks a limit, the install removes the fonts it added and
raises `RuntimeError`. `win32_font.SetAtlasLimits(max_side=None, max_mib=None)`
changes the limits for the process (`None` keeps a limit) and
`GetAtlasLimits()` returns `(max_side, max_mib)`: raise `max_mib` for larger
CJK sizes on a GPU with enough video memory, and set `max_side=8192` under
DX10.

## Textures

`CreateTexture(filename)` and `CreateTextureFromPixels(width, height,
pixels)` exist on the DX11 and DX12 renderers (`Dx11Window`/`Dx12Window`,
standalone or overlay, and `Dx11Inbound`/`Dx12Inbound`); both backends also
take `mips=False`. DX9, DX10, GL3 and VK have neither: check
`hasattr(renderer, 'CreateTexture')` and fall back, for example to a solid
rectangle. The returned objects share the same members on both backends:
`handle` (the ImGui texture id), `width`, `height`, `size`, `mipLevels`,
`bool()` and `FreeTexture()`; DX12 also has `LoadTextureFromFile`.

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

Timing: the renderer's device must exist. That is while `Serve()` runs (from
`CallBeforeFrameOnce` or the render callback), or for an inbound renderer
after its first frame. Otherwise, including after a callback raised out of
`Serve()`, creation raises `RuntimeError`. `CallBeforeFrameOnce` can be
queued before `Serve()`, as in the example above.

Threading: create textures on the render thread, either from
`CallBeforeFrameOnce` or from the render callback; `CallBeforeFrameOnce` is
not required. A call from another thread raises `RuntimeError` ("render
thread"). Decode anywhere instead: `pyimgui.DecodeImage(path)` runs on any
thread, with the GIL released and no window needed, so a worker decodes and
the render thread only calls `CreateTextureFromPixels`. Every creation and
decode call releases the GIL during decode and upload, so other Python
threads keep running. Drawing happens only in the render callback. A DX12
upload waits for its GPU copy, so keep the number of uploads per frame small.

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

Do not re-queue `CallBeforeFrameOnce` from inside itself: a callback queued
there runs in the same frame, so a callback that keeps re-queueing itself
never lets a frame through. Spread work across frames from the render
callback instead, as the example above does.

Lifetime: keep the returned object alive while you draw it, because `handle`
is a plain int. Dropping it, or calling `FreeTexture()`, frees it at the next
frame boundary; on DX12 only after the GPU is done with it. After
`FreeTexture()` the object is falsy and draws nothing. Textures belong to one
session: once `Serve()` returned or raised, or the inbound renderer is
destroyed, reading `handle` raises `RuntimeError`, so create new ones for a
new session. `InvalidateDeviceObjects()` (after a font change) does not
affect textures. DX12 holds up to 4094 live textures at once; beyond that,
creation raises `RuntimeError`. DX12 `LoadTextureFromFile` changes `handle`,
and so does DX12 `UpdatePixels`.

Format and memory: `pixels` is RGBA8 with straight alpha, row 0 at the top,
in a C-contiguous buffer (`bytes`, `bytearray`, `memoryview`, `array.array`,
or numpy). Tight rows need exactly `width*height*4` bytes; with `rowPitch=n`,
rows start every `n` bytes and the buffer needs at least `n*height` bytes.
Short buffers raise `ValueError` before anything is read. A 4096x4096 texture
is 64 MiB at 4 bytes per pixel, and `mips=True` adds about a third; a side
may be at most 16384 px, matching the font atlas limits above.

Drawing: `imgui.Image`, `dl.AddImage`, `dl.AddImageQuad` (rotated or skewed
quads, with per-corner UVs), and `esp.add_image_triangle` (any textured
triangle, for example a clipped polygon drawn as a fan; see
[esp.md](esp.md)). UV (0, 0) is the top-left texel.

Sampling: by default, every texture samples bilinear on mip 0 only, on both
backends. Both backends add `mips=True` at creation and a per-draw sampler:
wrap draws in `SetTextureSampler(dl, pyimgui.TextureFilter.Point/Linear/Anisotropic)`
and `ResetTextureSampler(dl)` on the same draw list. `Point` keeps magnified
pixels crisp, `Linear` is trilinear across mips, `Anisotropic` suits a
stretched image seen at a shallow angle. Keep text outside a `Point` scope,
since it loses its anti-aliasing there. There is no nesting: `Reset`
restores the backend's default.

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

Large images: memory follows the format rule above (64 MiB at 4096x4096,
plus about a third with mips). Drawn much smaller than its size, a texture
aliases under the default sampler; `mips=True` plus a `Linear` or
`Anisotropic` scope avoids that. Dropping a texture frees it at the next
frame boundary, so a cache can drop what it no longer shows. For very large
images, consider tiling: several smaller textures, created and dropped as
the view changes.

Grayscale: `transform=pyimgui.TextureTransform.GrayscaleBT709` on
`CreateTexture`, DX12 `LoadTextureFromFile` and `DecodeImage` converts the
image once, before upload: `Y = (2126 R + 7152 G + 722 B + 5000) // 10000`
on the stored 8-bit values, output `(Y, Y, Y, A)`. On an ordinary sRGB image
that is BT.709 luma, not linear luminance. Alpha and size are kept, mips are
built after the conversion, and without `transform` nothing changes.

Updating pixels: `tex.UpdatePixels(pixels, *, rowPitch=0)` replaces a
texture's pixels with a new buffer of the same size, with the pixel and
`rowPitch` rules of `CreateTextureFromPixels`. Call it on the render thread
only, from the render callback or `CallBeforeFrameOnce`; off the render
thread, on an empty or freed texture, or after the session ended it raises
`RuntimeError`, and a buffer sized for another width or height raises
`ValueError`. A texture created with `mips=True` gets its whole mip chain
rebuilt from the new pixels. DX11 updates in place and keeps `handle`, so
draws already recorded earlier in the frame show the new pixels too; DX12
uploads a new texture on every call and changes `handle`, so draws recorded
earlier in the frame still show the old pixels - read `handle` when you
draw.

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

## Next

- [inbound.md](inbound.md) - draw inside another process's own D3D/GL/VK renderer.
- [esp.md](esp.md) - world-to-screen projection and ESP drawing helpers.
- [overlay.md](overlay.md) - a frameless desktop overlay (`Dx11Window.overlay = True`).
