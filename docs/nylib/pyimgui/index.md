# nylib.pyimgui

Direct Dear ImGui 1.91.5-docking bindings for Python, with DX9/DX10/DX11/DX12/
GL3/VK frontends. Each frontend has a standalone-window class and an injected
"inbound" class for drawing inside another process's own renderer (see
[inbound.md](inbound.md)).

Keywords: Dear ImGui, imgui, pyimgui, Dx9Window, Dx11Window, Dx12Window, Dx11Inbound, Dx12Inbound, inbound, overlay, ESP, DirectX, DX11, DX12, OpenGL3, Vulkan, render hook, in-process overlay, pybind11

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

## Next

- [inbound.md](inbound.md) - draw inside another process's own D3D/GL/VK renderer.
- [esp.md](esp.md) - world-to-screen projection and ESP drawing helpers.
- [overlay.md](overlay.md) - a frameless desktop overlay (`Dx11Window.overlay = True`).
