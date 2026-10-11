# nylib.pyimgui

Direct Dear ImGui 1.91.5-docking bindings for Python, with DX9/DX10/DX11/DX12/
GL3/VK frontends. Each frontend has a standalone-window class and an injected
"inbound" class for drawing inside another process's own renderer (see
[inbound.md](inbound.md)).

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
`wnd.InvalidateDeviceObjects()`, called in the same `CallBeforeFrameOnce`
callback, so the backend uploads the rebuilt atlas texture.

Every script font contributes all of its glyphs, so the atlas grows with
`size_pixels` (`AutoInstall` is about 4096x4096 at 16 px). An install that
would exceed 16384 pixels on a side widens the atlas; if it still does not fit,
the install removes the fonts it added and raises `RuntimeError`. DX10 caps
textures at 8192 pixels on a side, and D3D11/D3D12 also cap one texture's size
in bytes - as low as 128 MiB (a 4096x8192 atlas) on devices with little
dedicated video memory - so keep `size_pixels` lower there.

## Next

- [inbound.md](inbound.md) - draw inside another process's own D3D/GL/VK renderer.
- [esp.md](esp.md) - world-to-screen projection and ESP drawing helpers.
- [overlay.md](overlay.md) - a frameless desktop overlay (`Dx11Window.overlay = True`).
