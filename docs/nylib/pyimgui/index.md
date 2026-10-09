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

## Next

- [inbound.md](inbound.md) - draw inside another process's own D3D/GL/VK renderer.
- [esp.md](esp.md) - world-to-screen projection and ESP drawing helpers.
- overlay mode (`Dx11Window.overlay = True`, a frameless desktop overlay): documented later.
