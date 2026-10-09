# Inbound overlays

Draw inside another process's own D3D/GL/VK renderer, hooked in-place (no
extra swap chain) - the typical ESP/trainer overlay shape. Run this from
inside the target process (e.g. injected Python).

## Attach

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

`CreateInbound(renderCallback, frontend=None)` picks the frontend from
whichever single `d3d9/10/11/12.dll` is already loaded in the process; pass
`frontend=` (one of `'dx9'`, `'dx10'`, `'dx11'`, `'dx12'`, `'gl3'`, `'vk'`) when
more than one D3D runtime is loaded (it otherwise raises, naming the loaded
set), or construct the class directly (`Dx11Inbound`, `Dx12Inbound`, ...).
`Attach()` installs the hook and starts calling `renderCallback`; `Detach()`
removes it.

Your `renderCallback` always runs on the thread that owns the game's present
call - call `pyimgui`/`pyimgui.esp` only from there, never from another
thread.

## Knobs

- `inputPolicy` (`pyimgui.InputPolicy.Auto`/`CaptureAll`/`PassAll`, default
  `Auto`): `Auto` swallows mouse/keyboard only while ImGui itself wants it
  (`io.WantCaptureMouse`/`WantCaptureKeyboard`); `CaptureAll` always swallows;
  `PassAll` never swallows (ImGui still sees input, the game does too).
- `viewportsEnable` (`Dx11Inbound`/`Dx12Inbound` only, default `True`): set to
  `False` to keep ImGui windows inside the game's window instead of floating
  as their own OS windows.
