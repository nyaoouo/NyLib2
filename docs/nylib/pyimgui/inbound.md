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
stops drawing and input. Installed hooks remain as pass-throughs for the
process lifetime so that other overlays can keep calling through them.

On `Dx11Inbound` and `Dx12Inbound`, `Attach(mode=...)` accepts
`pyimgui.HookMode.Detours` (the default), `Vtable`, or `Auto`. `Vtable` hooks
the shared DXGI swap-chain slots for `Present`, `Present1`, `ResizeBuffers`,
and `ResizeBuffers1`; DX12 also hooks the command-queue vtable slot used for
queue discovery. This mode requires `IDXGISwapChain3` and does not patch
function entry bytes. `Auto` compares the full instruction span Detours would
replace with the on-disk image. It chooses Detours for pristine native methods
and Vtable when an entry is already patched and the shared table is available.
`renderer.hookMode` reports the actual choice. Changing the mode while
attached raises `RuntimeError`; call `Detach()` first. DX9, DX10, GL3, and
Vulkan keep their existing hooks and do not accept `mode=`.

Shared-vtable hooks may miss a swap chain whose object vptr was replaced or
whose caller cached a function pointer. In that case, use `Detours` explicitly.

Your `renderCallback` always runs on the thread that owns the game's present
call - call `pyimgui`/`pyimgui.esp` only from there, never from another
thread.

## Knobs

- `inputPolicy` (`pyimgui.InputPolicy.Auto`/`CaptureAll`/`PassAll`, default
  `Auto`): `Auto` swallows mouse/keyboard only while ImGui itself wants it
  (`io.WantCaptureMouse`/`WantCaptureKeyboard`); `CaptureAll` always swallows;
  `PassAll` never calls ImGui's handler for buttons, wheel or keyboard, so the
  game gets them and ImGui does not (it still sees everything else, cursor
  moves included).
- `viewportsEnable` (`Dx11Inbound`/`Dx12Inbound` only, default `True`): set to
  `False` to keep ImGui windows inside the game's window instead of floating
  as their own OS windows.
- `gamepadPolicy` (`pyimgui.GamepadPolicy`, default `WhenForeground`): the
  gamepad feeds ImGui only while the game window is foreground; `Always` for
  the old behaviour; `Never` to ignore it; none under `PassAll`.
