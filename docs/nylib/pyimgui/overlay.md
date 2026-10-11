# Overlay mode

`overlay = True` on `Dx11Window`/`Dx12Window` turns a standalone window into a
frameless desktop canvas that draws over a whole monitor (or over another
window's client area) instead of inside its own bordered window. The
canvas lets mouse clicks pass through to whatever is behind it unless you are
interacting with one of its ImGui windows - the usual shape for an ESP or HUD
overlay.

## Monitor mode

With no target set, the canvas covers one monitor:

```python
from nylib.pyimgui import Dx11Window
from nylib.pyimgui import imgui
import nylib.pyimgui.esp as esp

def render(wnd):
    cam = esp.Camera.from_pov(location=(0.0, 0.0, 500.0), rotation=(0.0, 0.0, 0.0), fov=90.0)
    dl = esp.get_canvas_draw_list()
    screen = esp.world_to_screen(cam, (100.0, 0.0, 0.0))
    if screen is not None:
        esp.add_text_outlined(dl, screen, esp.Rgba(255, 0, 0), "target")
    imgui.Begin("Overlay")
    imgui.Text("drawn on the desktop")
    imgui.End()

wnd = Dx11Window(render)
wnd.overlay = True
wnd.Serve()
```

`overlayMonitor` (default 0, the primary) picks which monitor from
`GetMonitors()` the canvas covers.

## Target mode

Set `overlayTarget` to follow a window instead: an `int` HWND for a fixed
target, or a callable "finder" (e.g. a `WindowQuery`) that returns an HWND, 0,
or `None`:

```python
from nylib.pyimgui import Dx11Window, WindowQuery

def found(hwnd):
    print("target found:", hwnd)

def lost():
    print("target lost")

def render(wnd):
    pass  # draw relative to wnd.targetHwnd's client area

wnd = Dx11Window(render)
wnd.overlay = True
wnd.overlayTarget = WindowQuery(exe="notepad.exe")
wnd.targetFoundCallback = found
wnd.targetLostCallback = lost
wnd.Serve()
```

The canvas then tracks the target's client area every frame, fires
`targetFoundCallback`/`targetLostCallback` on found/lost, and exposes the
current window as `targetHwnd`/`targetPid` (both 0 when there is no target).
While the target is minimized or otherwise not shown, the canvas hides and the
render callback keeps running at a low rate instead of stopping, so your own
state stays alive.

## Z-order

`overlayZOrder` decides where the canvas sits relative to a tracked target
(ignored in monitor mode, where the canvas is always on top):

- `AboveTarget` (default): the canvas stays directly above the target's
  top-level window, so another app brought in front of the target covers the
  overlay too; a target that is itself always-on-top keeps the canvas
  directly above it.
- `Topmost`: the canvas stays always on top and above the target, even when
  another app is in front of the target.

In `Topmost` (and in monitor mode) the canvas puts itself back above an
always-on-top window that becomes the foreground window, so two such windows
can trade places for a frame. The z-order is checked once per frame, so
switching apps can cover or uncover the canvas for a single frame.

## Click-through and input

`inputPolicy` (shared with inbound mode, see [inbound.md](inbound.md)) decides
whether mouse input reaches the canvas or passes through to the window below:

- `Auto` (default): passes through unless the latest frame wants to capture
  the mouse (hovering or interacting with an ImGui window); a drag that
  started outside the canvas keeps passing through even if it later crosses
  an ImGui window, until every held button is released; clicking a captured
  area brings the canvas to the foreground.
- `CaptureAll`: never passes through.
- `PassAll`: always passes through; ImGui still sees the cursor position but
  ignores buttons, wheel, keys and the gamepad, as in inbound mode, and lets go
  of anything it held when you switch to it.

Keys go to whichever window is the foreground window, under every policy:
the overlay can neither take keys from the game nor hand them to it. Clicking
an overlay window makes the overlay the foreground window, so keys then go to
the overlay - and not to the game - until you click back into the game; under
`PassAll` the overlay ignores them, but the game still does not get them. With
the default `gamepadPolicy` (`WhenForeground`) the overlay reads the gamepad
only while it is the foreground window; with `Always` it reads the gamepad on
every frame, with `Never` on none, and under `PassAll` never. A controller
button already held in the game when you click into the overlay reads as a
fresh press on the next frame, which can immediately activate whatever widget
has focus.

While a popup is open, the whole canvas captures mouse input - even outside
any ImGui window - until the popup closes, so a click meant for the game
first closes the popup and focuses the overlay instead. Keep the render
callback fast: a slow one delays how soon a stuck capture can be released.

## DPI

`overlayDpiAware` (default `True`): the canvas and every placement query
(monitor rect, target rect, cursor) use physical pixels regardless of the
process's own DPI awareness. Set it to `False` to use the `Serve()` thread's
current DPI context instead.

## Knobs

- `overlay` (bool, default `False`): set before `Serve()` to run in overlay
  mode instead of a normal window.
- `overlayTarget` (default `None`): `None` for monitor mode, an `int` HWND for
  a fixed target, or a finder callable.
- `overlayMonitor` (int, default `0`): index into `GetMonitors()` for monitor
  mode.
- `overlayZOrder` (`OverlayZOrder`, default `AboveTarget`): see Z-order above.
- `overlayDpiAware` (bool, default `True`): see DPI above.
- `targetFoundCallback` / `targetLostCallback`: called once each time the
  target is found/lost.
- `targetHwnd` / `targetPid` (read-only): the current target, 0 when none.
- `inputPolicy` (`InputPolicy`, default `Auto`): see Click-through above.
- `gamepadPolicy` (`GamepadPolicy`, default `WhenForeground`): see
  Click-through above.
