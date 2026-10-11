# nylib.pyimgui.esp

Pure-Python world-to-screen projection and ImGui drawing helpers for
ESP-style overlays (`import nylib.pyimgui.esp as esp`). numpy is optional and
used only by `add_lines_3d`'s fast path - `esp` never imports it itself.

Call every function below only on the render-callback thread (the one
`Serve()` or an inbound `Attach()` calls your `renderCallback` on) - that's
the thread that owns the current ImGui frame.

## Canvas

```python
import nylib.pyimgui.esp as esp

dl = esp.get_canvas_draw_list()      # background draw list of the main viewport
pos, size = esp.get_canvas_rect()    # main viewport (Pos, Size); don't assume pos == (0, 0)
```

## Camera

```python
cam = esp.Camera.from_pov(
    location=(0.0, 0.0, 0.0), rotation=(0.0, 0.0, 0.0), fov=90.0,
    convention=esp.UE,                 # esp.Unity for a Unity game
)
screen = esp.world_to_screen(cam, (100.0, 0.0, 0.0))        # ImVec2, or None if not visible
bounds = esp.project_bounds(cam, origin=(100.0, 0.0, 0.0), extent=(20.0, 20.0, 40.0))
```

`from_pov` takes a UE-style `(pitch, yaw, roll)` in degrees. For Unity's
`eulerAngles`, pass `(-pitch, yaw, -roll)` - `esp.Unity` only sets the world
axes, not this sign flip. `from_matrix(view_proj, convention)` builds a camera
from a 4x4 view-projection matrix (16 numbers, memory order) instead; use it
when the game already exposes one.

## Drawing

```python
col = esp.Rgba(255, 0, 0)
if screen is not None:
    esp.add_text_outlined(dl, screen, col, "target")
if bounds is not None:
    esp.add_corner_box(dl, bounds[0], bounds[1], col)
    esp.add_health_bar(dl, bounds[0], bounds[1], fraction=0.6)
```

| Function | Draws |
| --- | --- |
| `add_corner_box` | 2D corner brackets around a screen box |
| `add_health_bar` | a filled vertical bar left of a screen box |
| `add_text_outlined` | text with a 1px outline |
| `add_line_3d` / `add_lines_3d` | one / many world-space line segments |
| `add_box_3d` | the 12 edges of a world-space box |
| `add_circle_3d` | a world-space circle |
| `add_bones` | a skeleton from a joint lookup and `(parent, child)` pairs |

`add_lines_3d` takes an iterable of `(a, b)` pairs or a numpy `(N, 2, 3)`
array; an array takes a vectorized fast path.
