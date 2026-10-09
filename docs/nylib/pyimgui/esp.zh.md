> 本文档为 esp.md 的中文阅读副本；英文版为权威来源（canonical）。

<!-- dt:meta v="1" lang="zh" source="esp.md" -->

<!-- dt:section id="__preamble__" hash="2941bfb4e4a7" -->
# nylib.pyimgui.esp

纯Python的世界到屏幕投影和ImGui绘制辅助工具用于
ESP风格的覆盖层（`import nylib.pyimgui.esp as esp`）。numpy是可选的，
仅由`add_lines_3d`的快速路径使用 - `esp`从不自行导入它。

仅在渲染回调线程上调用下面的每个函数（即
`Serve()`或入站`Attach()`调用你的`renderCallback`的线程）- 这就是
拥有当前ImGui框架的线程。

<!-- dt:section id="canvas-0" hash="c688d4353ce0" -->
## 画布

```python
import nylib.pyimgui.esp as esp

dl = esp.get_canvas_draw_list()      # background draw list of the main viewport
pos, size = esp.get_canvas_rect()    # main viewport (Pos, Size); don't assume pos == (0, 0)
```

<!-- dt:section id="camera-0" hash="2b8fe45b1763" -->
## 摄像机

```python
cam = esp.Camera.from_pov(
    location=(0.0, 0.0, 0.0), rotation=(0.0, 0.0, 0.0), fov=90.0,
    convention=esp.UE,                 # esp.Unity for a Unity game
)
screen = esp.world_to_screen(cam, (100.0, 0.0, 0.0))        # ImVec2, or None if not visible
bounds = esp.project_bounds(cam, origin=(100.0, 0.0, 0.0), extent=(20.0, 20.0, 40.0))
```

`from_pov` 采用 UE 风格的 `(pitch, yaw, roll)`，单位为度数。对于 Unity 的
`eulerAngles`，传递 `(-pitch, yaw, -roll)` - `esp.Unity` 仅设置世界
坐标轴，而非此符号翻转。`from_matrix(view_proj, convention)` 从 4x4 视图投影矩阵（16 个数字，内存顺序）构建摄像机；当游戏已经公开一个时改为使用它。

<!-- dt:section id="drawing-0" hash="0560a7f85b97" -->
## 绘图

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
| `add_corner_box` | 屏幕框周围的2D角括号 |
| `add_health_bar` | 屏幕框左边的填充垂直条 |
| `add_text_outlined` | 带1px轮廓的文本 |
| `add_line_3d` / `add_lines_3d` | 一个/多个世界空间线段 |
| `add_box_3d` | 世界空间框的12条边 |
| `add_circle_3d` | 世界空间圆形 |
| `add_bones` | 来自联合查找和`(parent, child)`对的骨架 |

`add_lines_3d`接受`(a, b)`对的可迭代对象或numpy `(N, 2, 3)`数组；数组采用矢量化快速路径。
