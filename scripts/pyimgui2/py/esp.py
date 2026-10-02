"""World-to-screen projection for ESP overlays drawn with ImGui."""
import collections.abc
import math
import operator
import sys

from . import imgui

__all__ = [
    'Convention', 'UE', 'Unity', 'Camera', 'Rgba',
    'get_canvas_draw_list', 'get_canvas_rect', 'world_to_screen', 'project_bounds',
]

_FLT_MAX = 3.4028234663852886e38
_AXES = {
    'x': (1.0, 0.0, 0.0), '-x': (-1.0, 0.0, 0.0),
    'y': (0.0, 1.0, 0.0), '-y': (0.0, -1.0, 0.0),
    'z': (0.0, 0.0, 1.0), '-z': (0.0, 0.0, -1.0),
}
_NAN3 = (math.nan, math.nan, math.nan)
_MISSING = object()
_PLAIN_SEQ = (tuple, list)
_NOT_POINTS = (str, bytes, bytearray, collections.abc.Mapping)


def _is_ndarray(value):
    nd = getattr(sys.modules.get('numpy'), 'ndarray', None)
    return nd is not None and isinstance(value, nd)


def _length(value, kind):
    if isinstance(value, _NOT_POINTS):
        raise TypeError(f'{kind} must not be {type(value).__name__}')
    try:
        return len(value)
    except TypeError:
        raise TypeError(f'{kind} must be a sequence, got {type(value).__name__}') from None


def _read_seq(value, n, kind):
    if type(value) in _PLAIN_SEQ:
        if len(value) != n:
            raise ValueError(f'{kind} must have {n} elements, got {len(value)}')
        return tuple(float(v) for v in value)
    if _is_ndarray(value):
        if value.ndim != 1 or value.shape[0] != n:
            raise ValueError(f'{kind} array must have shape ({n},), got {value.shape}')
        return tuple(float(v) for v in value.tolist())
    length = _length(value, kind)
    if length != n:
        raise ValueError(f'{kind} must have {n} elements, got {length}')
    return tuple(float(value[i]) for i in range(n))


def _read_attrs(value, names):
    values = []
    for name in names:
        v = getattr(value, name, _MISSING)
        if v is _MISSING:
            return None
        values.append(v)
    return tuple(float(v) for v in values)


def _read_vec3(value):
    if type(value) in _PLAIN_SEQ:
        return _read_seq(value, 3, 'Vec3')
    v = _read_attrs(value, ('x', 'y', 'z'))
    if v is None:
        v = _read_attrs(value, ('X', 'Y', 'Z'))
    return v if v is not None else _read_seq(value, 3, 'Vec3')


def _read_vec2(value):
    v = _read_attrs(value, ('x', 'y'))
    return v if v is not None else _read_seq(value, 2, 'Vec2')


def _read_rotator(value):
    v = _read_attrs(value, ('pitch', 'yaw', 'roll'))
    if v is None:
        v = _read_attrs(value, ('Pitch', 'Yaw', 'Roll'))
    return v if v is not None else _read_seq(value, 3, 'Rotator')


def _read_matrix16(value):
    if _is_ndarray(value):
        if value.size != 16:
            raise ValueError(f'Matrix16 array must have 16 elements, got {value.size}')
        return tuple(float(v) for v in value.flat)
    length = _length(value, 'Matrix16')
    if length == 16:
        return tuple(float(value[i]) for i in range(16))
    if length == 4:
        rows = [value[i] for i in range(4)]
        if not all(isinstance(row, _NOT_POINTS) or hasattr(row, '__len__') for row in rows):
            raise ValueError('Matrix16 must have 16 numbers or 4 rows of 4, got 4 non-sequence elements')
        return tuple(v for row in rows for v in _read_seq(row, 4, 'Matrix16 row'))
    raise ValueError(f'Matrix16 must have 16 numbers or 4 rows of 4, got {length} elements')


def _read_col(value, name='col'):
    v = operator.index(value)
    if not 0 <= v < 1 << 32:
        raise ValueError(f'{name} must be in [0, 2**32), got {v}')
    return v


def _read_view_rect(view_rect, wmin):
    """Return (pos, size, wmin); an empty canvas makes wmin infinite."""
    if view_rect is None:
        pos, size = get_canvas_rect()
        pos, size = (pos.x, pos.y), (size.x, size.y)
        if not (size[0] > 0 and size[1] > 0):
            wmin = math.inf
        return pos, size, wmin
    length = _length(view_rect, 'view_rect')
    if length != 2:
        raise ValueError(f'view_rect must be (pos, size), got {length} elements')
    pos, size = _read_vec2(view_rect[0]), _read_vec2(view_rect[1])
    if not all(math.isfinite(v) for v in pos + size):
        raise ValueError(f'view_rect must be finite, got {pos}, {size}')
    if not (size[0] > 0 and size[1] > 0):
        raise ValueError(f'view_rect size must be positive, got {size}')
    return pos, size, wmin


def _axis(value, name):
    if not isinstance(value, str):
        raise TypeError(f'{name} must be a str, got {type(value).__name__}')
    v = value.lower()
    if v not in _AXES:
        raise ValueError(f'{name} must be one of x, y, z, -x, -y, -z, got {value!r}')
    return v


class Convention:
    """Axis convention of a game's world, camera and view-projection matrices."""

    __slots__ = ('_row_vectors', '_forward', '_right', '_up', '_fov_axis', '_basis')

    def __init__(self, row_vectors: bool = True, forward: str = 'x', right: str = 'y', up: str = 'z',
                 fov_axis: str = 'x') -> None:
        axes = (_axis(forward, 'forward'), _axis(right, 'right'), _axis(up, 'up'))
        if len({a[-1] for a in axes}) != 3:
            raise ValueError(f'forward, right and up must use three distinct axes, got {axes}')
        if not isinstance(fov_axis, str):
            raise TypeError(f'fov_axis must be a str, got {type(fov_axis).__name__}')
        fov = fov_axis.lower()
        if fov not in ('x', 'y'):
            raise ValueError(f"fov_axis must be 'x' or 'y', got {fov_axis!r}")
        init = object.__setattr__
        init(self, '_row_vectors', bool(row_vectors))
        init(self, '_forward', axes[0])
        init(self, '_right', axes[1])
        init(self, '_up', axes[2])
        init(self, '_fov_axis', fov)
        init(self, '_basis', tuple(_AXES[a] for a in axes))

    def __setattr__(self, name, value):
        raise AttributeError('Convention is immutable')

    def __delattr__(self, name):
        raise AttributeError('Convention is immutable')

    @property
    def row_vectors(self) -> bool:
        """True when matrices multiply row vectors (p * M).

        The 16 numbers are read in memory order, so column-vector matrices stored
        column-major (Unity Matrix4x4, GLM) also use row_vectors=True.
        """
        return self._row_vectors

    @property
    def forward(self) -> str:
        """World axis the camera looks along at zero rotation."""
        return self._forward

    @property
    def right(self) -> str:
        """World axis pointing right at zero rotation."""
        return self._right

    @property
    def up(self) -> str:
        """World axis pointing up at zero rotation."""
        return self._up

    @property
    def fov_axis(self) -> str:
        """Screen axis the field of view spans."""
        return self._fov_axis

    def __reduce__(self):
        return Convention, self._key()

    def __copy__(self):
        return self

    def __deepcopy__(self, memo):
        return self

    def _key(self):
        return self._row_vectors, self._forward, self._right, self._up, self._fov_axis

    def __eq__(self, other):
        if not isinstance(other, Convention):
            return NotImplemented
        return self._key() == other._key()

    def __hash__(self):
        return hash(self._key())

    def __repr__(self):
        return ('Convention(row_vectors={!r}, forward={!r}, right={!r}, up={!r}, fov_axis={!r})'
                .format(*self._key()))


UE = Convention()
Unity = Convention(forward='z', right='x', up='y', fov_axis='y')


def _check_convention(convention):
    if not isinstance(convention, Convention):
        raise TypeError(f'convention must be a Convention, got {type(convention).__name__}')


def _combine(a, b, c, f0, r0, u0):
    return tuple(a * f0[i] + b * r0[i] + c * u0[i] for i in range(3))


class Camera:
    """Immutable world-to-screen projection; build one with from_pov or from_matrix."""

    __slots__ = ('_convention', '_pos', '_size', '_wmin', '_pov', '_origin', '_rows')

    def __init__(self, *args, **kwargs):
        raise TypeError('use Camera.from_pov or Camera.from_matrix')

    def __setattr__(self, name, value):
        raise AttributeError('Camera is immutable')

    def __delattr__(self, name):
        raise AttributeError('Camera is immutable')

    def __reduce__(self):
        return Camera._create, tuple(getattr(self, name) for name in Camera.__slots__)

    def __copy__(self):
        return self

    def __deepcopy__(self, memo):
        return self

    @staticmethod
    def _create(convention, pos, size, wmin, pov, origin, rows):
        cam = object.__new__(Camera)
        init = object.__setattr__
        init(cam, '_convention', convention)
        init(cam, '_pos', pos)
        init(cam, '_size', size)
        init(cam, '_wmin', wmin)
        init(cam, '_pov', pov)
        init(cam, '_origin', origin)
        init(cam, '_rows', rows)
        return cam

    @staticmethod
    def from_pov(location, rotation, fov: float, convention: Convention = UE, view_rect=None) -> 'Camera':
        """Camera at location with a UE-style (pitch, yaw, roll) rotation and a full fov, all in degrees."""
        origin = _read_vec3(location)
        rot = _read_rotator(rotation)
        fov = float(fov)
        if not (math.isfinite(fov) and 0.0 < fov < 180.0):
            raise ValueError(f'fov must be finite and in (0, 180), got {fov}')
        tan_half = math.tan(math.radians(fov) / 2)
        if tan_half == 0.0:
            raise ValueError(f'fov is too small, got {fov}')
        _check_convention(convention)
        pos, size, wmin = _read_view_rect(view_rect, 0.01)
        if all(math.isfinite(v) for v in rot):
            p, yw, rl = (math.radians(v) for v in rot)
            sp, cp = math.sin(p), math.cos(p)
            sy, cy = math.sin(yw), math.cos(yw)
            sr, cr = math.sin(rl), math.cos(rl)
            f0, r0, u0 = convention._basis
            fwd = _combine(cp * cy, cp * sy, sp, f0, r0, u0)
            right = _combine(sr * sp * cy - cr * sy, sr * sp * sy + cr * cy, -sr * cp, f0, r0, u0)
            up = _combine(-(cr * sp * cy + sr * sy), cy * sr - cr * sp * sy, cr * cp, f0, r0, u0)
        else:
            fwd = right = up = _NAN3
        span = size[0] if convention.fov_axis == 'x' else size[1]
        k = (span / 2) / tan_half
        if not math.isfinite(k):
            raise ValueError(f'fov is too small for the view size, got {fov}')
        c = (pos[0] + size[0] / 2, pos[1] + size[1] / 2)
        return Camera._create(convention, pos, size, wmin, True, origin, (fwd, right, up, c, k))

    @staticmethod
    def from_matrix(view_proj, convention: Convention = UE, view_rect=None) -> 'Camera':
        """Camera from a 4x4 view-projection matrix given as 16 numbers in memory order."""
        m = _read_matrix16(view_proj)
        _check_convention(convention)
        pos, size, wmin = _read_view_rect(view_rect, 1e-6)
        if convention.row_vectors:
            cols = tuple((m[j], m[4 + j], m[8 + j], m[12 + j]) for j in range(4))
        else:
            cols = tuple((m[4 * j], m[4 * j + 1], m[4 * j + 2], m[4 * j + 3]) for j in range(4))
        return Camera._create(convention, pos, size, wmin, False, None, cols)

    @property
    def view_rect(self) -> 'tuple[imgui.ImVec2, imgui.ImVec2]':
        """The (pos, size) screen rect this camera projects into, as fresh copies."""
        return imgui.ImVec2(*self._pos), imgui.ImVec2(*self._size)

    def _homogeneous(self, x, y, z):
        if self._pov:
            fwd, right, up, c, k = self._rows
            ox, oy, oz = self._origin
            dx, dy, dz = x - ox, y - oy, z - oz
            f = dx * fwd[0] + dy * fwd[1] + dz * fwd[2]
            r = dx * right[0] + dy * right[1] + dz * right[2]
            u = dx * up[0] + dy * up[1] + dz * up[2]
            return c[0] * f + k * r, c[1] * f - k * u, f
        (a0, a1, a2, a3), (b0, b1, b2, b3), _, (w0, w1, w2, w3) = self._rows
        c0 = x * a0 + y * a1 + z * a2 + a3
        c1 = x * b0 + y * b1 + z * b2 + b3
        w = x * w0 + y * w1 + z * w2 + w3
        (vx, vy), (sx, sy) = self._pos, self._size
        return vx * w + (c0 + w) * sx / 2, vy * w + (w - c1) * sy / 2, w


def _check_camera(cam):
    if not isinstance(cam, Camera):
        raise TypeError(f'cam must be a Camera, got {type(cam).__name__}')


def _visible(w, wmin):
    return wmin <= w < math.inf


def _in_range(v):
    return -_FLT_MAX <= v <= _FLT_MAX


def _near_point(wmin, ha, hb):
    """Screen position where segment A->B crosses W == wmin, measured from A."""
    xa, ya, wa = ha
    xb, yb, wb = hb
    t = (wmin - wa) / (wb - wa)
    return (xa + t * (xb - xa)) / wmin, (ya + t * (yb - ya)) / wmin


def _project_point(wmin, h):
    x, y, w = h
    if not _visible(w, wmin):
        return None
    sx, sy = x / w, y / w
    return (sx, sy) if _in_range(sx) and _in_range(sy) else None


def _project_segment(wmin, ha, hb):
    """Screen endpoints of the part of segment A->B in front of the camera, or None."""
    va, vb = _visible(ha[2], wmin), _visible(hb[2], wmin)
    if va and vb:
        pa, pb = (ha[0] / ha[2], ha[1] / ha[2]), (hb[0] / hb[2], hb[1] / hb[2])
    elif va:
        pa, pb = (ha[0] / ha[2], ha[1] / ha[2]), _near_point(wmin, ha, hb)
    elif vb:
        pa, pb = _near_point(wmin, ha, hb), (hb[0] / hb[2], hb[1] / hb[2])
    else:
        return None
    if all(_in_range(v) for v in pa + pb):
        return pa, pb
    return None


def Rgba(r: int, g: int, b: int, a: int = 255) -> int:
    """Pack 8-bit components into an IM_COL32 colour."""
    parts = []
    for name, value in (('r', r), ('g', g), ('b', b), ('a', a)):
        v = operator.index(value)
        if not 0 <= v <= 255:
            raise ValueError(f'{name} must be in [0, 255], got {v}')
        parts.append(v)
    r, g, b, a = parts
    return (a << 24) | (b << 16) | (g << 8) | r


def _main_viewport():
    if imgui.GetCurrentContext() is None:
        raise RuntimeError('no current ImGui context')
    return imgui.GetMainViewport()


def get_canvas_draw_list() -> imgui.ImDrawList:
    """Background draw list of the main viewport."""
    return imgui.GetBackgroundDrawList(_main_viewport())


def get_canvas_rect() -> 'tuple[imgui.ImVec2, imgui.ImVec2]':
    """Copies of the main viewport's (Pos, Size)."""
    vp = _main_viewport()
    return imgui.ImVec2(vp.Pos.x, vp.Pos.y), imgui.ImVec2(vp.Size.x, vp.Size.y)


def world_to_screen(cam: Camera, p) -> 'imgui.ImVec2 | None':
    """Screen position of world point p, or None when it is not visible."""
    _check_camera(cam)
    s = _project_point(cam._wmin, cam._homogeneous(*_read_vec3(p)))
    return None if s is None else imgui.ImVec2(*s)


def project_bounds(cam: Camera, origin, extent) -> 'tuple[imgui.ImVec2, imgui.ImVec2] | None':
    """Screen-space (min, max) of the visible part of the world box origin +- extent, or None."""
    _check_camera(cam)
    ox, oy, oz = _read_vec3(origin)
    ex, ey, ez = _read_vec3(extent)
    hs = [cam._homogeneous(x, y, z)
          for x in (ox - ex, ox + ex) for y in (oy - ey, oy + ey) for z in (oz - ez, oz + ez)]
    wmin = cam._wmin
    vis = [_visible(h[2], wmin) for h in hs]
    pts = [(h[0] / h[2], h[1] / h[2]) for h, v in zip(hs, vis) if v]
    for i in range(8):
        for bit in (4, 2, 1):
            j = i | bit
            if j != i and vis[i] != vis[j]:
                pts.append(_near_point(wmin, hs[i], hs[j]))
    if not pts or not all(_in_range(v) for pt in pts for v in pt):
        return None
    xs, ys = [pt[0] for pt in pts], [pt[1] for pt in pts]
    return imgui.ImVec2(min(xs), min(ys)), imgui.ImVec2(max(xs), max(ys))
