import ctypes
import dataclasses
import pathlib

from ...pyimgui import imgui


@dataclasses.dataclass
class IconFont:
    ttf: pathlib.Path
    glyphs: str
    size: float = 15.0


@dataclasses.dataclass
class IconSetMeta:
    name: str
    fonts: list[IconFont]


_loaded: set[str] = set()


def is_installed(name: str) -> bool:
    return name in _loaded


def _compress_ranges(codepoints: set[int]) -> list[tuple[int, int]]:
    """Collapse a set of codepoints into [(lo, hi), ...] inclusive ranges."""
    if not codepoints:
        return []
    sorted_cps = sorted(codepoints)
    out: list[tuple[int, int]] = []
    start = prev = sorted_cps[0]
    for c in sorted_cps[1:]:
        if c == prev + 1:
            prev = c
            continue
        out.append((start, prev))
        start = prev = c
    out.append((start, prev))
    return out


def _build_glyph_ranges(glyphs: str):
    """Build an ImWchar range array (`lo1, hi1, lo2, hi2, ..., 0`) as a ctypes c_ushort array.

    The pyimgui binding for ``AddFontFromFileTTF.glyph_ranges`` accepts a
    pointer-like object; a ctypes array satisfies that. The array must outlive
    the font-atlas build — keep a reference (the caller does)."""
    cps = {ord(c) for c in glyphs if ord(c) > 0}
    pairs = _compress_ranges(cps)
    n = len(pairs) * 2 + 1
    arr = (ctypes.c_ushort * n)()
    i = 0
    for lo, hi in pairs:
        arr[i] = lo
        arr[i + 1] = hi
        i += 2
    arr[i] = 0
    return arr


def install_icon(meta: IconSetMeta, *, io: imgui.ImGuiIO = None) -> list:
    """Merge the icon font(s) described by ``meta`` into the current font atlas.

    Must be called once at app init, BEFORE the renderer's first frame builds
    the font texture. Calling it again with the same ``meta.name`` is a no-op.

    If no base font has been added yet, the default font is added first.
    """
    if meta.name in _loaded:
        return []
    if io is None:
        io = imgui.GetIO()
    atlas = io.Fonts
    if len(atlas.Fonts) == 0:
        atlas.AddFontDefault()

    # Keep references to ranges + configs alive until Build() reads them.
    pinned: list = []
    out = []
    for f in meta.fonts:
        ttf = pathlib.Path(f.ttf)
        if not ttf.is_file():
            raise FileNotFoundError(f"icon font not found: {ttf}")
        if not f.glyphs:
            continue

        ranges = _build_glyph_ranges(f.glyphs)
        cfg = imgui.ImFontConfig()
        cfg.MergeMode = True
        cfg.PixelSnapH = True
        font = atlas.AddFontFromFileTTF(str(ttf), f.size, cfg, ranges)
        pinned.append((ranges, cfg))
        out.append(font)

    atlas.Build()
    _loaded.add(meta.name)
    del pinned  # safe to drop after Build()
    return out
