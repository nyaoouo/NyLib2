import pathlib

from ..utils import IconFont, IconSetMeta
from . import regular, solid
from .solid import *  # noqa: F401,F403 — re-export solid as default

_HERE = pathlib.Path(__file__).resolve().parent
_RES = _HERE / "resources"

_meta_ = IconSetMeta(
    name="fa",
    fonts=[
        IconFont(ttf=_RES / "fa-solid-900.ttf", glyphs=solid._glyphs_, size=15.0),
        IconFont(ttf=_RES / "fa-regular-400.ttf", glyphs=regular._glyphs_, size=15.0),
    ],
)
