from __future__ import annotations
import typing
from . import gUtils
from . import imgui
__all__: list[str] = ['gUtils', 'imgui', 'Dx9Inbound', 'Dx9Window', '_Dx9Render', 'Dx10Inbound', 'Dx10Render', 'Dx10Window', '_Dx10Render', 'Dx11Inbound', 'Dx11Texture', 'Dx11Window', '_Dx11Render', '_RenderBase', 'Dx12Inbound', 'Dx12Render', 'Dx12TextureHelper', 'Dx12Window']
from pyimgui.dx9 import Dx9Inbound as Dx9Inbound, Dx9Window as Dx9Window, _Dx9Render as _Dx9Render
from pyimgui.dx10 import Dx10Inbound as Dx10Inbound, Dx10Window as Dx10Window, _Dx10Render as _Dx10Render
Dx10Render = _Dx10Render
from pyimgui.dx11 import Dx11Inbound as Dx11Inbound, Dx11Texture as Dx11Texture, Dx11Window as Dx11Window, _Dx11Render as _Dx11Render, _RenderBase as _RenderBase
from pyimgui.dx12 import Dx12Inbound as Dx12Inbound, Dx12Render as Dx12Render, Dx12TextureHelper as Dx12TextureHelper, Dx12Window as Dx12Window
def __getattr__(name: str) -> typing.Any:
    ...
