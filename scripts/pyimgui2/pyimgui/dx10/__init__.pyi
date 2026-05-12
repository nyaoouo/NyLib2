from __future__ import annotations
import collections.abc
import pyimgui.imgui
import typing
from . import detours
from . import inbound
__all__: list[str] = ['Dx10Inbound', 'Dx10Render', 'Dx10Window', '_Dx10Render', '_RenderBase', 'detours', 'inbound']
class Dx10Inbound(_Dx10Render):
    def Attach(self) -> None:
        ...
    def Detach(self) -> None:
        ...
    def __init__(self, renderCallback: collections.abc.Callable | None = None) -> None:
        ...
class Dx10Window(_Dx10Render):
    ClearColor: pyimgui.imgui.ImVec4
    def Serve(self) -> None:
        ...
    def __init__(self, renderCallback: collections.abc.Callable | None = None) -> None:
        ...
class _Dx10Render(_RenderBase):
    @staticmethod
    def CreateDeviceObjects() -> bool:
        ...
    @staticmethod
    def InvalidateDeviceObjects() -> None:
        ...
class _RenderBase:
    renderCallback: collections.abc.Callable | None
    title: str
    def CallBeforeFrameOnce(self, arg0: collections.abc.Callable) -> None:
        ...
    def Close(self) -> None:
        ...
    def HideToTray(self) -> None:
        ...
    def RestoreFromTray(self) -> None:
        ...
    def UpdateTrayIconInfo(self, tooltip: str, iconPath: str = '') -> None:
        ...
Dx10Render = _Dx10Render
