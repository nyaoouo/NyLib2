from __future__ import annotations
import typing
__all__: list[str] = ['GetMethod', 'GetRenderType', 'GuessRenderType', 'Init', 'RenderType']
class RenderType:
    """
    Members:
    
      None
    
      D3D9
    
      D3D10
    
      D3D11
    
      D3D12
    
      Auto
    
      Unknown
    """
    Auto: typing.ClassVar[RenderType]  # value = <RenderType.Auto: 5>
    D3D10: typing.ClassVar[RenderType]  # value = <RenderType.D3D10: 2>
    D3D11: typing.ClassVar[RenderType]  # value = <RenderType.D3D11: 3>
    D3D12: typing.ClassVar[RenderType]  # value = <RenderType.D3D12: 4>
    D3D9: typing.ClassVar[RenderType]  # value = <RenderType.D3D9: 1>
    Unknown: typing.ClassVar[RenderType]  # value = <RenderType.Unknown: 6>
    __members__: typing.ClassVar[dict[str, RenderType]]  # value = {'None': <RenderType.None: 0>, 'D3D9': <RenderType.D3D9: 1>, 'D3D10': <RenderType.D3D10: 2>, 'D3D11': <RenderType.D3D11: 3>, 'D3D12': <RenderType.D3D12: 4>, 'Auto': <RenderType.Auto: 5>, 'Unknown': <RenderType.Unknown: 6>}
    def __eq__(self, other: typing.Any) -> bool:
        ...
    def __getstate__(self) -> int:
        ...
    def __hash__(self) -> int:
        ...
    def __index__(self) -> int:
        ...
    def __init__(self, value: typing.SupportsInt | typing.SupportsIndex) -> None:
        ...
    def __int__(self) -> int:
        ...
    def __ne__(self, other: typing.Any) -> bool:
        ...
    def __repr__(self) -> str:
        ...
    def __setstate__(self, state: typing.SupportsInt | typing.SupportsIndex) -> None:
        ...
    def __str__(self) -> str:
        ...
    @property
    def name(self) -> str:
        ...
    @property
    def value(self) -> int:
        ...
def GetMethod(index: typing.SupportsInt | typing.SupportsIndex) -> int:
    ...
def GetRenderType() -> RenderType:
    ...
def GuessRenderType() -> RenderType:
    ...
def Init(renderType: RenderType) -> None:
    ...
