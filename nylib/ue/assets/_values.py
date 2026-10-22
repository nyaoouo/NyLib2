"""The export records of nylib.ue.assets: ExportInfo and the two reference types."""
from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class ObjectRef:
    kind: str
    package: str | None
    name: str | None
    path: str | None
    _target: int = field(default=0, repr=False)

    def __bool__(self) -> bool:
        return self.kind != 'null'


@dataclass(frozen=True, slots=True)
class SoftObjectRef:
    package: str
    asset: str
    subpath: str
    path: str

    def __bool__(self) -> bool:
        return self.path != ''


@dataclass(frozen=True, slots=True)
class ExportInfo:
    package: str
    name: str
    path: str = field(repr=False)
    index: int
    class_name: str | None
    class_ref: ObjectRef = field(repr=False)
    super_ref: ObjectRef = field(repr=False)
    template_ref: ObjectRef = field(repr=False)
    outer: int | None
    flags: int
    size: int
    container: str
