"""The Engine context: one target's Dumper-7 @ ea0dab3 state over a MemorySource."""
import logging

from ..memory import MemorySource
from .accessor import SourceAccessor
from .gnames import FNameStatics, NameArray
from .objects import ObjectArray
from .platform import Platform
from .state import Off, PropertySizes, Settings

_log = logging.getLogger('nylib.ue.engine')


class Engine:
    """One target's Dumper-7 state (the ea0dab3 statics made per-instance) over a MemorySource."""
    __slots__ = ('mem', 'acc', 'provenance', 'messages', 'statics', 'off', 'settings', 'property_sizes',
                 'platform', 'objects', 'names', 'fname', 'cast_cache')

    def __init__(self, source: MemorySource):
        self.mem = source
        self.acc = SourceAccessor(source)
        self.provenance: dict[str, str] = {}
        self.messages: list[str] = []
        self.statics: dict[str, object] = {}
        self.off = Off()
        self.settings = Settings()
        self.property_sizes = PropertySizes()
        self.platform = Platform(source)
        self.objects = ObjectArray(self)
        self.names = NameArray(self)
        self.fname = FNameStatics(self)
        self.cast_cache: dict[tuple[str, int, int], int] | None = None  # A12: class CastFlags while a dict (engine init only)

    def cerr(self, text: str) -> None:
        """std::cerr << text: kept in messages and logged at DEBUG."""
        self.messages.append(text)
        _log.debug(text)

    def init_bootstrap(self) -> None:
        """The first two steps of Generator::InitEngineCore @ ea0dab3."""
        self.objects.init()
        self.fname.init_windows()
