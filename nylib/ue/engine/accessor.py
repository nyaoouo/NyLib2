"""nylib.ctype accessor over a MemorySource; view() is the only place nylib.ue binds ctype objects to memory."""
from ...ctype import CAccessor, CData
from ..errors import UeError
from ..memory import MemorySource


class SourceAccessor(CAccessor):
    """CAccessor reading and writing through a MemorySource; it never calls or allocates."""

    def __init__(self, source: MemorySource):
        if not isinstance(source, MemorySource):
            raise TypeError(f'source must be a MemorySource, got {type(source).__name__}')
        self.source = source
        self._fresh = None

    @property
    def fresh(self) -> 'SourceAccessor':
        if self._fresh is None:
            if (source := self.source.fresh) is self.source:
                self._fresh = self
            else:
                self._fresh = fresh = type(self)(source)
                fresh._fresh = fresh
        return self._fresh

    def read(self, address: int, size: int) -> bytes:
        return self.source.read(address, size)

    def write(self, address: int, value: bytes) -> None:
        self.source.write(address, value)

    def call(self, func_decl, address, *args):
        raise UeError('nylib.ue accessors do not call; calls go through nylib.ue.calls')

    def alloc(self, size):
        raise UeError('nylib.ue accessors do not allocate')

    def free(self, address):
        raise UeError('nylib.ue accessors do not allocate')

    def alloc_exec(self, size):
        raise UeError('nylib.ue accessors do not allocate')

    def free_exec(self, address):
        raise UeError('nylib.ue accessors do not allocate')


def view(cls: type, address: int, accessor: SourceAccessor):
    """cls(_address_=address, _accessor_=accessor) for a nylib.ctype class, checked."""
    if not (isinstance(cls, type) and issubclass(cls, CData)):
        raise TypeError(f'cls must be a nylib.ctype.CData subclass, got {cls!r}')
    if not isinstance(address, int):
        raise TypeError(f'address must be int, got {type(address).__name__}')
    if not isinstance(accessor, SourceAccessor):
        raise TypeError(f'accessor must be a SourceAccessor, got {type(accessor).__name__}')
    return cls(_address_=address, _accessor_=accessor)
