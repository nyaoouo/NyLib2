"""The runtime session's accessor (RT7): refuses reads after close and writes in a read-only session."""
from ..engine.accessor import SourceAccessor
from ..errors import ReadOnlySessionError, SessionError


class RuntimeAccessor(SourceAccessor):
    """SourceAccessor bound to one session; the write backstop behind every codec's check_write."""
    ctx = None  # set once by the session right after construction

    def read(self, address: int, size: int) -> bytes:
        if (ctx := self.ctx) is not None and ctx.closed:
            raise SessionError('the session is closed')
        return SourceAccessor.read(self, address, size)

    def write(self, address: int, value: bytes) -> None:
        ctx = self.ctx
        if ctx is not None and ctx.closed:
            raise SessionError('the session is closed')
        if ctx is None or not ctx.write:
            raise ReadOnlySessionError(f'write of {len(value):#x} bytes at {address:#x} refused: the session is read-only',
                                       address=address, size=len(value))
        SourceAccessor.write(self, address, value)
