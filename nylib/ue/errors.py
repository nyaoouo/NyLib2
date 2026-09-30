class UeError(Exception):
    """Base exception for nylib.ue."""


class MemoryReadError(UeError):
    """Raised when a memory read cannot be completed."""

    def __init__(self, address: int, size: int, reason: str):
        self.address = address
        self.size = size
        self.reason = reason
        super().__init__(f'cannot read {size:#x} bytes at {address:#x}: {reason}')


class MemoryWriteError(UeError):
    """Raised when a memory write cannot be completed."""

    def __init__(self, address: int, size: int, reason: str):
        self.address = address
        self.size = size
        self.reason = reason
        super().__init__(f'cannot write {size:#x} bytes at {address:#x}: {reason}')


class TargetError(UeError):
    """Raised when opening or querying a target process fails."""

    def __init__(self, target: int | str, reason: str):
        self.target = target
        self.reason = reason
        super().__init__(f'cannot open target {target!r}: {reason}')


class PeFormatError(UeError):
    """Raised when a PE image fails to parse."""

    def __init__(self, base: int, reason: str):
        self.base = base
        self.reason = reason
        super().__init__(f'not a PE32+ AMD64 image at {base:#x}: {reason}')


class CaptureError(UeError):
    """Raised when a capture file is invalid or cannot be used."""

    def __init__(self, path: str, reason: str):
        self.path = path
        self.reason = reason
        super().__init__(f'invalid capture {path}: {reason}')
