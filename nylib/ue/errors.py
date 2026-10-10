from typing import Iterable


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


class SnapshotError(UeError):
    """Raised when a snapshot folder is malformed or incomplete."""

    def __init__(self, path, reason: str):
        self.path = path
        self.reason = reason
        super().__init__(f'invalid snapshot {path}: {reason}')


class SchemaError(SnapshotError):
    """Raised when a loaded snapshot's schema major version is unsupported."""

    def __init__(self, path, reason: str):
        self.path = path
        self.reason = reason
        UeError.__init__(self, reason)


class DetectionError(UeError):
    """Raised when target/offset detection exhausts every finder."""

    def __init__(self, step: str, detail: str, explanations: Iterable[str] = ()):
        self.step = step
        self.detail = detail
        self.explanations = tuple(explanations)
        super().__init__(f'detection stopped at {step}: {detail}')


def _set_details(err: UeError, details: dict) -> None:
    for name, value in details.items():
        setattr(err, name, value)


class AmbiguousTargetError(TargetError):
    """Raised when a process name matches more than one PID."""


class ProfileError(UeError):
    """Raised when a profile TOML is invalid, has unknown keys or bad values."""

    def __init__(self, path, reason: str):
        self.path = path
        self.reason = reason
        super().__init__(f'invalid profile {path}: {reason}')


class OutputRootError(UeError):
    """Raised when internal mode needs an output root and none was given."""

    def __init__(self, message: str, **details):
        super().__init__(message)
        _set_details(self, details)


class SessionError(UeError):
    """Base for runtime session policy violations."""

    def __init__(self, message: str, **details):
        super().__init__(message)
        _set_details(self, details)


class ReadOnlySessionError(SessionError):
    """Raised when a write is attempted on a read-only session."""


class CallsDisabledError(SessionError):
    """Raised when a call is attempted on a session with calls disabled."""


class DumpMismatchError(SessionError):
    """Raised when a dump does not match what was expected."""


class UnverifiedOffsetsError(SessionError):
    """Raised when a session would use offsets that were never verified."""


class AmbiguousNameError(UeError, LookupError):
    """Raised when a short-name lookup matches more than one object."""

    def __init__(self, message: str, **details):
        super().__init__(message)
        _set_details(self, details)


class CallError(UeError):
    """Raised when a ProcessEvent call fails or times out."""

    def __init__(self, message: str, **details):
        super().__init__(message)
        _set_details(self, details)


class MarshalError(UeError, TypeError):
    """Raised when a call argument cannot be marshalled."""

    def __init__(self, message: str, **details):
        super().__init__(message)
        _set_details(self, details)
