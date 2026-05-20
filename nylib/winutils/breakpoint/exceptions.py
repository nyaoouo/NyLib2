"""Exception hierarchy for nylib.winutils.breakpoint."""

from __future__ import annotations

from typing import Iterable


class BreakpointError(Exception):
    """Base class for all breakpoint errors."""


class SlotExhaustedError(BreakpointError):
    """Raised when a HARD breakpoint cannot find a free DR slot on one or more threads."""

    def __init__(self, message: str, *, missing_tids: Iterable[int] = ()):
        super().__init__(message)
        self.missing_tids = tuple(missing_tids)


class InvalidBreakpointError(BreakpointError):
    """Raised for bad address/size/flag combinations at install time."""


class BackendError(BreakpointError):
    """Raised when the native backend reports a non-zero status."""

    def __init__(self, message: str, *, status: int = 0):
        super().__init__(message)
        self.status = int(status)
