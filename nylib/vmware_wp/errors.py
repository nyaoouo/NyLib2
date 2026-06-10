from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from nylib.vmware_wp.results import ProcessResult, RestResult


class VmwareError(Exception):
    """Base class for all nylib.vmware_wp errors."""


class VmwareConfigError(VmwareError):
    """Missing or invalid configuration (e.g. REST base_url unset)."""


class BinaryNotFoundError(VmwareError):
    """A required executable (vmrun / vmcli) could not be resolved."""

    def __init__(self, name: str, message: str | None = None) -> None:
        self.name = name
        super().__init__(message or f"executable {name!r} could not be resolved")


class CredentialNotFoundError(VmwareError):
    """A credential could not be read from the OS credential store."""


class VmwareTimeoutError(VmwareError):
    """A subprocess or HTTP request exceeded its timeout."""

    def __init__(self, message: str, *, timeout: float | None = None) -> None:
        self.timeout = timeout
        super().__init__(message)


class ProcessCommandError(VmwareError):
    """A subprocess returned a non-zero exit code (check=True)."""

    def __init__(self, result: "ProcessResult") -> None:
        self.result = result
        stderr = (result.stderr or "").strip()
        if len(stderr) > 500:
            stderr = stderr[:500] + "..."
        message = (
            f"{result.backend} command failed (returncode={result.returncode}): "
            f"{list(result.command)}"
        )
        if stderr:
            message += f"\n{stderr}"
        super().__init__(message)


class RestRequestError(VmwareError):
    """An HTTP response had status >= 400 (check=True)."""

    def __init__(self, result: "RestResult") -> None:
        self.result = result
        body = (result.text or "").strip()
        if len(body) > 500:
            body = body[:500] + "..."
        message = (
            f"rest request failed (status={result.status_code}): "
            f"{list(result.command)}"
        )
        if body:
            message += f"\n{body}"
        super().__init__(message)
