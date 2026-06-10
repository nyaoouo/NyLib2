from __future__ import annotations

import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

from nylib.vmware_wp.discovery import discover_binary
from nylib.vmware_wp.errors import (
    BinaryNotFoundError,
    ProcessCommandError,
    VmwareTimeoutError,
)
from nylib.vmware_wp.results import ProcessResult


@dataclass(frozen=True)
class ProcessBackend:
    name: str
    path: Path | None = None
    search_roots: tuple[Path, ...] = ()
    default_timeout: float = 120.0

    def resolve(self) -> Path:
        resolution = discover_binary(self.name, override=self.path, search_roots=self.search_roots)
        if not resolution.available or resolution.path is None:
            raise BinaryNotFoundError(self.name)
        return resolution.path

    def run(self, args, *, timeout: float | None = None, check: bool = True, env=None,
            redactor=None) -> ProcessResult:
        exe = self.resolve()
        raw_command = (str(exe), *(str(a) for a in args))
        stored_command = tuple(redactor(raw_command)) if redactor is not None else raw_command
        effective_timeout = self.default_timeout if timeout is None else timeout
        start = time.monotonic()
        try:
            completed = subprocess.run(
                raw_command,
                capture_output=True,
                text=True,
                timeout=effective_timeout,
                env=dict(env) if env is not None else None,
            )
        except subprocess.TimeoutExpired as exc:
            raise VmwareTimeoutError(
                f"{self.name} command timed out after {effective_timeout}s: {list(stored_command)}",
                timeout=effective_timeout,
            ) from exc
        duration = time.monotonic() - start
        result = ProcessResult(
            backend=self.name,
            command=stored_command,
            duration=duration,
            returncode=completed.returncode,
            stdout=completed.stdout or "",
            stderr=completed.stderr or "",
        )
        if check and completed.returncode != 0:
            raise ProcessCommandError(result)
        return result
