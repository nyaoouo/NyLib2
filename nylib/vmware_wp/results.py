from __future__ import annotations

import json as _json
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class CommandResult:
    """Common base for all backend results."""

    backend: str
    command: tuple[str, ...]
    duration: float


@dataclass(frozen=True)
class ProcessResult(CommandResult):
    returncode: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.returncode == 0

    @property
    def lines(self) -> list[str]:
        return [line.strip() for line in self.stdout.splitlines() if line.strip()]


@dataclass(frozen=True)
class RestResult(CommandResult):
    status_code: int
    text: str
    headers: dict[str, str] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.status_code < 400

    @property
    def json(self) -> Any:
        text = self.text.strip()
        if not text:
            return None
        return _json.loads(text)
