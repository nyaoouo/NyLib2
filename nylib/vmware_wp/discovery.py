from __future__ import annotations

import os
import shutil
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class BinaryResolution:
    name: str
    path: Path | None
    source: str
    available: bool


def executable_name(name: str) -> str:
    if os.name == "nt" and not name.lower().endswith(".exe"):
        return f"{name}.exe"
    return name


def _registry_roots() -> tuple[Path, ...]:
    """Best-effort WS Pro install paths from the Windows registry."""
    if os.name != "nt":
        return ()
    try:
        import winreg
    except ImportError:
        return ()

    roots: list[Path] = []
    keys = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\VMware, Inc.\VMware Workstation"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\VMware, Inc.\VMware Workstation"),
    ]
    for hive, subkey in keys:
        try:
            with winreg.OpenKey(hive, subkey) as handle:
                value, _ = winreg.QueryValueEx(handle, "InstallPath")
        except OSError:
            continue
        if value:
            candidate = Path(value)
            if candidate not in roots:
                roots.append(candidate)
    return tuple(roots)


def _well_known_roots() -> tuple[Path, ...]:
    return (
        Path(r"C:\Program Files (x86)\VMware\VMware Workstation"),
        Path(r"C:\Program Files\VMware\VMware Workstation"),
    )


def default_search_roots() -> tuple[Path, ...]:
    """Extended search: registry probe + well-known dirs, deduped, order-preserved."""
    roots: list[Path] = []
    for root in (*_registry_roots(), *_well_known_roots()):
        if root not in roots:
            roots.append(root)
    return tuple(roots)


def discover_binary(
    name: str,
    *,
    override: Path | None = None,
    search_roots: tuple[Path, ...] = (),
) -> BinaryResolution:
    command = executable_name(name)

    if override is not None:
        override_path = Path(override).expanduser()
        return BinaryResolution(
            name=name,
            path=override_path,
            source="override",
            available=override_path.is_file(),
        )

    resolved = shutil.which(command)
    if resolved:
        return BinaryResolution(name=name, path=Path(resolved), source="path", available=True)

    for root in search_roots:
        candidate = Path(root) / command
        if candidate.is_file():
            return BinaryResolution(name=name, path=candidate, source="root", available=True)

    for source, roots in (("registry", _registry_roots()), ("default", _well_known_roots())):
        for root in roots:
            candidate = Path(root) / command
            if candidate.is_file():
                return BinaryResolution(name=name, path=candidate, source=source, available=True)

    return BinaryResolution(name=name, path=None, source="unresolved", available=False)
