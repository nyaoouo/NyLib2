from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from nylib.vmware_wp.errors import VmwareConfigError
from nylib.vmware_wp.process import ProcessBackend
from nylib.vmware_wp.rest import RestBackend


@dataclass
class VmwareConfig:
    vmrun_path: Path | None = None
    vmcli_path: Path | None = None
    search_roots: tuple[Path, ...] = ()
    rest_base_url: str | None = None
    rest_auth: tuple[str, str] | None = None
    timeout: float = 120.0
    auto_vm_password: bool = True

    def vmrun(self) -> ProcessBackend:
        return ProcessBackend(
            name="vmrun",
            path=self.vmrun_path,
            search_roots=self.search_roots,
            default_timeout=self.timeout,
        )

    def vmcli(self) -> ProcessBackend:
        return ProcessBackend(
            name="vmcli",
            path=self.vmcli_path,
            search_roots=self.search_roots,
            default_timeout=self.timeout,
        )

    def rest(self) -> RestBackend:
        if not self.rest_base_url:
            raise VmwareConfigError("rest_base_url is not configured")
        return RestBackend(
            base_url=self.rest_base_url,
            auth=self.rest_auth,
            default_timeout=self.timeout,
        )
