from __future__ import annotations

from dataclasses import dataclass

from nylib.vmware_wp.config import VmwareConfig
from nylib.vmware_wp.errors import VmwareError
from nylib.vmware_wp.results import ProcessResult
from nylib.vmware_wp.rest_api import WorkstationRest
from nylib.vmware_wp.vmcli import Vmcli
from nylib.vmware_wp.vmrun import Vmrun


class NoProviderError(VmwareError):
    """No provider in the fallback chain succeeded."""

    def __init__(self, attempts: dict[str, str]) -> None:
        self.attempts = attempts
        detail = "; ".join(f"{name}: {err}" for name, err in attempts.items())
        super().__init__(f"no provider succeeded ({detail})")


def _run_fallback_chain(attempts):
    """attempts: list[tuple[str, callable]]. Try each; return first success."""
    errors: dict[str, str] = {}
    for name, factory in attempts:
        try:
            return factory()
        except VmwareError as exc:
            errors[name] = str(exc)
    raise NoProviderError(errors)


@dataclass
class Workstation:
    config: VmwareConfig
    _vmrun: Vmrun | None = None
    _vmcli: Vmcli | None = None
    _rest: WorkstationRest | None = None

    def vmrun(self) -> Vmrun:
        if self._vmrun is None:
            self._vmrun = Vmrun.from_config(self.config)
        return self._vmrun

    def vmcli(self) -> Vmcli:
        if self._vmcli is None:
            self._vmcli = Vmcli.from_config(self.config)
        return self._vmcli

    def rest(self) -> WorkstationRest:
        if self._rest is None:
            self._rest = WorkstationRest.from_config(self.config)
        return self._rest

    # ---- capability methods (fallback chain) ----
    def list_running_vms(self) -> list[str]:
        return self.vmrun().list_running_vms()

    def power_state(self, *, vm_id=None, vmx_path=None):
        attempts = []
        if vm_id:
            attempts.append(("rest", lambda: self.rest().get_power_state(vm_id)))
        if vmx_path:
            attempts.append(("vmcli", lambda: self.vmcli().power(vmx_path, "query")))
        if not attempts:
            raise ValueError("power_state requires vm_id or vmx_path")
        return _run_fallback_chain(attempts)

    def power(self, vmx_path, operation, *, mode=None, vm_password=None) -> ProcessResult:
        return _run_fallback_chain([
            ("vmrun", lambda: self.vmrun().power(vmx_path, operation, mode=mode, vm_password=vm_password)),
            ("vmcli", lambda: self.vmcli().power(vmx_path, str(operation).capitalize())),
        ])

    def list_snapshots(self, vmx_path, *, show_tree=False, vm_password=None) -> list[str]:
        return self.vmrun().list_snapshots(vmx_path, show_tree=show_tree, vm_password=vm_password)
