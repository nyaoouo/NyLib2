from __future__ import annotations

from dataclasses import dataclass

from nylib.vmware_wp.config import VmwareConfig
from nylib.vmware_wp.rest import RestBackend

REST_VM_ENDPOINTS = {
    "inventory": "/vms",
    "registration": "/vms/registration",
    "details": "/vms/{vm_id}",
    "configparams": "/vms/{vm_id}/configparams",
    "ip": "/vms/{vm_id}/ip",
    "nic": "/vms/{vm_id}/nic",
    "nic_ips": "/vms/{vm_id}/nicips",
    "params": "/vms/{vm_id}/params/{name}",
    "power": "/vms/{vm_id}/power",
    "restrictions": "/vms/{vm_id}/restrictions",
    "sharedfolders": "/vms/{vm_id}/sharedfolders",
}

REST_NETWORK_ENDPOINTS = {
    "vmnets": "/vmnets",
    "vmnet": "/vmnet",
    "portforward": "/vmnet/{vmnet}/portforward",
    "mactoip": "/vmnet/{vmnet}/mactoip",
}


def render_endpoint(name: str, **values: str) -> str:
    templates = {**REST_VM_ENDPOINTS, **REST_NETWORK_ENDPOINTS}
    return templates[name].format(**values)


@dataclass(frozen=True)
class WorkstationRest:
    backend: RestBackend

    @classmethod
    def from_config(cls, config: VmwareConfig) -> "WorkstationRest":
        return cls(config.rest())

    def list_vms(self):
        return self.backend.request("GET", render_endpoint("inventory")).json

    def get_vm(self, vm_id):
        return self.backend.request("GET", render_endpoint("details", vm_id=vm_id)).json

    def get_power_state(self, vm_id):
        return self.backend.request("GET", render_endpoint("power", vm_id=vm_id)).json

    def get_ip(self, vm_id):
        return self.backend.request("GET", render_endpoint("ip", vm_id=vm_id)).json

    def set_power_state(self, vm_id, operation: str):
        # WS Pro REST expects a plain-text body: on|off|shutdown|suspend|pause|unpause
        return self.backend.request(
            "PUT", render_endpoint("power", vm_id=vm_id), data=operation
        ).json
