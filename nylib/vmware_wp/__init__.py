from __future__ import annotations

from nylib.vmware_wp.config import VmwareConfig
from nylib.vmware_wp.discovery import (
    BinaryResolution,
    default_search_roots,
    discover_binary,
)
from nylib.vmware_wp.errors import (
    BinaryNotFoundError,
    CredentialNotFoundError,
    ProcessCommandError,
    RestRequestError,
    VmwareConfigError,
    VmwareError,
    VmwareTimeoutError,
)
from nylib.vmware_wp.process import ProcessBackend
from nylib.vmware_wp.rest import RestBackend
from nylib.vmware_wp.results import CommandResult, ProcessResult, RestResult
from nylib.vmware_wp.vmrun import GuestExecResult, Vmrun, VmrunPowerOp
from nylib.vmware_wp.vmcli import Vmcli
from nylib.vmware_wp.wincred import (
    read_credential_password,
    read_encrypted_vm_password,
    require_encrypted_vm_password,
)
from nylib.vmware_wp.rest_api import (
    REST_NETWORK_ENDPOINTS,
    REST_VM_ENDPOINTS,
    WorkstationRest,
    render_endpoint,
)
from nylib.vmware_wp.workstation import NoProviderError, Workstation

__all__ = [
    "VmwareConfig",
    "BinaryResolution",
    "default_search_roots",
    "discover_binary",
    "VmwareError",
    "VmwareConfigError",
    "BinaryNotFoundError",
    "CredentialNotFoundError",
    "VmwareTimeoutError",
    "ProcessCommandError",
    "RestRequestError",
    "ProcessBackend",
    "RestBackend",
    "CommandResult",
    "ProcessResult",
    "RestResult",
    "Vmrun",
    "VmrunPowerOp",
    "GuestExecResult",
    "Vmcli",
    "read_credential_password",
    "read_encrypted_vm_password",
    "require_encrypted_vm_password",
    "WorkstationRest",
    "render_endpoint",
    "REST_VM_ENDPOINTS",
    "REST_NETWORK_ENDPOINTS",
    "Workstation",
    "NoProviderError",
]
