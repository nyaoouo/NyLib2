from __future__ import annotations

from dataclasses import dataclass

from nylib.vmware_wp.config import VmwareConfig
from nylib.vmware_wp.process import ProcessBackend
from nylib.vmware_wp.results import ProcessResult


@dataclass(frozen=True)
class Vmcli:
    backend: ProcessBackend

    @classmethod
    def from_config(cls, config: VmwareConfig) -> "Vmcli":
        return cls(config.vmcli())

    def invoke(self, module, command, *, vmx_path=None, arguments=None, verbose=False,
               timeout=None, check=True) -> ProcessResult:
        args = []
        if verbose:
            args.append("--verbose")
        if vmx_path:
            args.append(str(vmx_path))
        args += [module, command]
        if arguments:
            args += [str(a) for a in arguments]
        return self.backend.run(args, timeout=timeout, check=check)

    def power(self, vmx_path, command, *, arguments=None, verbose=False) -> ProcessResult:
        return self.invoke("Power", command, vmx_path=vmx_path, arguments=arguments, verbose=verbose)

    def snapshot(self, vmx_path, command, *, arguments=None, verbose=False) -> ProcessResult:
        return self.invoke("Snapshot", command, vmx_path=vmx_path, arguments=arguments, verbose=verbose)

    def serial(self, vmx_path, command, *, arguments=None, verbose=False) -> ProcessResult:
        return self.invoke("Serial", command, vmx_path=vmx_path, arguments=arguments, verbose=verbose)
