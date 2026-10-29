# nylib.vmware_wp

Control VMware Workstation Pro from Python — power VMs on/off, manage snapshots, run guest commands with output capture, and call the Workstation REST API. Zero third-party dependencies; backends include `vmrun`, `vmcli` (subprocess), and the REST daemon (stdlib `urllib`).

Keywords: Vmrun, Vmcli, WorkstationRest, Workstation, VmwareConfig, KernelDebugger, WinDbg, KD, serial named pipe, kernel debugging, REST API, power, snapshot, guest command, exec_in_guest, encrypted VM password, Credential Manager, GuestExecResult, ProcessResult, password auto-resolve

## Quick start

Create a Vmrun backend, configure it, and control a VM.

```python
# needs: VMware Workstation Pro installed
from nylib.vmware_wp import Vmrun, VmwareConfig

config = VmwareConfig()
vr = Vmrun.from_config(config)

vmx = r"D:\vm\Win11\Win11.vmx"
vr.power(vmx, "start")                           # encrypted VM: -vp resolved from Credential Manager
print(vr.list_running_vms())
vr.power(vmx, "stop", mode="soft")
```

## Power control

```python
# needs: VMware Workstation Pro installed
from nylib.vmware_wp import Vmrun, VmwareConfig

vr = Vmrun.from_config(VmwareConfig())
vmx = r"D:\vm\Win11\Win11.vmx"

vr.power(vmx, "start")                           # power on
vr.power(vmx, "suspend")                         # suspend
vr.power(vmx, "reset")                           # hard reset
vr.power(vmx, "stop", mode="soft")               # graceful shutdown
```

## Guest command execution with output capture

```python
# needs: VMware Workstation Pro installed
from nylib.vmware_wp import Vmrun, VmwareConfig

vr = Vmrun.from_config(VmwareConfig())
vmx = r"D:\vm\Win11\Win11.vmx"

# Run a command in the guest and get stdout, returncode
result = vr.exec_in_guest(vmx, "user", "password", "whoami /all", capture=True)
print(f"Exit code: {result.returncode}")
print(f"Output:\n{result.stdout}")
```

## Snapshots

```python
# needs: VMware Workstation Pro installed
from nylib.vmware_wp import Vmrun, VmwareConfig

vr = Vmrun.from_config(VmwareConfig())
vmx = r"D:\vm\Win11\Win11.vmx"

vr.create_snapshot(vmx, "baseline")              # create snapshot
print(vr.list_snapshots(vmx))                    # list all
vr.revert_to_snapshot(vmx, "baseline")           # revert to it
vr.delete_snapshot(vmx, "baseline")              # remove it
```

## Windows kernel debugging with WinDbg or KD

`KernelDebugger` connects a Windows guest's virtual COM port to a named pipe that an elevated WinDbg or KD on the host attaches to; the full walk-through is in the [README](../../nylib/vmware_wp/README.md#windows-kernel-debugging-over-a-named-pipe).

```python
# needs: VMware Workstation Pro, a powered-off Windows VM, an elevated host process
from nylib.vmware_wp import KernelDebugger, Vmrun, VmwareConfig

vmx = r"D:\vm\Win11\Win11.vmx"
vr = Vmrun.from_config(VmwareConfig())
kd = KernelDebugger(vmx, "analysis_kd", serial_port=1)  # COM1, host pipe \\.\pipe\analysis_kd

kd.configure_vmx(vmrun=vr)  # powered-off VM only; returns False if already configured
vr.power(vmx, "start")
# ... wait until vr.check_tools_state(vmx) reports "running"
kd.enable_guest("administrator", "guest-password", vmrun=vr)  # guest BCD; applies at the next guest reboot
debugger = kd.launch_debugger(
    r"C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\windbg.exe",
    break_on_connect=True,
    commands="g",
)
```

Then reboot the guest from inside, keep the debugger attached until the initial break has continued, and when finished call `kd.disable_guest(...)`, then reboot or shut down the guest. `configure_vmx` refuses an occupied COM port (pick `serial_port` 1 to 4) and enables VMware's **Yield CPU on poll**; BitLocker or Secure Boot adjustments in the guest are left to you.

## Notes

- Encrypted VM passwords are auto-resolved from the Windows Credential Manager (keyed by the VM's `encryptedVM.guid`); use `auto_vm_password=False` in `VmwareConfig` to disable.
- `exec_in_guest(..., capture=True)` stages the command in a guest batch file and copies output back; `capture=False` runs it directly without capturing.
- `ProcessResult` and `GuestExecResult` expose `.ok` (boolean), `.returncode`, `.stdout` / `.lines`, and `.command` (redacted for secrets: `-vp`, `-gu`, `-gp` passwords become `***`).
- For REST API access or cross-provider abstraction, see `WorkstationRest` and `Workstation` in the [full README](../../nylib/vmware_wp/README.md).
- Requires Python ≥ 3.11. No third-party dependencies; subprocess backends work on non-Windows where `vmrun`/`vmcli` exist (Fusion, etc.).
