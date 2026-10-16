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

`KernelDebugger` connects a Windows guest's virtual COM port to a named pipe on the VMware host.
First configure the VMX while powered off. Once the VM and VMware Tools are running, enable the
guest's serial kernel debug transport using an administrator account. Start the host debugger in an
elevated process, then reboot from inside the guest to apply the BCD settings.

```python
import time

from nylib.vmware_wp import KernelDebugger, ProcessCommandError, Vmrun, VmwareConfig

vmx = r"D:\vm\Win11\Win11.vmx"
vr = Vmrun.from_config(VmwareConfig())
kd = KernelDebugger(vmx, "analysis_kd", serial_port=1)  # COM1

kd.configure_vmx(vmrun=vr)  # powered-off VM only; returns False if already configured
vr.power(vmx, "start")
for _ in range(60):
    try:
        if vr.check_tools_state(vmx).stdout.strip() == "running":
            break
    except ProcessCommandError:
        pass
    time.sleep(2)
else:
    raise TimeoutError("VMware Tools did not become ready within 120 seconds")

kd.enable_guest("administrator", "guest-password", vmrun=vr)
debugger = kd.launch_debugger(
    r"C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\windbg.exe",
    break_on_connect=True,
    commands="g",
)
restart = vr.exec_in_guest(
    vmx, "administrator", "guest-password",
    "shutdown /r /t 30 && echo __KD_RESTART_SCHEDULED__", capture=True,
)
if restart.returncode or "__KD_RESTART_SCHEDULED__" not in restart.stdout:
    raise RuntimeError(f"Guest restart was not scheduled: {restart.stdout}")
```

Wait for the guest restart and debugger connection before issuing more guest commands. When analysis
is finished and VMware Tools is running again, call `kd.disable_guest(...)` and reboot or shut down
the guest to return to a non-debug boot. Keep the debugger attached until the initial break has
continued: `break_on_connect=True` stops the guest, and `commands="g"` resumes it automatically.
Closing the debugger immediately on connection can leave the guest stopped at the break.

Use `kd.debugger_command("kd.exe")` to get an argument tuple for an external process manager, or
`kd.launch_debugger("kd.exe", break_on_connect=True)` for an immediate-break console session. The
launch call returns a `subprocess.Popen` immediately. Use `commands="..."` for debugger startup
commands and `log_path="..."` to record a session. `configure_vmx` refuses an occupied COM port;
select another `serial_port` from 1 to 4 if the VM already uses COM1. It never edits the guest's BCD;
`enable_guest` performs that separate step and reports failed BCDEdit output.

The serial port enables VMware's **Yield CPU on poll** setting. Windows kernel debugging polls the
virtual COM port, and without this setting VMware can consume excessive host CPU time.

The host debugger connects to `\\.\pipe\analysis_kd`. A VMware server-side pipe is created after
power-on. For VMware, the command omits the generic `resets=0,reconnect` options; if a VMware reset
drops the debugger session, launch it again. BCDEdit changes may require guest BitLocker or Secure
Boot adjustments, which the library does not make. See [Microsoft's virtual COM kernel debugging
guide](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/attaching-to-a-virtual-machine--kernel-mode-)
and the [VMware Workstation Pro 17 guide](https://techdocs2-prod.adobecqms.net/content/dam/broadcom/techdocs/us/en/pdf/vmware/desktop-hypervisors/workstation/vmware-workstation-pro-17-0.pdf).

## Notes

- Encrypted VM passwords are auto-resolved from the Windows Credential Manager (keyed by the VM's `encryptedVM.guid`); use `auto_vm_password=False` in `VmwareConfig` to disable.
- `exec_in_guest(..., capture=True)` stages the command in a guest batch file and copies output back; `capture=False` runs it directly without capturing.
- `ProcessResult` and `GuestExecResult` expose `.ok` (boolean), `.returncode`, `.stdout` / `.lines`, and `.command` (redacted for secrets: `-vp`, `-gu`, `-gp` passwords become `***`).
- For REST API access or cross-provider abstraction, see `WorkstationRest` and `Workstation` in the [full README](../../nylib/vmware_wp/README.md).
- Requires Python ≥ 3.11. No third-party dependencies; subprocess backends work on non-Windows where `vmrun`/`vmcli` exist (Fusion, etc.).
