# nylib.vmware_wp

Control **VMware Workstation Pro** from Python — power, snapshots, guest commands, and the
Workstation REST API — through one uniform, synchronous, **zero-dependency** interface.

- Backends: `vmrun` and `vmcli` (subprocess) + the Workstation **REST** daemon (stdlib `urllib`).
- Exceptions-primary error model; secrets are redacted in results and error messages.
- Encrypted-VM passwords can be **auto-resolved** from the Windows Credential Manager.

## Quick start

```python
from nylib.vmware_wp import Vmrun, VmwareConfig

vmx = r"D:\vm\Win11\Win11.vmx"
vr = Vmrun.from_config(VmwareConfig())   # auto_vm_password=True

vr.power(vmx, "start")                    # encrypted VM: -vp resolved automatically
print(vr.list_running_vms())

# run a command in the guest and capture its output in one call
out = vr.exec_in_guest(vmx, "user", "password", "whoami /all", capture=True)
print(out.returncode, out.stdout)

vr.power(vmx, "stop", mode="soft")        # graceful shutdown
```

## Layout

| Module | Purpose |
|---|---|
| `config.py` | `VmwareConfig` — single place to build backends (paths, REST url/auth, `auto_vm_password`). |
| `results.py` | `CommandResult` / `ProcessResult` (`.ok`, `.lines`) / `RestResult` (`.ok`, `.json`). |
| `errors.py` | `VmwareError` tree: `BinaryNotFoundError`, `CredentialNotFoundError`, `VmwareTimeoutError`, `ProcessCommandError`, `RestRequestError`, `VmwareConfigError`. |
| `discovery.py` | `discover_binary()` — PATH + Windows registry + well-known install dirs. |
| `process.py` | `ProcessBackend` — `subprocess.run` wrapper (`run(args, *, timeout, check, env, redactor)`). |
| `rest.py` | `RestBackend` — `urllib` wrapper (`request(method, endpoint, *, json_body, headers, data, ...)`). |
| `vmrun.py` | `Vmrun` (power / snapshots / guest ops / `exec_in_guest`), `VmrunPowerOp`, `GuestExecResult`. |
| `vmcli.py` | `Vmcli` — `invoke` + `power` / `snapshot` / `serial` helpers. |
| `kernel_debugger.py` | `KernelDebugger` — Windows guest KD over a VMware serial named pipe. |
| `rest_api.py` | `WorkstationRest` + endpoint catalog + `render_endpoint`. |
| `workstation.py` | `Workstation` — fallback-chain facade across providers; `NoProviderError`. |
| `wincred.py` | Recover encrypted-VM passwords from the Windows Credential Manager. |

## Error model

Failures **raise** (`BinaryNotFoundError`, `VmwareTimeoutError`, `ProcessCommandError`,
`RestRequestError`, …); a returned `Result` means success. Pass `check=False` to a method/`invoke`
to receive the `ProcessResult` instead of raising — useful for probes like `file_exists_in_guest`
where a non-zero exit code is meaningful data. vmrun reports guest errors on **stdout**, so inspect
`err.result.stdout` when handling `ProcessCommandError`.

## Encrypted VMs

The VM *encryption* password is distinct from *guest login* credentials. With
`VmwareConfig.auto_vm_password=True` (default), `Vmrun` reads the encryption password from the
Windows Credential Manager (keyed by the vmx's `encryptedVM.guid`) when you don't pass one — so
`start` and guest ops on encrypted VMs work without prompting. Pass `vm_password=...` explicitly to
override, or set `auto_vm_password=False` to disable. Off-Windows / when no password is stored, it
falls back to `None` (i.e. behaves as unencrypted).

## Guest command execution

`vmrun runProgramInGuest` does not return stdout and expects a program's arguments as a single
command-line string. `Vmrun.exec_in_guest(..., capture=True)` handles both: it stages the command in
a guest batch file, redirects the whole batch to a temp file, and copies the output back — returning
a `GuestExecResult(returncode, stdout, command)`. Use `shell=False` to run a program directly, and
`capture=False` to skip output capture.

## Windows kernel debugging over a named pipe

`KernelDebugger` connects a Windows guest's virtual COM port to WinDbg or KD on the VMware host.
Run `configure_vmx` while the VM is powered off. It adds a server-side named pipe to an unused COM
port, preserves the rest of the VMX file, and refuses to replace an existing serial port. `enable_guest`
requires an administrator account inside the running guest and verifies that both BCDEdit commands
finished successfully. The debugger process runs on the host and must be elevated.
The port enables VMware's **Yield CPU on poll** setting so serial polling does not monopolize host CPU.

```python
import time

from nylib.vmware_wp import KernelDebugger, ProcessCommandError, Vmrun, VmwareConfig

vmx = r"D:\vm\Win11\Win11.vmx"
vr = Vmrun.from_config(VmwareConfig())
kd = KernelDebugger(vmx, "win11_kd", serial_port=1)  # COM1

kd.configure_vmx(vmrun=vr)                 # VM must be powered off
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

Wait for the guest restart and debugger connection before issuing more guest commands. After analysis,
once VMware Tools is running again, call `kd.disable_guest(...)` and reboot or shut down the guest.
`break_on_connect=True` stops the guest at the initial break; `commands="g"` resumes it automatically.
Do not close the debugger immediately on connection: the guest may still be stopped at that break.

`debugger_command(executable="kd.exe")` returns the command tuple for a console debugger or an
external process manager; `launch_debugger(executable="kd.exe")` returns a `subprocess.Popen` without
waiting for a debugging session to end. Pass `break_on_connect=True` to request an immediate break,
`commands="..."` for WinDbg/KD startup commands, and `log_path="..."` to write a debugger log.
The serial transport is `com:pipe,port=\\.\pipe\win11_kd`. VMware's server endpoint creates the pipe
after VM power-on, so start the debugger after the VM starts and before the guest reboot. If a VMware
reset drops the session, restart WinDbg/KD.

The VMX configuration and guest BCD are separate changes. BCDEdit may require BitLocker or Secure
Boot adjustments in the guest; this library does not change those settings. See the
[Microsoft VM debugging guide](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/attaching-to-a-virtual-machine--kernel-mode-)
and the [VMware Workstation Pro 17 guide](https://techdocs2-prod.adobecqms.net/content/dam/broadcom/techdocs/us/en/pdf/vmware/desktop-hypervisors/workstation/vmware-workstation-pro-17-0.pdf).

## Folder copy (archive → transfer → unarchive)

`vmrun` only copies single files. `Vmrun.copy_folder_from_host_to_guest` /
`copy_folder_from_guest_to_host` move a whole directory's *contents* by packing it into one
**`.tar.gz`**, shipping that single file, and unpacking on the far side. `tar.gz` is the most
portable choice: Linux's GNU `tar` and the `tar.exe` (bsdtar) bundled with Windows 10 1803+ both
create *and* extract it with no extra tooling. The guest OS is auto-detected from the vmx's
`guestOS` line (override with `guest_os="windows"|"posix"`).

`file_filter` (a glob string or an iterable of globs) is applied **guest-side**: at extraction for
host→guest, at archiving for guest→host. `None` copies everything.

```python
# push a payload folder into a fresh guest dir
vr.copy_folder_from_host_to_guest(vmx, "user", "pw", r".\guest", r"C:\Temp\run123")

# pull just the logs back to the host
vr.copy_folder_from_guest_to_host(vmx, "user", "pw", r"C:\Temp\run123\output", r".\output",
                                  file_filter="*.log")
```

> Param ordering follows the single-file helpers (host→guest: `host_path, guest_path`;
> guest→host: `guest_path, host_path`). The Windows guest path is fully tested; the posix path
> (`/bin/sh -c tar …`) is best-effort.

## Notes

- Requires Python ≥ 3.11. No third-party runtime dependencies.
- Windows-focused (registry discovery, Credential Manager); subprocess backends also work where
  `vmrun`/`vmcli` exist (e.g. Fusion) but credential auto-resolution is Windows-only.
