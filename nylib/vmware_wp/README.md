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
