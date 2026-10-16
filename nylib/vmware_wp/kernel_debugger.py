from __future__ import annotations

import os
import re
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from nylib.vmware_wp.config import VmwareConfig
from nylib.vmware_wp.errors import BinaryNotFoundError, VmwareConfigError
from nylib.vmware_wp.vmrun import GuestExecResult, Vmrun


_PIPE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
_VMX_SETTING = re.compile(rb"[ \t]*(serial\d+\.[^= \t]+)[ \t]*=[ \t]*(.*)", re.I)
_GUEST_MARKER = "__NYLIB_KD_CONFIGURED__"


@dataclass(frozen=True)
class KernelDebugger:
    """WinDbg/KD serial-pipe setup for a Windows guest in Workstation Pro."""

    vmx_path: Path
    pipe_name: str
    serial_port: int = 1

    def __post_init__(self):
        object.__setattr__(self, "vmx_path", Path(self.vmx_path))
        if not _PIPE_NAME.fullmatch(self.pipe_name):
            raise ValueError("pipe_name must be a simple Windows named-pipe name")
        if type(self.serial_port) is not int or not 1 <= self.serial_port <= 4:
            raise ValueError("serial_port must be an integer from 1 to 4 (COM1 to COM4)")

    @property
    def pipe_path(self) -> str:
        return "\\\\.\\pipe\\" + self.pipe_name

    def configure_vmx(self, *, vmrun: Vmrun | None = None) -> bool:
        """Add the serial pipe to a powered-off VMX; return False if already configured."""
        path = self.vmx_path
        if path.suffix.lower() != ".vmx" or not path.is_file():
            raise VmwareConfigError(f"VMX file does not exist: {path}")

        source = path.read_bytes()
        prefix = f"serial{self.serial_port - 1}."
        settings = {
            prefix + "present": "TRUE",
            prefix + "fileType": "pipe",
            prefix + "fileName": self.pipe_path,
            prefix + "pipe.endPoint": "server",
            prefix + "startConnected": "TRUE",
            prefix + "yieldOnMsrRead": "TRUE",
        }
        existing: dict[str, list[str]] = {}
        for line in source.splitlines():
            match = _VMX_SETTING.fullmatch(line)
            if match is None:
                continue
            key = match.group(1).decode("ascii").lower()
            value = match.group(2).strip().strip(b'"').decode("utf-8", errors="replace")
            if key.startswith(prefix):
                existing.setdefault(key, []).append(value)
            elif key.endswith(".filename") and key.startswith("serial") and value == self.pipe_path:
                raise VmwareConfigError(f"named pipe is already assigned to {key}")

        if existing:
            if all(existing.get(key.lower()) == [value] for key, value in settings.items()):
                return False
            raise VmwareConfigError(
                f"COM{self.serial_port} already has serial settings; choose a free port or remove them first"
            )

        runner = vmrun if vmrun is not None else Vmrun.from_config(VmwareConfig())
        target = os.path.normcase(os.path.abspath(path))
        if any(os.path.normcase(os.path.abspath(vmx)) == target for vmx in runner.list_running_vms()):
            raise VmwareConfigError("power off the VM before changing its serial-port configuration")

        newline = b"\r\n" if b"\r\n" in source else b"\n"
        addition = newline.join(f'{key} = "{value}"'.encode("ascii") for key, value in settings.items())
        contents = source + (newline if source and not source.endswith((b"\n", b"\r")) else b"") + addition + newline
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(dir=path.parent, prefix=path.name + ".", suffix=".tmp",
                                             delete=False) as handle:
                temporary = Path(handle.name)
                handle.write(contents)
            os.replace(temporary, path)
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)
        return True

    def enable_guest(self, guest_username: str, guest_password: str, *, vmrun: Vmrun | None = None,
                     vm_password: str | None = None) -> GuestExecResult:
        """Set the guest BCD serial transport and enable kernel debugging."""
        command = (
            f"bcdedit /dbgsettings serial debugport:{self.serial_port} baudrate:115200"
            f" && bcdedit /debug on && echo {_GUEST_MARKER}"
        )
        return self._run_guest_bcd(command, guest_username, guest_password, vmrun=vmrun,
                                   vm_password=vm_password)

    def disable_guest(self, guest_username: str, guest_password: str, *, vmrun: Vmrun | None = None,
                      vm_password: str | None = None) -> GuestExecResult:
        """Disable kernel debugging in the guest's current boot entry."""
        return self._run_guest_bcd(f"bcdedit /debug off && echo {_GUEST_MARKER}",
                                   guest_username, guest_password, vmrun=vmrun, vm_password=vm_password)

    def _run_guest_bcd(self, command: str, guest_username: str, guest_password: str, *,
                       vmrun: Vmrun | None, vm_password: str | None) -> GuestExecResult:
        runner = vmrun if vmrun is not None else Vmrun.from_config(VmwareConfig())
        result = runner.exec_in_guest(self.vmx_path, guest_username, guest_password, command,
                                      vm_password=vm_password, capture=True)
        if result.returncode != 0 or _GUEST_MARKER not in result.stdout.splitlines():
            raise VmwareConfigError(f"guest BCD setup failed: {result.stdout.strip() or result.returncode}")
        return result

    def debugger_command(self, executable: str | Path = "windbg.exe", *, break_on_connect: bool = False,
                         commands: str | None = None, log_path: str | Path | None = None) -> tuple[str, ...]:
        """Build a WinDbg or KD command line for the VMware-hosted pipe."""
        command = [str(executable)]
        if break_on_connect:
            command.append("-b")
        if log_path is not None:
            command.extend(("-logo", str(log_path)))
        if commands is not None:
            command.extend(("-c", commands))
        command.extend(("-k", f"com:pipe,port={self.pipe_path}"))
        return tuple(command)

    def launch_debugger(self, executable: str | Path = "windbg.exe", *, break_on_connect: bool = False,
                        commands: str | None = None, log_path: str | Path | None = None):
        """Start WinDbg/KD without waiting for the debugging session to end."""
        command = self.debugger_command(executable, break_on_connect=break_on_connect,
                                        commands=commands, log_path=log_path)
        try:
            return subprocess.Popen(command)
        except FileNotFoundError as exc:
            raise BinaryNotFoundError(str(executable)) from exc
