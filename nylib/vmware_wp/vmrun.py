from __future__ import annotations

import os
import pathlib
import subprocess
import tempfile
from dataclasses import dataclass
from enum import Enum

from nylib.vmware_wp.config import VmwareConfig
from nylib.vmware_wp.errors import VmwareError
from nylib.vmware_wp.process import ProcessBackend
from nylib.vmware_wp.results import ProcessResult
from nylib.vmware_wp.wincred import read_encrypted_vm_password

_SECRET_FLAGS = {"-vp", "-gu", "-gp"}
_CMD = r"C:\Windows\System32\cmd.exe"


def _redact_secret_args(command):
    out, mask = [], False
    for tok in command:
        if mask:
            out.append("***")
            mask = False
            continue
        out.append(tok)
        if tok in _SECRET_FLAGS:
            mask = True
    return out


class VmrunPowerOp(str, Enum):
    START = "start"
    STOP = "stop"
    RESET = "reset"
    SUSPEND = "suspend"


@dataclass(frozen=True)
class GuestExecResult:
    """Result of Vmrun.exec_in_guest: exit code + (optionally captured) output."""

    returncode: int
    stdout: str
    command: tuple[str, ...]

    @property
    def ok(self) -> bool:
        return self.returncode == 0


@dataclass(frozen=True)
class Vmrun:
    backend: ProcessBackend
    host_type: str = "ws"
    auto_vm_password: bool = False

    @classmethod
    def from_config(cls, config: VmwareConfig) -> "Vmrun":
        return cls(config.vmrun(), auto_vm_password=config.auto_vm_password)

    def _resolve_vm_password(self, vmx_path, vm_password):
        """Use the explicit password, else (if enabled) auto-read from the OS store."""
        if vm_password is not None:
            return vm_password
        if self.auto_vm_password and vmx_path:
            return read_encrypted_vm_password(str(vmx_path))
        return None

    def invoke(self, args, *, guest_username=None, guest_password=None,
               vm_password=None, timeout=None, check=True) -> ProcessResult:
        command = ["-T", self.host_type]
        if vm_password:
            command += ["-vp", vm_password]
        if guest_username:
            command += ["-gu", guest_username]
        if guest_password:
            command += ["-gp", guest_password]
        command += [str(a) for a in args]
        return self.backend.run(command, timeout=timeout, check=check, redactor=_redact_secret_args)

    # ---- parsed queries ----
    def list_running_vms(self) -> list[str]:
        result = self.invoke(["list"])
        return [ln for ln in result.lines if not ln.startswith("Total running VMs:")]

    def list_snapshots(self, vmx_path, *, show_tree=False, vm_password=None) -> list[str]:
        vm_password = self._resolve_vm_password(vmx_path, vm_password)
        args = ["listSnapshots", str(vmx_path)]
        if show_tree:
            args.append("showTree")
        result = self.invoke(args, vm_password=vm_password)
        return [ln for ln in result.lines if not ln.startswith("Total snapshots:")]

    # ---- power ----
    def power(self, vmx_path, operation, *, mode=None, vm_password=None) -> ProcessResult:
        vm_password = self._resolve_vm_password(vmx_path, vm_password)
        op = operation.value if isinstance(operation, VmrunPowerOp) else VmrunPowerOp(operation).value
        args = [op, str(vmx_path)]
        if mode:
            args.append(mode)
        return self.invoke(args, vm_password=vm_password)

    # ---- snapshots (write) ----
    def create_snapshot(self, vmx_path, name, *, vm_password=None) -> ProcessResult:
        vm_password = self._resolve_vm_password(vmx_path, vm_password)
        return self.invoke(["snapshot", str(vmx_path), name], vm_password=vm_password)

    def revert_to_snapshot(self, vmx_path, name, *, vm_password=None) -> ProcessResult:
        vm_password = self._resolve_vm_password(vmx_path, vm_password)
        return self.invoke(["revertToSnapshot", str(vmx_path), name], vm_password=vm_password)

    def delete_snapshot(self, vmx_path, name, *, and_delete_children=False, vm_password=None) -> ProcessResult:
        vm_password = self._resolve_vm_password(vmx_path, vm_password)
        args = ["deleteSnapshot", str(vmx_path), name]
        if and_delete_children:
            args.append("andDeleteChildren")
        return self.invoke(args, vm_password=vm_password)

    # ---- info ----
    def get_guest_ip_address(self, vmx_path, *, wait=False, vm_password=None) -> ProcessResult:
        vm_password = self._resolve_vm_password(vmx_path, vm_password)
        args = ["getGuestIPAddress", str(vmx_path)]
        if wait:
            args.append("-wait")
        return self.invoke(args, vm_password=vm_password)

    def check_tools_state(self, vmx_path, *, vm_password=None) -> ProcessResult:
        vm_password = self._resolve_vm_password(vmx_path, vm_password)
        return self.invoke(["checkToolsState", str(vmx_path)], vm_password=vm_password)

    # ---- guest ops ----
    def run_program_in_guest(self, vmx_path, guest_username, guest_password, program_path, *,
                             program_arguments=None, no_wait=False, interactive=False,
                             active_window=False, vm_password=None) -> ProcessResult:
        vm_password = self._resolve_vm_password(vmx_path, vm_password)
        args = ["runProgramInGuest", str(vmx_path)]
        if no_wait:
            args.append("-noWait")
        if active_window:
            args.append("-activeWindow")
        if interactive:
            args.append("-interactive")
        args.append(str(program_path))
        if program_arguments:
            # vmrun runProgramInGuest wants the program's arguments as ONE
            # command-line string (splitting them into separate tokens fails for
            # cmd.exe). Join with Windows quoting rules.
            args.append(subprocess.list2cmdline([str(a) for a in program_arguments]))
        return self.invoke(args, guest_username=guest_username, guest_password=guest_password, vm_password=vm_password)

    def create_temp_file_in_guest(self, vmx_path, guest_username, guest_password, *, vm_password=None) -> str:
        """Create a temp file in the guest and return its path (from stdout)."""
        vm_password = self._resolve_vm_password(vmx_path, vm_password)
        res = self.invoke(
            ["CreateTempfileInGuest", str(vmx_path)],
            guest_username=guest_username, guest_password=guest_password, vm_password=vm_password,
        )
        return res.stdout.strip()

    def exec_in_guest(self, vmx_path, guest_username, guest_password, command, *,
                      vm_password=None, shell=True, capture=True, timeout=None) -> GuestExecResult:
        """Run a command in the guest, optionally capturing its combined output.

        - command: a shell command string (shell=True) or a program/argv
          (shell=False, str or [exe, *args]).
        - capture=True: redirect output to a guest temp file, copy it back, read
          and return it as GuestExecResult.stdout, then clean up.
        - capture=False: just run; stdout is "".
        Non-zero exit codes do not raise (the returncode is reported instead).
        """
        vm_password = self._resolve_vm_password(vmx_path, vm_password)

        def _inner_cmdline():
            if isinstance(command, (list, tuple)):
                return subprocess.list2cmdline([str(c) for c in command])
            return str(command)

        if capture:
            # Robust capture: write the command into a guest .bat and redirect the
            # WHOLE batch's output (`cmd /c bat > out 2>&1`). This sidesteps cmd's
            # operator-precedence (`a & b > f` redirects only `b`) and its
            # multi-quote `/c` mangling. vmware temp paths have no spaces, so the
            # redirect is left unquoted (quoting a /c line with 2+ paths breaks it).
            out_path = self.create_temp_file_in_guest(
                vmx_path, guest_username, guest_password, vm_password=vm_password,
            )
            if not out_path:
                raise VmwareError("could not create a temp file in guest for output capture")
            bat_path = out_path + ".bat"
            host_bat = tempfile.NamedTemporaryFile(
                prefix="nyvm_", suffix=".bat", delete=False, mode="w",
                encoding="utf-8", newline="\r\n",
            )
            try:
                host_bat.write("@echo off\n" + _inner_cmdline() + "\n")
                host_bat.close()
                self.copy_file_from_host_to_guest(
                    vmx_path, guest_username, guest_password, host_bat.name, bat_path,
                    vm_password=vm_password,
                )
            finally:
                try:
                    os.unlink(host_bat.name)
                except OSError:
                    pass
            res = self.invoke(
                ["runProgramInGuest", str(vmx_path), _CMD,
                 "/c " + bat_path + " > " + out_path + " 2>&1"],
                guest_username=guest_username, guest_password=guest_password,
                vm_password=vm_password, check=False, timeout=timeout,
            )
            host_tmp = tempfile.NamedTemporaryFile(prefix="nyvmexec_", suffix=".txt", delete=False)
            host_tmp.close()
            text = ""
            try:
                self.copy_file_from_guest_to_host(
                    vmx_path, guest_username, guest_password, out_path, host_tmp.name, vm_password=vm_password,
                )
                text = pathlib.Path(host_tmp.name).read_text(encoding="utf-8", errors="replace")
            finally:
                try:
                    os.unlink(host_tmp.name)
                except OSError:
                    pass
                for guest_path in (out_path, bat_path):
                    try:
                        self.delete_file_in_guest(
                            vmx_path, guest_username, guest_password, guest_path, vm_password=vm_password,
                        )
                    except VmwareError:
                        pass
            return GuestExecResult(res.returncode, text, res.command)

        if shell:
            args = ["runProgramInGuest", str(vmx_path), _CMD, "/c " + _inner_cmdline()]
        elif isinstance(command, (list, tuple)):
            program = str(command[0])
            rest = [str(c) for c in command[1:]]
            args = ["runProgramInGuest", str(vmx_path), program]
            if rest:
                args.append(subprocess.list2cmdline(rest))
        else:
            args = ["runProgramInGuest", str(vmx_path), str(command)]
        res = self.invoke(
            args, guest_username=guest_username, guest_password=guest_password,
            vm_password=vm_password, check=False, timeout=timeout,
        )
        return GuestExecResult(res.returncode, "", res.command)

    def run_script_in_guest(self, vmx_path, guest_username, guest_password, interpreter_path,
                            script_text, *, vm_password=None) -> ProcessResult:
        vm_password = self._resolve_vm_password(vmx_path, vm_password)
        return self.invoke(
            ["runScriptInGuest", str(vmx_path), interpreter_path, script_text],
            guest_username=guest_username, guest_password=guest_password, vm_password=vm_password,
        )

    def list_processes_in_guest(self, vmx_path, guest_username, guest_password, *, vm_password=None) -> ProcessResult:
        vm_password = self._resolve_vm_password(vmx_path, vm_password)
        return self.invoke(
            ["listProcessesInGuest", str(vmx_path)],
            guest_username=guest_username, guest_password=guest_password, vm_password=vm_password,
        )

    def copy_file_from_host_to_guest(self, vmx_path, guest_username, guest_password, host_path, guest_path, *,
                                     vm_password=None, timeout=None) -> ProcessResult:
        vm_password = self._resolve_vm_password(vmx_path, vm_password)
        return self.invoke(
            ["copyFileFromHostToGuest", str(vmx_path), str(host_path), str(guest_path)],
            guest_username=guest_username, guest_password=guest_password, vm_password=vm_password, timeout=timeout,
        )

    def copy_file_from_guest_to_host(self, vmx_path, guest_username, guest_password, guest_path, host_path, *,
                                     vm_password=None, timeout=None) -> ProcessResult:
        vm_password = self._resolve_vm_password(vmx_path, vm_password)
        return self.invoke(
            ["copyFileFromGuestToHost", str(vmx_path), str(guest_path), str(host_path)],
            guest_username=guest_username, guest_password=guest_password, vm_password=vm_password, timeout=timeout,
        )

    def file_exists_in_guest(self, vmx_path, guest_username, guest_password, guest_path, *, vm_password=None) -> ProcessResult:
        vm_password = self._resolve_vm_password(vmx_path, vm_password)
        return self.invoke(
            ["fileExistsInGuest", str(vmx_path), str(guest_path)],
            guest_username=guest_username, guest_password=guest_password, vm_password=vm_password, check=False,
        )

    def directory_exists_in_guest(self, vmx_path, guest_username, guest_password, guest_path, *, vm_password=None) -> ProcessResult:
        vm_password = self._resolve_vm_password(vmx_path, vm_password)
        return self.invoke(
            ["directoryExistsInGuest", str(vmx_path), str(guest_path)],
            guest_username=guest_username, guest_password=guest_password, vm_password=vm_password, check=False,
        )

    def list_directory_in_guest(self, vmx_path, guest_username, guest_password, guest_path, *, vm_password=None) -> ProcessResult:
        vm_password = self._resolve_vm_password(vmx_path, vm_password)
        return self.invoke(
            ["listDirectoryInGuest", str(vmx_path), str(guest_path)],
            guest_username=guest_username, guest_password=guest_password, vm_password=vm_password,
        )

    def create_directory_in_guest(self, vmx_path, guest_username, guest_password, guest_path, *, vm_password=None) -> ProcessResult:
        vm_password = self._resolve_vm_password(vmx_path, vm_password)
        return self.invoke(
            ["createDirectoryInGuest", str(vmx_path), str(guest_path)],
            guest_username=guest_username, guest_password=guest_password, vm_password=vm_password,
        )

    def delete_file_in_guest(self, vmx_path, guest_username, guest_password, guest_path, *, vm_password=None) -> ProcessResult:
        vm_password = self._resolve_vm_password(vmx_path, vm_password)
        return self.invoke(
            ["deleteFileInGuest", str(vmx_path), str(guest_path)],
            guest_username=guest_username, guest_password=guest_password, vm_password=vm_password,
        )

    def delete_directory_in_guest(self, vmx_path, guest_username, guest_password, guest_path, *, vm_password=None) -> ProcessResult:
        vm_password = self._resolve_vm_password(vmx_path, vm_password)
        return self.invoke(
            ["deleteDirectoryInGuest", str(vmx_path), str(guest_path)],
            guest_username=guest_username, guest_password=guest_password, vm_password=vm_password,
        )
