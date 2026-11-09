import ctypes
import dataclasses
import os
import sys
import shlex
import subprocess

from .. import winapi


def _ansi_name(name: str) -> bytes:
    try:
        raw = name.encode('mbcs')
    except UnicodeEncodeError:
        parts = []
        for c in name:
            try:
                parts.append(c.encode('mbcs'))
            except UnicodeEncodeError:
                parts.append(b'?' * (2 if ord(c) > 0xFFFF else 1))
        raw = b''.join(parts)
    return raw[:259]


def iter_processes():
    from ..process._snapshot import Snapshot
    for record in Snapshot().processes():
        entry = winapi.ProcessEntry32()
        entry.dwSize = ctypes.sizeof(winapi.ProcessEntry32)
        entry.th32ProcessID = record.process_id
        entry.cntThreads = record.thread_count
        entry.th32ParentProcessID = record.parent_process_id
        entry.pcPriClassBase = record.base_priority & 0xFFFFFFFF
        entry.szExeFile = _ansi_name(record.name)
        yield entry


@dataclasses.dataclass(frozen=True)
class ProcessInfo:
    """One process from a system snapshot; `creation_time` is a FILETIME (100-ns ticks since 1601)."""
    name: str
    process_id: int
    parent_process_id: int
    session_id: int
    creation_time: int
    thread_count: int


def list_processes() -> list[ProcessInfo]:
    """Every process from one system snapshot, in snapshot order; opens no process and needs no privilege."""
    from ..process._snapshot import Snapshot
    return [ProcessInfo(r.name, r.process_id, r.parent_process_id, r.session_id, r.creation_time, r.thread_count)
            for r in Snapshot().processes()]


def pid_by_executable(executable_name: bytes | str):
    if isinstance(executable_name, str):
        executable_name = executable_name.encode(winapi.DEFAULT_ENCODING)
    for process in iter_processes():
        if process.szExeFile == executable_name:
            yield process.th32ProcessID


def run_admin():
    try:
        if ctypes.windll.shell32.IsUserAnAdmin(): return
    except:
        pass
    args = sys.argv[1:] if getattr(sys, 'frozen', False) else sys.orig_argv[1:]
    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, subprocess.list2cmdline(args), os.getcwd(), 1)
    raise PermissionError("Need admin permission, a new process should be started, if not, please run it as admin manually")


def enable_privilege():
    hProcess = ctypes.c_void_p(winapi.GetCurrentProcess())
    if winapi.OpenProcessToken(hProcess, 32, ctypes.byref(hProcess)):
        tkp = winapi.TOKEN_PRIVILEGES()
        winapi.LookupPrivilegeValue(None, "SeDebugPrivilege", ctypes.byref(tkp.Privileges[0].Luid))
        tkp.count = 1
        tkp.Privileges[0].Attributes = 2
        winapi.AdjustTokenPrivileges(hProcess, 0, ctypes.byref(tkp), 0, None, None)


class create_suspend_process:
    def __init__(self, cmd, **kwargs):
        if isinstance(cmd, (list, tuple)):
            cmd = shlex.join(cmd)
        if isinstance(cmd, str):
            cmd = cmd.encode(winapi.DEFAULT_ENCODING)
        assert isinstance(cmd, bytes), type(cmd)
        self.cmd = cmd
        self.process_information = None
        self.startup_info = winapi.STARTUPINFOA(**kwargs)

    def start(self):
        assert not self.process_information, "Process already started"
        self.process_information = winapi.PROCESS_INFORMATION()
        winapi.CreateProcessA(
            None, self.cmd,
            None, None, 0,
            4 | 8,  # CREATE_SUSPENDED | DETACHED_PROCESS
            None, None,
            ctypes.byref(self.startup_info), ctypes.byref(self.process_information)
        )
        return self

    def resume(self):
        assert self.process_information, "Process not started"
        winapi.ResumeThread(self.process_information.hThread)

    def wait(self):
        assert self.process_information, "Process not started"
        winapi.WaitForSingleObject(self.process_information.hProcess, -1)

    def __del__(self):
        if self.process_information:
            winapi.CloseHandle(self.process_information.hProcess)
            winapi.CloseHandle(self.process_information.hThread)

    def __enter__(self):
        return self.start()

    def __exit__(self, exc_type, exc_val, exc_tb):
        # self.wait()
        self.resume()
