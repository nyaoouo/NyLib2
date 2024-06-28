import ctypes
import sys

from .. import winapi


def iter_processes():
    hSnap = winapi.CreateToolhelp32Snapshot(0x00000002, 0)
    process_entry = winapi.ProcessEntry32()
    process_entry.dwSize = ctypes.sizeof(process_entry)
    winapi.Process32First(hSnap, ctypes.byref(process_entry))
    try:
        yield process_entry
        while 1:
            yield process_entry
            winapi.Process32Next(hSnap, ctypes.byref(process_entry))
    except WindowsError as e:
        if e.winerror != 18:
            raise
    finally:
        winapi.CloseHandle(hSnap)


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
    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
    raise PermissionError("Need admin permission, a new process should be started, if not, please run it as admin manually")


def enable_privilege():
    hProcess = ctypes.c_void_p(winapi.GetCurrentProcess())
    if winapi.OpenProcessToken(hProcess, 32, ctypes.byref(hProcess)):
        tkp = winapi.TOKEN_PRIVILEGES()
        winapi.LookupPrivilegeValue(None, "SeDebugPrivilege", ctypes.byref(tkp.Privileges[0].Luid))
        tkp.count = 1
        tkp.Privileges[0].Attributes = 2
        winapi.AdjustTokenPrivileges(hProcess, 0, ctypes.byref(tkp), 0, None, None)
