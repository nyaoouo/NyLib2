from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from nylib.vmware_wp import KernelDebugger, VmwareConfigError
from nylib.vmware_wp.vmrun import GuestExecResult


class FakeVmrun:
    def __init__(self, *, running=(), guest_output="__NYLIB_KD_CONFIGURED__\n"):
        self.running = running
        self.guest_output = guest_output
        self.command = None

    def list_running_vms(self):
        return self.running

    def exec_in_guest(self, vmx_path, username, password, command, **kwargs):
        self.command = command
        return GuestExecResult(0, self.guest_output, ())


class KernelDebuggerTests(unittest.TestCase):
    def test_configure_vmx_preserves_bytes_and_is_idempotent(self):
        with tempfile.TemporaryDirectory() as directory:
            vmx = Path(directory) / "test.vmx"
            original = b'.encoding = "windows-1252"\r\ndisplayName = "caf\xe9"\r\n'
            vmx.write_bytes(original)
            debugger = KernelDebugger(vmx, "sample_kd")
            self.assertTrue(debugger.configure_vmx(vmrun=FakeVmrun()))
            configured = vmx.read_bytes()
            self.assertTrue(configured.startswith(original))
            self.assertIn(b'serial0.fileName = "\\\\.\\pipe\\sample_kd"\r\n', configured)
            self.assertIn(b'serial0.pipe.endPoint = "server"\r\n', configured)
            self.assertIn(b'serial0.yieldOnMsrRead = "TRUE"\r\n', configured)
            self.assertFalse(debugger.configure_vmx(vmrun=FakeVmrun()))
            self.assertEqual(vmx.read_bytes(), configured)

    def test_configure_vmx_rejects_running_vm_and_occupied_port(self):
        with tempfile.TemporaryDirectory() as directory:
            vmx = Path(directory) / "test.vmx"
            vmx.write_text('displayName = "test"\n', encoding="ascii")
            debugger = KernelDebugger(vmx, "sample_kd")
            with self.assertRaisesRegex(VmwareConfigError, "power off"):
                debugger.configure_vmx(vmrun=FakeVmrun(running=[str(vmx)]))
            self.assertNotIn(b"serial0", vmx.read_bytes())
            vmx.write_text('serial0.present = "TRUE"\nserial0.fileType = "thinprint"\n', encoding="ascii")
            with self.assertRaisesRegex(VmwareConfigError, "already has serial settings"):
                debugger.configure_vmx(vmrun=FakeVmrun())

    def test_guest_setup_checks_output_and_debugger_command(self):
        debugger = KernelDebugger(Path("test.vmx"), "sample_kd", serial_port=2)
        runner = FakeVmrun()
        debugger.enable_guest("user", "password", vmrun=runner)
        self.assertIn("debugport:2 baudrate:115200", runner.command)
        self.assertIn("bcdedit /debug on", runner.command)
        debugger.disable_guest("user", "password", vmrun=runner)
        self.assertIn("bcdedit /debug off", runner.command)
        with self.assertRaisesRegex(VmwareConfigError, "guest BCD setup failed"):
            debugger.enable_guest("user", "password", vmrun=FakeVmrun(guest_output="Access is denied"))
        self.assertEqual(
            debugger.debugger_command("kd.exe", break_on_connect=True),
            ("kd.exe", "-b", "-k", r"com:pipe,port=\\.\pipe\sample_kd"),
        )
        self.assertEqual(
            debugger.debugger_command("kd.exe", commands=".echo ready;g", log_path="kd.log"),
            ("kd.exe", "-logo", "kd.log", "-c", ".echo ready;g", "-k",
             r"com:pipe,port=\\.\pipe\sample_kd"),
        )

    def test_launch_is_nonblocking_and_passes_argv(self):
        debugger = KernelDebugger(Path("test.vmx"), "sample_kd")
        with patch("nylib.vmware_wp.kernel_debugger.subprocess.Popen") as popen:
            self.assertIs(debugger.launch_debugger("kd.exe"), popen.return_value)
        popen.assert_called_once_with(debugger.debugger_command("kd.exe"))


if __name__ == "__main__":
    unittest.main()
