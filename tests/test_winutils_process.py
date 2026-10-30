import ctypes
import os
import sys
import unittest
from ctypes import wintypes
from unittest.mock import MagicMock, patch

from nylib.winutils.process import run_admin


def _split(params: str) -> list[str]:
    """Split a command line with CommandLineToArgvW after a dummy program name."""
    shell32 = ctypes.WinDLL('shell32', use_last_error=True)
    shell32.CommandLineToArgvW.restype = ctypes.POINTER(wintypes.LPWSTR)
    shell32.CommandLineToArgvW.argtypes = (wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_int))
    argc = ctypes.c_int()
    argv = shell32.CommandLineToArgvW('prog ' + params, ctypes.byref(argc))
    try:
        return [argv[i] for i in range(1, argc.value)]
    finally:
        ctypes.WinDLL('kernel32').LocalFree(argv)


class RunAdminTests(unittest.TestCase):
    def _run(self, argv, orig_argv, frozen):
        shell_execute = MagicMock()
        with patch.object(ctypes.windll.shell32, 'IsUserAnAdmin', return_value=0), \
                patch.object(ctypes.windll.shell32, 'ShellExecuteW', shell_execute), \
                patch.object(sys, 'argv', argv), patch.object(sys, 'orig_argv', orig_argv), \
                patch.object(sys, 'frozen', frozen, create=True):
            with self.assertRaises(PermissionError):
                run_admin()
        shell_execute.assert_called_once()
        return shell_execute.call_args.args

    def test_frozen_passes_arguments_only(self):
        exe = r'C:\Apps\My Tool\tool.exe'
        args = self._run([exe, '--profile', r'C:\My Data\p.toml'], [exe, '--profile', r'C:\My Data\p.toml'], True)
        self.assertEqual(args[:3], (None, 'runas', sys.executable))
        self.assertEqual(_split(args[3]), ['--profile', r'C:\My Data\p.toml'])
        self.assertEqual(args[4], os.getcwd())

    def test_module_run_keeps_interpreter_options(self):
        argv = [r'C:\pkg\__main__.py', 'a b']
        args = self._run(argv, ['python', '-m', 'pkg', 'a b'], False)
        self.assertEqual(_split(args[3]), ['-m', 'pkg', 'a b'])
        self.assertEqual(args[4], os.getcwd())

    def test_already_admin_returns_without_launching(self):
        shell_execute = MagicMock()
        with patch.object(ctypes.windll.shell32, 'IsUserAnAdmin', return_value=1), \
                patch.object(ctypes.windll.shell32, 'ShellExecuteW', shell_execute):
            self.assertIsNone(run_admin())
        shell_execute.assert_not_called()


if __name__ == '__main__':
    unittest.main()
