> 本文档为 vmware_wp.md 的中文阅读副本；英文版为权威来源（canonical）。

<!-- dt:meta v="1" lang="zh" source="vmware_wp.md" -->

<!-- dt:section id="__preamble__" hash="c69473cad6c6" -->
# nylib.vmware_wp

从 Python 控制 VMware Workstation Pro — 打开/关闭 VM 电源、管理快照、运行来宾命令并捕获输出，以及调用 Workstation REST API。零第三方依赖；后端包括 `vmrun`、`vmcli`（子流程）和 REST 守护程序（stdlib `urllib`）。

关键词: Vmrun, Vmcli, WorkstationRest, Workstation, VmwareConfig, KernelDebugger, WinDbg, KD, serial named pipe, kernel debugging, REST API, power, snapshot, guest command, exec_in_guest, encrypted VM password, Credential Manager, GuestExecResult, ProcessResult, password auto-resolve

<!-- dt:section id="quick-start-0" hash="265063375286" -->
## Quick start

创建一个 Vmrun 后端，配置它，并控制一个 VM。

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

<!-- dt:section id="power-control-0" hash="7956d85b18e1" -->
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

<!-- dt:section id="guest-command-execution-with-output-capture-0" hash="d048c4fd1ca2" -->
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

<!-- dt:section id="snapshots-0" hash="a1c202cabf8a" -->
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

<!-- dt:section id="windows-kernel-debugging-with-windbg-or-kd-0" hash="8e0db86614d9" -->
## Windows kernel debugging with WinDbg or KD

`KernelDebugger` 将 Windows 来宾的虚拟 COM 端口连接到一个命名管道，宿主机上以提升权限运行的 WinDbg 或 KD 可附加到该管道；完整的演练见 [README](../../nylib/vmware_wp/README.md#windows-kernel-debugging-over-a-named-pipe)。

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

然后从来宾内部重启来宾，在初始中断继续执行之前保持调试器附加，完成后调用 `kd.disable_guest(...)`，再重启或关闭来宾。`configure_vmx` 会拒绝已被占用的 COM 端口（请选择 `serial_port` 1 到 4），并启用 VMware 的 **Yield CPU on poll**；来宾中 BitLocker 或 Secure Boot 的调整由你自行处理。

<!-- dt:section id="notes-0" hash="0adf06c84708" -->
## Notes

- 加密的 VM 密码自动从 Windows 凭据管理器解析（由 VM 的 `encryptedVM.guid` 键控）；在 `VmwareConfig` 中使用 `auto_vm_password=False` 禁用。
- `exec_in_guest(..., capture=True)` 在来宾批处理文件中暂存命令并复制输出返回；`capture=False` 直接运行而不捕获。
- `ProcessResult` 和 `GuestExecResult` 公开 `.ok`（布尔值）、`.returncode`、`.stdout` / `.lines` 和 `.command`（密钥已编辑：`-vp`、`-gu`、`-gp` 密码变为 `***`）。
- 有关 REST API 访问或跨提供程序抽象，请参阅[完整 README](../../nylib/vmware_wp/README.md) 中的 `WorkstationRest` 和 `Workstation`。
- 需要 Python ≥ 3.11。无第三方依赖；子流程后端可在 `vmrun`/`vmcli` 存在的非 Windows 系统上运行（Fusion 等）。
