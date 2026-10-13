> 本文档为 sign.md 的中文阅读副本；英文版为权威来源（canonical）。

<!-- dt:meta v="1" lang="zh" source="sign.md" -->

<!-- dt:section id="__preamble__" hash="5a05e7496623" -->
# nylib.winutils.sign

用 Authenticode 证书签署 PE 文件并验证签名，具有内置驱动程序（内核模式）签署和自动处理已过期测试证书的功能。

关键词: SigningService, VerificationService, CertificateLoader, SignRequest, sign, verify, Authenticode, driver signing, cross-cert, certificate, PFX, hash algorithm, timestamping, expired cert, bypass, MSCVStore

<!-- dt:section id="quick-start-0" hash="4f028c66ce1e" -->
## Quick start

验证系统二进制文件上的签名（不需要证书）：

```python
from nylib.winutils.sign import VerificationService

verifier = VerificationService()
verdict = verifier.verify(r"C:\Windows\System32\kernel32.dll")
print(verdict.summary())
```

用证书签署自己的文件：

```python
# needs: certificate (PFX file), target executable file
from nylib.winutils.sign import (
    SigningService, VerificationService, CertificateLoader, SignRequest,
    HashAlgorithmType, TimestampKind,
)

signer = SigningService(CertificateLoader())
result = signer.sign(SignRequest(
    file_path=r"C:\path\to\app.exe",
    pfx_path=r"C:\path\to\cert.pfx",
    password="secret",
    hash_algorithm=HashAlgorithmType.SHA256,
    timestamp_url="http://timestamp.digicert.com",
    timestamp_kind=TimestampKind.RFC3161,
))
print(result.summary())
```

<!-- dt:section id="sign-a-pe-executable-0" hash="cfc94dec68e8" -->
## Sign a PE executable

使用文件将签署证书包装在 `SignRequest` 中，然后在服务上调用 `sign()`。结果对象包含成功状态、消息和证书元数据：

```python
# needs: certificate (PFX file), target PE file
from nylib.winutils.sign import (
    SigningService, CertificateLoader, SignRequest, HashAlgorithmType,
)

signer = SigningService(CertificateLoader())
result = signer.sign(SignRequest(
    file_path=r"C:\target\myapp.exe",
    pfx_path=r"C:\certs\mycert.pfx",
    password=None,  # omit for unprotected PFX
    hash_algorithm=HashAlgorithmType.SHA256,
))
if result.success:
    print(f"Signed with cert: {result.certificate_subject}")
else:
    print(f"Failed: {result.message} (HRESULT: {hex(result.hresult)})")
```

<!-- dt:section id="sign-a-driver-with-cross-certificate-chain-0" hash="a39663d446c3" -->
## Sign a driver with cross-certificate chain

设置 `driver_mode=True` 以组装并嵌入跨证书链（内核模式签署所需）。捆绑的 Microsoft 跨证书存储库 (`MSCVStore.p7b`) 自动使用并根据所需的根进行检查。通过 `additional_cert_paths` 传递自定义跨证书以首先搜索它们，或设置 `use_bundled_cross_certs=False` 仅依赖自定义路径：

```python
# needs: driver certificate (PFX file), target driver file (.sys)
from nylib.winutils.sign import SigningService, CertificateLoader, SignRequest

signer = SigningService(CertificateLoader())
result = signer.sign(SignRequest(
    file_path=r"C:\drivers\mydriver.sys",
    pfx_path=r"C:\certs\driver_cert.pfx",
    password="secret",
    driver_mode=True,
    required_chain_root="Microsoft Code Verification Root",
))
print(result.summary())
```

<!-- dt:section id="verify-a-signature-0" hash="8fc6702031d8" -->
## Verify a signature

使用文件路径调用 `verify()`。结果包括签名状态、证书主题和指纹，以及链式验证失败的状态代码：

```python
from nylib.winutils.sign import VerificationService

verifier = VerificationService()
# Verifying an already-signed system file (read-only, no admin needed).
verdict = verifier.verify(r"C:\Windows\System32\kernel32.dll")
if verdict.success:
    print(f"Valid signature: {verdict.certificate_subject}")
else:
    print(f"Invalid: {verdict.message} (Status: {hex(verdict.status_code)})")
```

<!-- dt:section id="timestamping-0" hash="a62656ff15a6" -->
## Timestamping

包含时间戳以允许在证书过期后验证签名。`TimestampKind.RFC3161`（现代）适用于大多数云 TSA；`TimestampKind.AUTHENTICODE` 是过时的：

```python
# needs: certificate, network connection, writable target file
from nylib.winutils.sign import (
    SigningService, CertificateLoader, SignRequest, TimestampKind,
)

signer = SigningService(CertificateLoader())
result = signer.sign(SignRequest(
    file_path=r"C:\path\to\app.exe",
    pfx_path=r"C:\path\to\cert.pfx",
    password="secret",
    timestamp_url="http://timestamp.digicert.com",
    timestamp_kind=TimestampKind.RFC3161,
))
```

<!-- dt:section id="expired-or-test-certificates-0" hash="cbc29b49176a" -->
## Expired or test certificates

超出有效期的签署证书通常会失败，出现 `0x800B0101` (CERT_E_EXPIRED)。默认情况下，`auto_bypass_expired_cert=True` 将签署包装在进程内时间有效性绕过中，使证书在签署时看起来有效；如果需要自己包装调用，请禁用它：

```python
# needs: expired certificate (PFX file), target file
import datetime
from nylib.winutils.sign import SigningService, CertificateLoader, SignRequest, bypass

# Manual bypass for a specific date (opt out of auto_bypass_expired_cert).
with bypass.BypassTsCheck(datetime.datetime(2014, 4, 1)):
    result = SigningService(CertificateLoader()).sign(SignRequest(
        file_path=r"C:\path\to\app.exe",
        pfx_path=r"C:\path\to\expired_cert.pfx",
        password="secret",
        auto_bypass_expired_cert=False,
    ))
```

<!-- dt:section id="notes-0" hash="91b329fecc26" -->
## Notes

- **Windows-only.** 需要 `crypt32.dll`、`mssign32.dll`、`wintrust.dll`（始终存在于 Windows 上）。
- **不需要 `signtool.exe`。** 使用 ctypes 绑定直接调用 Win32 API。
- **PFX 必须包含私钥。** 如果证书没有可访问的私钥，从 PFX 加载将失败。
- **时间戳需要网络和 URL 可达性。** 如果时间戳失败，整个签署操作将失败（设置 `timestamp_kind=TimestampKind.NONE` 跳过时间戳）。
- **使用跨证书的驱动程序签署需要小心的根验证。** 如果链没有到达 `required_chain_root`，签署将失败并包含详细错误；设置 `required_chain_root=None` 以嵌入链而不强制执行根。
- **不要在同一调用中混合 `auto_bypass_expired_cert` 和手动 `BypassTsCheck`。** 在使用 `BypassTsCheck` 包装之前设置 `auto_bypass_expired_cert=False`。
