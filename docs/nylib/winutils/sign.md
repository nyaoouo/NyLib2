# nylib.winutils.sign

Sign PE files with Authenticode certificates and verify signatures, with built-in driver (kernel-mode) signing and automatic handling of expired test certificates.

Keywords: SigningService, VerificationService, CertificateLoader, SignRequest, sign, verify, Authenticode, driver signing, cross-cert, certificate, PFX, hash algorithm, timestamping, expired cert, bypass, MSCVStore

## Quick start

Verify a signature on a system binary (no certificate needed):

```python
from nylib.winutils.sign import VerificationService

verifier = VerificationService()
verdict = verifier.verify(r"C:\Windows\System32\kernel32.dll")
print(verdict.summary())
```

To sign your own file with a certificate:

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

## Sign a PE executable

Wrap the signing certificate in a `SignRequest` with the file to sign, then call `sign()` on the service. The result object holds success status, messages, and certificate metadata:

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

## Sign a driver with cross-certificate chain

Set `driver_mode=True` to assemble and embed the cross-certificate chain (required for kernel-mode signing). The bundled Microsoft cross-cert store (`MSCVStore.p7b`) is used automatically and checked against the required root. Pass `additional_cert_paths` with custom cross-certificates to search them first, or set `use_bundled_cross_certs=False` to rely only on custom paths:

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

## Verify a signature

Call `verify()` with the file path. The result includes signature status, certificate subject and thumbprint, and a status code for chained verification failures:

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

## Timestamping

Include a timestamp to allow signature verification after the certificate expires. `TimestampKind.RFC3161` (modern) works with most cloud TSAs; `TimestampKind.AUTHENTICODE` is legacy:

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

## Expired or test certificates

Out-of-validity signing certificates normally fail with `0x800B0101` (CERT_E_EXPIRED). By default, `auto_bypass_expired_cert=True` wraps signing in an in-process time-validity bypass so the certificate appears valid at signing time; disable it if you need to wrap the call yourself:

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

## Notes

- **Windows-only.** Requires `crypt32.dll`, `mssign32.dll`, `wintrust.dll` (always present on Windows).
- **No `signtool.exe` needed.** Uses ctypes bindings directly to the Win32 APIs.
- **PFX must include a private key.** Loading from a PFX fails if the certificate has no accessible private key.
- **Timestamping requires network and URL reachability.** If timestamping fails, the entire signing operation fails (set `timestamp_kind=TimestampKind.NONE` to skip timestamping).
- **Driver signing with cross-certs requires careful root verification.** If the chain does not reach `required_chain_root`, signing fails with a detailed error; set `required_chain_root=None` to embed the chain without enforcing a root.
- **Do not mix `auto_bypass_expired_cert` and manual `BypassTsCheck` on the same call.** Set `auto_bypass_expired_cert=False` before wrapping with `BypassTsCheck`.
