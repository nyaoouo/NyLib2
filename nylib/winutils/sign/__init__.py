r"""Authenticode code-signing and signature verification for Windows.

A thin, dependency-free wrapper over the Win32 signing surface (``mssign32!SignerSign`` /
``SignerTimeStamp`` and ``wintrust!WinVerifyTrust``, driven through ``crypt32`` with ctypes --
see :mod:`.native`). It needs no ``signtool.exe`` on the machine and adds two things signtool
does not give you directly:

* **Driver (kernel-mode) signing** -- assembles and embeds the cross-certificate chain the way
  ``signtool sign /ac`` does, and refuses to sign unless that chain reaches a required root. A
  full Microsoft cross-cert bundle (``MSCVStore.p7b``, 29 CAs) ships with the package and is used
  automatically, so no ``/ac`` file is required.
* **Automatic expired-certificate handling** -- if the signing certificate is outside its
  validity window (typical for test / expired code-signing certs) ``SignerSign`` would normally
  fail with ``0x800B0101`` (``CERT_E_EXPIRED``). When ``SignRequest.auto_bypass_expired_cert`` is
  set (the default) signing is transparently wrapped in an in-process time-validity bypass (see
  :mod:`.bypass`), so callers no longer need to wrap their calls in ``bypass.BypassTsCheck``.

Quick start
-----------
Sign a file with a PFX, then verify it::

    from nylib.winutils.sign import (
        SigningService, VerificationService, CertificateLoader, SignRequest,
        HashAlgorithmType, TimestampKind,
    )

    signer = SigningService(CertificateLoader())
    result = signer.sign(SignRequest(
        file_path=r"C:\\path\\to\\app.exe",
        pfx_path=r"C:\\path\\to\\cert.pfx",
        password="secret",                        # or None for an unprotected PFX
        hash_algorithm=HashAlgorithmType.SHA256,
        timestamp_url="http://timestamp.digicert.com",
        timestamp_kind=TimestampKind.RFC3161,     # TimestampKind.NONE to skip timestamping
    ))
    print(result.summary())
    if not result.success:
        raise SystemExit(result.hresult)

    verdict = VerificationService().verify(r"C:\\path\\to\\app.exe")
    print(verdict.summary())

Use :meth:`SigningService.sign_many` / :meth:`VerificationService.verify_many` for batches.

Driver / kernel-mode signing
----------------------------
Set ``driver_mode=True``; the bundled cross-cert store is embedded automatically and the
assembled chain is checked against ``required_chain_root`` (default
``"Microsoft Code Verification Root"``)::

    result = signer.sign(SignRequest(
        file_path=r"C:\\path\\to\\driver.sys",
        pfx_path=r"C:\\path\\to\\cert.pfx",
        password="secret",
        driver_mode=True,
        # additional_cert_paths=(r"C:\\extra\\crosscert.cer",),  # extra /ac sources, searched first
        # use_bundled_cross_certs=False,                         # rely only on additional_cert_paths
        # required_chain_root=None,                              # embed the chain, enforce no root
    ))

Expired / test certificates
----------------------------
Out-of-validity signing certs are handled transparently by default. Opt out with
``auto_bypass_expired_cert=False`` -- then signing fails on an expired cert, or you can drive the
bypass yourself with an explicit date::

    import datetime
    from nylib.winutils.sign import SigningService, CertificateLoader, SignRequest, bypass

    with bypass.BypassTsCheck(datetime.datetime(2014, 4, 1)):
        SigningService(CertificateLoader()).sign(SignRequest(..., auto_bypass_expired_cert=False))

Notes
-----
* Windows-only; requires ``crypt32`` / ``mssign32`` / ``wintrust``.
* Native failures raise ``OSError`` (``ctypes.WinError``); the high-level ``sign`` / ``verify``
  methods catch them and report through :class:`SignResult` / :class:`VerifyResult` instead.
* ``auto_bypass_expired_cert`` installs process-wide API hooks for the duration of the
  ``SignerSign`` call; do not combine it with a manual :class:`bypass.BypassTsCheck` around the
  same call (set the flag to ``False`` if you wrap it yourself).
"""
import ctypes
import datetime
import contextlib
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Iterable
from ctypes import wintypes
from . import native, bypass

# Cross-certificate bundle shipped with this package: a PKCS#7 of the 29 Microsoft cross-certs
# (VeriSign/Symantec, DigiCert, GlobalSign, Comodo/AddTrust, Entrust, GeoTrust, Go Daddy, thawte,
# ...), each chaining its CA up to "Microsoft Code Verification Root". This is the same set
# CSignTool keeps in its embedded "MSCVStore" resource. Used automatically in driver mode so the
# caller does not have to supply a /ac file. Resolved relative to __file__ so it works both from
# source and inside a PyInstaller bundle (see nylib/__pyinstaller/hook-nylib.winutils.sign.py).
BUNDLED_CROSS_CERT_STORE = Path(__file__).resolve().parent / "MSCVStore.p7b"


def bundled_cross_cert_store_path() -> str | None:
    """Absolute path to the bundled cross-cert store, or None if it is not present."""
    return str(BUNDLED_CROSS_CERT_STORE) if BUNDLED_CROSS_CERT_STORE.is_file() else None


def to_hresult(value: int) -> int:
    return ctypes.c_uint32(value).value


def format_hresult(value: int) -> str:
    return f"0x{to_hresult(value):08X}"


class HashAlgorithmType(str, Enum):
    SHA1 = "sha1"
    SHA256 = "sha256"
    SHA384 = "sha384"
    SHA512 = "sha512"

    def to_alg_id(self) -> int:
        if self == HashAlgorithmType.SHA1:
            return native.CALG_SHA1
        elif self == HashAlgorithmType.SHA256:
            return native.CALG_SHA256
        elif self == HashAlgorithmType.SHA384:
            return native.CALG_SHA384
        return native.CALG_SHA512


class TimestampKind(str, Enum):
    NONE = "none"
    AUTHENTICODE = "authenticode"
    RFC3161 = "rfc3161"


@dataclass(frozen=True)
class SignRequest:
    file_path: str
    pfx_path: str
    password: str | None = None
    timestamp_url: str | None = None
    hash_algorithm: HashAlgorithmType = HashAlgorithmType.SHA256
    timestamp_kind: TimestampKind = TimestampKind.NONE

    # --- Driver (kernel-mode) signing options ---
    driver_mode: bool = False
    additional_cert_paths: tuple[str, ...] = ()
    use_bundled_cross_certs: bool = True
    required_chain_root: str | None = "Microsoft Code Verification Root"

    # When the signing certificate is outside its validity window (NotBefore..NotAfter),
    # automatically wrap signing in an in-process time-validity bypass (see bypass.BypassTsCheck)
    # so SignerSign does not fail with 0x800B0101 (CERT_E_EXPIRED). Set False to opt out: signing
    # then fails on an expired cert, or you can wrap BypassTsCheck yourself with an explicit date.
    auto_bypass_expired_cert: bool = True


@dataclass(frozen=True)
class SignResult:
    file_path: str
    success: bool
    message: str
    certificate_subject: str | None
    certificate_thumbprint: str | None
    timestamp_applied: bool
    hresult: int = 0

    def summary(self) -> str:
        if self.success:
            line = f"SUCCESS: {self.file_path} - {self.message}"
        else:
            line = f"FAILURE: {self.file_path} - {self.message} (HRESULT: {format_hresult(self.hresult)})"
        if self.certificate_subject and self.certificate_thumbprint:
            line += f" [Subject: {self.certificate_subject}, Thumbprint: {self.certificate_thumbprint}]"
        return line


@dataclass(frozen=True)
class VerifyResult:
    file_path: str
    success: bool
    message: str
    status_code: int
    certificate_subject: str | None
    certificate_thumbprint: str | None

    def summary(self) -> str:
        if self.success:
            line = f"VERIFIED: {self.file_path} - {self.message}"
        else:
            line = f"NOT VERIFIED: {self.file_path} - {self.message} (Status Code: {format_hresult(self.status_code)})"
        if self.certificate_subject and self.certificate_thumbprint:
            line += f" [Subject: {self.certificate_subject}, Thumbprint: {self.certificate_thumbprint}]"
        return line


class LoadedCertificateSet:

    def __init__(self, store_handle: int, signing_certificate_context: int):
        self.store_handle = store_handle
        self.signing_certificate_context = signing_certificate_context
        self.extra_stores: list[int] = []

    def close(self) -> None:
        for handle in self.extra_stores:
            if handle:
                native.CertCloseStore(handle, 0, _ignore_error=True)
        self.extra_stores = []
        if self.signing_certificate_context:
            native.CertFreeCertificateContext(self.signing_certificate_context, _ignore_error=True)
            self.signing_certificate_context = 0
        if self.store_handle:
            native.CertCloseStore(self.store_handle, 0, _ignore_error=True)
            self.store_handle = 0

    def __enter__(self) -> "LoadedCertificateSet":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()


class CertificateLoader:
    def load_from_pfx(self, pfx_path: str, password: str | None) -> LoadedCertificateSet:
        pfx_file = Path(pfx_path)
        if not pfx_path:
            raise ValueError("A PFX path is required.")
        if not pfx_file.exists():
            raise FileNotFoundError(f"The specified PFX file was not found: {pfx_path}")

        pfx_bytes = pfx_file.read_bytes()
        byte_buffer = (ctypes.c_ubyte * len(pfx_bytes)).from_buffer_copy(pfx_bytes)
        blob = native.CryptDataBlob(len(pfx_bytes), byte_buffer)
        store_handle = native.PFXImportCertStore(ctypes.byref(blob), password, native.CRYPT_EXPORTABLE)
        previous = ctypes.c_void_p()
        chosen_context = 0
        try:
            while True:
                current = native.CertEnumCertificatesInStore(store_handle, previous.value)
                if not current:
                    break
                previous = ctypes.c_void_p(current)
                if self._has_private_key(current):
                    chosen_context = native.CertDuplicateCertificateContext(current)
                    break
        finally:
            if previous.value:
                native.CertFreeCertificateContext(previous.value, _ignore_error=True)

        if not chosen_context:
            native.CertCloseStore(store_handle, 0, _ignore_error=True)
            raise RuntimeError(f"The certificate loaded from '{pfx_path}' does not include an accessible private key.")

        return LoadedCertificateSet(store_handle, chosen_context)

    @staticmethod
    def _has_private_key(cert_context: int) -> bool:
        handle = ctypes.c_void_p()
        key_spec = wintypes.DWORD()
        caller_free = wintypes.BOOL()
        success = native.CryptAcquireCertificatePrivateKey(
            cert_context,
            native.CRYPT_ACQUIRE_SILENT_FLAG | native.CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG,
            None,
            ctypes.byref(handle),
            ctypes.byref(key_spec),
            ctypes.byref(caller_free),
            _ignore_error=True,
        )
        if not success:
            ctypes.set_last_error(0)
            success = native.CryptAcquireCertificatePrivateKey(
                cert_context,
                native.CRYPT_ACQUIRE_SILENT_FLAG,
                None,
                ctypes.byref(handle),
                ctypes.byref(key_spec),
                ctypes.byref(caller_free),
                _ignore_error=True,
            )
        if not success:
            return False
        if caller_free.value and handle.value:
            if key_spec.value == native.CERT_NCRYPT_KEY_SPEC:
                native.ncrypt.NCryptFreeObject(handle)
            else:
                native.advapi32.CryptReleaseContext(handle, 0)
        return True


class SigningService:
    def __init__(self, certificate_loader: CertificateLoader):
        self._certificate_loader = certificate_loader

    def sign_many(self, requests: Iterable[SignRequest]) -> list[SignResult]:
        return [self.sign(request) for request in requests]

    def sign(self, request: SignRequest) -> SignResult:
        file_path = Path(request.file_path)
        if not request.file_path or not file_path.exists():
            return SignResult(request.file_path, False, "The target file was not found.", None, None, False)

        try:
            with self._certificate_loader.load_from_pfx(request.pfx_path, request.password) as certificate_set:
                signing_store = certificate_set.store_handle
                if request.driver_mode:
                    cross_cert_paths = list(request.additional_cert_paths)
                    if request.use_bundled_cross_certs:
                        bundled = bundled_cross_cert_store_path()
                        if bundled:
                            cross_cert_paths.append(bundled)
                    cross_stores = []
                    for cert_path in cross_cert_paths:
                        handle = open_cert_file_store(cert_path)
                        certificate_set.extra_stores.append(handle)
                        cross_stores.append(handle)
                    driver_store = native.CertOpenStore(
                        native.CERT_STORE_PROV_MEMORY,
                        native.X509_ASN_ENCODING | native.PKCS_7_ASN_ENCODING,
                        None,
                        0,
                        None,
                    )
                    certificate_set.extra_stores.append(driver_store)
                    source_stores = cross_stores + [certificate_set.store_handle]
                    reaches_root, actual_root = assemble_chain_into_store(
                        certificate_set.signing_certificate_context,
                        driver_store,
                        source_stores,
                        request.required_chain_root,
                    )
                    if not reaches_root:
                        return SignResult(
                            request.file_path,
                            False,
                            "This certificate can not be used for driving signature! "
                            f'(chain root is "{actual_root}", expected "{request.required_chain_root}")',
                            None,
                            None,
                            False,
                        )
                    signing_store = driver_store
                else:
                    for cert_path in request.additional_cert_paths:
                        add_certs_from_file_to_store(certificate_set.store_handle, cert_path)

                absolute_path = str(file_path.resolve())
                file_info = native.SignerFileInfo(ctypes.sizeof(native.SignerFileInfo), absolute_path, None)
                subject_index = wintypes.DWORD(0)
                subject_info = native.SignerSubjectInfo(
                    ctypes.sizeof(native.SignerSubjectInfo),
                    ctypes.cast(ctypes.pointer(subject_index), ctypes.c_void_p),
                    native.SIGNER_SUBJECT_FILE,
                    ctypes.addressof(file_info),
                )
                cert_store_info = native.SignerCertStoreInfo(
                    ctypes.sizeof(native.SignerCertStoreInfo),
                    certificate_set.signing_certificate_context,
                    native.SIGNER_CERT_POLICY_STORE,
                    signing_store,
                )
                signer_cert = native.SignerCert(
                    ctypes.sizeof(native.SignerCert),
                    native.SIGNER_CERT_STORE,
                    ctypes.addressof(cert_store_info),
                    None,
                )
                signature_info = native.SignerSignatureInfo(
                    ctypes.sizeof(native.SignerSignatureInfo),
                    request.hash_algorithm.to_alg_id(),
                    0,
                    None,
                    None,
                    None,
                )
                timestamp_url = request.timestamp_url if request.timestamp_kind != TimestampKind.NONE else None
                # An out-of-validity signing cert makes SignerSign's internal CertVerifyTimeValidity
                # fail with 0x800B0101 (CERT_E_EXPIRED). When auto_bypass_expired_cert is set, wrap
                # signing + timestamping in an in-process time-validity bypass so the caller does not
                # have to (see bypass.BypassTsCheck); otherwise this is a no-op context.
                ts_bypass = self._build_validity_bypass(request, certificate_set.signing_certificate_context)
                with (ts_bypass or contextlib.nullcontext()):
                    sign_hr = native.SignerSign(
                        ctypes.byref(subject_info),
                        ctypes.byref(signer_cert),
                        ctypes.byref(signature_info),
                        None,
                        timestamp_url,
                        None,
                        None,
                    )
                    if sign_hr != 0:
                        return SignResult(
                            request.file_path,
                            False,
                            f"SignerSign failed with {format_hresult(sign_hr)}.",
                            None,
                            None,
                            False,
                            to_hresult(sign_hr),
                        )
                    timestamp_applied = False
                    if timestamp_url and request.timestamp_kind != TimestampKind.NONE:
                        if request.timestamp_kind == TimestampKind.AUTHENTICODE:
                            ts_hr = native.SignerTimeStamp(ctypes.byref(subject_info), timestamp_url, None, None)
                        else:
                            ts_hr = native.SignerTimeStampEx2(
                                native.SIGNER_TIMESTAMP_RFC3161,
                                ctypes.byref(subject_info),
                                timestamp_url,
                                request.hash_algorithm.to_alg_id(),
                                None,
                                None,
                                None,
                            )
                        if ts_hr != 0:
                            return SignResult(
                                request.file_path,
                                False,
                                f"Timestamping failed with {format_hresult(ts_hr)}.",
                                None,
                                None,
                                False,
                                to_hresult(ts_hr),
                            )
                        timestamp_applied = True

                certificate_subject = None
                certificate_thumbprint = None
                try:
                    certificate_subject = get_certificate_subject(certificate_set.signing_certificate_context)
                    certificate_thumbprint = get_certificate_thumbprint(certificate_set.signing_certificate_context)
                except Exception:
                    pass
                message = "File signed and timestamped." if timestamp_applied else "File signed successfully."
                if ts_bypass is not None:
                    message += " (certificate time-validity auto-bypassed)"
                return SignResult(request.file_path, True, message, certificate_subject, certificate_thumbprint, timestamp_applied)
        except Exception as exc:
            return SignResult(request.file_path, False, str(exc), None, None, False)

    @staticmethod
    def _build_validity_bypass(request: SignRequest, cert_context: int) -> "bypass.BypassTsCheck | None":
        """Return a BypassTsCheck to wrap signing in iff the cert is outside its validity window
        and auto_bypass_expired_cert is enabled; otherwise None (sign without any hooks).

        The bypass is fed a date at the midpoint of [NotBefore, NotAfter] -- safely inside the
        window -- so SignerSign's CertVerifyTimeValidity (and the embedded signing time) see a
        valid moment regardless of the real clock.
        """
        if not request.auto_bypass_expired_cert:
            return None
        validity = get_certificate_validity(cert_context)
        if validity is None:
            return None
        not_before, not_after = validity
        now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
        if not_before <= now <= not_after:
            return None
        midpoint = not_before + (not_after - not_before) / 2
        return bypass.BypassTsCheck(midpoint)


class VerificationService:
    LOCAL_ACCEPTABLE_STATUS = 0x800B0109

    def verify_many(self, file_paths: Iterable[str]) -> list[VerifyResult]:
        return [self.verify(file_path) for file_path in file_paths]

    def verify(self, file_path: str) -> VerifyResult:
        target = Path(file_path)
        if not file_path or not target.exists():
            return VerifyResult(file_path, False, "The target file was not found.", 0x80070002, None, None)

        absolute_path = str(target.resolve())
        file_info = native.WinTrustFileInfo(ctypes.sizeof(native.WinTrustFileInfo), absolute_path, None, None)
        data = native.WinTrustData(
            ctypes.sizeof(native.WinTrustData),
            None,
            None,
            native.WTD_UI_NONE,
            native.WTD_REVOKE_NONE,
            native.WTD_CHOICE_FILE,
            ctypes.addressof(file_info),
            native.WTD_STATEACTION_IGNORE,
            None,
            None,
            0,
            native.WTD_UICONTEXT_EXECUTE,
            None,
        )

        try:
            status = native.WinVerifyTrust(None, ctypes.byref(native.WINTRUST_ACTION_GENERIC_VERIFY_V2), ctypes.byref(data))
            subject, thumbprint = try_get_signer_details(absolute_path)
            if status == 0:
                return VerifyResult(file_path, True, "Signature verification succeeded.", 0, subject, thumbprint)
            if to_hresult(status) == self.LOCAL_ACCEPTABLE_STATUS and subject:
                return VerifyResult(file_path, True, "Signature is present; certificate chain is untrusted on this machine.", to_hresult(status), subject, thumbprint)
            return VerifyResult(file_path, False, f"WinVerifyTrust returned {format_hresult(status)}.", to_hresult(status), subject, thumbprint)
        except Exception as exc:
            return VerifyResult(file_path, False, str(exc), 0, None, None)


def get_certificate_subject(cert_context: int) -> str | None:
    if not cert_context:
        return None
    # _ignore_error=True: this is an optional metadata lookup -- degrade to None instead of
    # raising if the name cannot be read (CertGetNameStringW returns 0 only on error).
    required = native.CertGetNameStringW(cert_context, native.CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, None, None, 0, _ignore_error=True)
    if not required:
        return None
    buffer = ctypes.create_unicode_buffer(required)
    if not native.CertGetNameStringW(cert_context, native.CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, None, buffer, required, _ignore_error=True):
        return None
    return buffer.value or None


def get_certificate_thumbprint(cert_context: int) -> str | None:
    if not cert_context:
        return None
    size = wintypes.DWORD(0)
    # _ignore_error=True: optional lookup -- return None rather than raise if the hash property
    # is unavailable.
    if not native.CertGetCertificateContextProperty(cert_context, native.CERT_HASH_PROP_ID, None, ctypes.byref(size), _ignore_error=True):
        return None
    buffer = (ctypes.c_ubyte * size.value)()
    if not native.CertGetCertificateContextProperty(cert_context, native.CERT_HASH_PROP_ID, ctypes.byref(buffer), ctypes.byref(size), _ignore_error=True):
        return None
    return "".join(f"{byte:02X}" for byte in buffer[: size.value])


def get_certificate_issuer(cert_context: int) -> str | None:
    if not cert_context:
        return None
    flags = native.CERT_NAME_ISSUER_FLAG
    # _ignore_error=True: optional lookup -- return None rather than raise on failure.
    required = native.CertGetNameStringW(cert_context, native.CERT_NAME_SIMPLE_DISPLAY_TYPE, flags, None, None, 0, _ignore_error=True)
    if not required:
        return None
    buffer = ctypes.create_unicode_buffer(required)
    if not native.CertGetNameStringW(cert_context, native.CERT_NAME_SIMPLE_DISPLAY_TYPE, flags, None, buffer, required, _ignore_error=True):
        return None
    return buffer.value or None


# FILETIME counts 100-nanosecond intervals since this epoch, in UTC.
_FILETIME_EPOCH = datetime.datetime(1601, 1, 1)


def _filetime_to_datetime(file_time: wintypes.FILETIME) -> datetime.datetime:
    ticks = (file_time.dwHighDateTime << 32) | file_time.dwLowDateTime
    return _FILETIME_EPOCH + datetime.timedelta(microseconds=ticks // 10)


def get_certificate_validity(cert_context: int) -> tuple[datetime.datetime, datetime.datetime] | None:
    """Return the certificate's ``(not_before, not_after)`` as naive UTC datetimes.

    Returns None if the context is null or the validity cannot be read/represented (e.g. a
    "never expires" NotAfter that overflows ``datetime``) -- callers treat None as "do not
    bypass", which is correct because such a certificate is not time-expired.
    """
    if not cert_context:
        return None
    try:
        cert_info = ctypes.cast(cert_context, ctypes.POINTER(native.CertContext)).contents.pCertInfo.contents
        return _filetime_to_datetime(cert_info.NotBefore), _filetime_to_datetime(cert_info.NotAfter)
    except (ValueError, OSError, OverflowError):
        return None


def add_certs_from_file_to_store(store_handle: int, cert_path: str) -> int:
    path = Path(cert_path)
    if not cert_path or not path.exists():
        raise FileNotFoundError(f"Additional certificate file was not found: {cert_path}")

    encoding = wintypes.DWORD()
    content = wintypes.DWORD()
    fmt = wintypes.DWORD()
    source_store = ctypes.c_void_p()
    if not native.CryptQueryObject(
        native.CERT_QUERY_OBJECT_FILE,
        ctypes.c_wchar_p(str(path.resolve())),
        native.CERT_QUERY_CONTENT_FLAG_ALL,
        native.CERT_QUERY_FORMAT_FLAG_ALL,
        0,
        ctypes.byref(encoding),
        ctypes.byref(content),
        ctypes.byref(fmt),
        ctypes.byref(source_store),
        None,
        None,
        _ignore_error=True,
    ):
        raise RuntimeError(f"Could not read any certificate from '{cert_path}'.")

    added = 0
    previous = ctypes.c_void_p()
    try:
        while True:
            current = native.CertEnumCertificatesInStore(source_store.value, previous.value)
            if not current:
                break
            previous = ctypes.c_void_p(current)
            # ADD_USE_EXISTING keeps the store de-duplicated; copies the context in.
            if native.CertAddCertificateContextToStore(
                store_handle, current, native.CERT_STORE_ADD_USE_EXISTING, None, _ignore_error=True
            ):
                added += 1
    finally:
        if source_store.value:
            native.CertCloseStore(source_store.value, 0, _ignore_error=True)
    return added


def open_cert_file_store(cert_path: str) -> int:
    path = Path(cert_path)
    if not cert_path or not path.exists():
        raise FileNotFoundError(f"Additional certificate file was not found: {cert_path}")
    encoding = wintypes.DWORD()
    content = wintypes.DWORD()
    fmt = wintypes.DWORD()
    store = ctypes.c_void_p()
    if not native.CryptQueryObject(
        native.CERT_QUERY_OBJECT_FILE,
        ctypes.c_wchar_p(str(path.resolve())),
        native.CERT_QUERY_CONTENT_FLAG_ALL,
        native.CERT_QUERY_FORMAT_FLAG_ALL,
        0,
        ctypes.byref(encoding),
        ctypes.byref(content),
        ctypes.byref(fmt),
        ctypes.byref(store),
        None,
        None,
        _ignore_error=True,
    ):
        raise RuntimeError(f"Could not read any certificate from '{cert_path}'.")
    return store.value or 0


def _find_issuer_in_stores(child_context: int, source_stores: list[int]) -> int:
    info = ctypes.cast(child_context, ctypes.POINTER(native.CertContext)).contents.pCertInfo
    issuer_blob = info.contents.Issuer
    for store in source_stores:
        if not store:
            continue
        found = native.CertFindCertificateInStore(
            store,
            native.X509_ASN_ENCODING | native.PKCS_7_ASN_ENCODING,
            0,
            native.CERT_FIND_SUBJECT_NAME,
            ctypes.byref(issuer_blob),
            None,
            _ignore_error=True,
        )
        if found:
            return found
    return 0


def assemble_chain_into_store(signing_cert: int, dest_store: int, source_stores: list[int],
                              required_root: str | None) -> tuple[bool, str | None]:
    current = signing_cert
    current_owned = False
    seen: set[str] = set()
    root_name: str | None = None
    try:
        while True:
            subject = get_certificate_subject(current)
            issuer = get_certificate_issuer(current)
            thumbprint = get_certificate_thumbprint(current)
            if thumbprint and thumbprint in seen:
                root_name = subject  # loop guard (cross-cert cycles)
                break
            if thumbprint:
                seen.add(thumbprint)
            if not issuer or subject == issuer:
                root_name = subject  # reached a self-signed certificate
                break
            issuer_context = _find_issuer_in_stores(current, source_stores)
            if not issuer_context:
                root_name = issuer  # top of the chain we can assemble
                break
            issuer_subject = get_certificate_subject(issuer_context)
            issuer_issuer = get_certificate_issuer(issuer_context)
            if issuer_subject and issuer_subject == issuer_issuer:
                # Reached the self-signed root: record it but do not embed it.
                root_name = issuer_subject
                native.CertFreeCertificateContext(issuer_context, _ignore_error=True)
                break
            native.CertAddCertificateContextToStore(
                dest_store, issuer_context, native.CERT_STORE_ADD_USE_EXISTING, None, _ignore_error=True
            )
            if current_owned:
                native.CertFreeCertificateContext(current, _ignore_error=True)
            current = issuer_context
            current_owned = True
    finally:
        if current_owned:
            native.CertFreeCertificateContext(current, _ignore_error=True)

    ok = required_root is None or root_name == required_root
    return ok, root_name


def try_get_signer_details(file_path: str) -> tuple[str | None, str | None]:
    encoding = wintypes.DWORD()
    content = wintypes.DWORD()
    fmt = wintypes.DWORD()
    cert_store = ctypes.c_void_p()
    crypt_msg = ctypes.c_void_p()

    # _ignore_error=True: an unsigned/unreadable file simply has no signer details -- return
    # (None, None) so verify() can still report the WinVerifyTrust status, instead of raising.
    success = native.CryptQueryObject(
        native.CERT_QUERY_OBJECT_FILE,
        ctypes.c_wchar_p(file_path),
        native.CERT_QUERY_CONTENT_FLAG_ALL,
        native.CERT_QUERY_FORMAT_FLAG_ALL,
        0,
        ctypes.byref(encoding),
        ctypes.byref(content),
        ctypes.byref(fmt),
        ctypes.byref(cert_store),
        ctypes.byref(crypt_msg),
        None,
        _ignore_error=True,
    )
    if not success:
        return (None, None)

    resolved_cert = ctypes.c_void_p()
    previous = ctypes.c_void_p()
    try:
        cert_context = resolve_signer_certificate(cert_store.value or 0, crypt_msg.value or 0)
        if cert_context:
            resolved_cert = ctypes.c_void_p(cert_context)
            return (get_certificate_subject(cert_context), get_certificate_thumbprint(cert_context))

        cert_context = native.CertEnumCertificatesInStore(cert_store.value, previous.value)
        if not cert_context:
            return (None, None)
        previous = ctypes.c_void_p(cert_context)
        return (get_certificate_subject(cert_context), get_certificate_thumbprint(cert_context))
    finally:
        if resolved_cert.value:
            native.CertFreeCertificateContext(resolved_cert.value)
        if previous.value:
            native.CertFreeCertificateContext(previous.value)
        if crypt_msg.value:
            native.CryptMsgClose(crypt_msg.value)
        if cert_store.value:
            native.CertCloseStore(cert_store.value, 0)


def resolve_signer_certificate(cert_store: int, crypt_msg: int) -> int:
    if not cert_store or not crypt_msg:
        return 0

    signer_store = (ctypes.c_void_p * 1)(cert_store)
    signer_context = ctypes.c_void_p()
    signer_index = wintypes.DWORD()
    # _ignore_error=True: a failed verify is expected here -- fall through to manual signer
    # extraction from CMSG_SIGNER_INFO_PARAM rather than raising.
    if native.CryptMsgGetAndVerifySigner(
        crypt_msg,
        1,
        signer_store,
        0,
        ctypes.byref(signer_context),
        ctypes.byref(signer_index),
        _ignore_error=True,
    ):
        return signer_context.value or 0

    # _ignore_error=True: missing signer info -> return 0 (no signer) instead of raising.
    size = wintypes.DWORD(0)
    if not native.CryptMsgGetParam(crypt_msg, native.CMSG_SIGNER_INFO_PARAM, 0, None, ctypes.byref(size), _ignore_error=True):
        return 0

    buffer = (ctypes.c_ubyte * size.value)()
    if not native.CryptMsgGetParam(crypt_msg, native.CMSG_SIGNER_INFO_PARAM, 0, ctypes.byref(buffer), ctypes.byref(size), _ignore_error=True):
        return 0

    signer_info = ctypes.cast(buffer, ctypes.POINTER(native.CmsgSignerInfo)).contents
    cert_id = native.CertId()
    cert_id.dwIdChoice = native.CERT_ID_ISSUER_SERIAL_NUMBER
    cert_id.Value.IssuerSerialNumber = native.CertIssuerSerialNumber(signer_info.Issuer, signer_info.SerialNumber)

    # _ignore_error=True: not-found returns NULL (0) here rather than raising.
    return native.CertFindCertificateInStore(
        cert_store,
        native.X509_ASN_ENCODING | native.PKCS_7_ASN_ENCODING,
        0,
        native.CERT_FIND_SUBJECT_CERT,
        ctypes.byref(cert_id),
        None,
        _ignore_error=True,
    ) or 0
