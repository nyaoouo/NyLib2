import ctypes
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Iterable
from ctypes import wintypes
from . import native


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

    def close(self) -> None:
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
            native.CertCloseStore(store_handle, 0)
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
                    native.SIGNER_CERT_POLICY_STORE | native.SIGNER_CERT_POLICY_CHAIN_NO_ROOT,
                    certificate_set.store_handle,
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
                    # Keep signing success even if certificate metadata cannot be read.
                    pass
                message = "File signed and timestamped." if timestamp_applied else "File signed successfully."
                return SignResult(request.file_path, True, message, certificate_subject, certificate_thumbprint, timestamp_applied)
        except Exception as exc:
            return SignResult(request.file_path, False, str(exc), None, None, False)


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
    required = native.CertGetNameStringW(cert_context, native.CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, None, None, 0)
    if not required:
        return None
    buffer = ctypes.create_unicode_buffer(required)
    if not native.CertGetNameStringW(cert_context, native.CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, None, buffer, required):
        return None
    return buffer.value or None


def get_certificate_thumbprint(cert_context: int) -> str | None:
    if not cert_context:
        return None
    size = wintypes.DWORD(0)
    if not native.CertGetCertificateContextProperty(cert_context, native.CERT_HASH_PROP_ID, None, ctypes.byref(size)):
        return None
    buffer = (ctypes.c_ubyte * size.value)()
    if not native.CertGetCertificateContextProperty(cert_context, native.CERT_HASH_PROP_ID, ctypes.byref(buffer), ctypes.byref(size)):
        return None
    return "".join(f"{byte:02X}" for byte in buffer[: size.value])


def try_get_signer_details(file_path: str) -> tuple[str | None, str | None]:
    encoding = wintypes.DWORD()
    content = wintypes.DWORD()
    fmt = wintypes.DWORD()
    cert_store = ctypes.c_void_p()
    crypt_msg = ctypes.c_void_p()

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
    if native.CryptMsgGetAndVerifySigner(
        crypt_msg,
        1,
        signer_store,
        0,
        ctypes.byref(signer_context),
        ctypes.byref(signer_index),
    ):
        return signer_context.value or 0

    size = wintypes.DWORD(0)
    if not native.CryptMsgGetParam(crypt_msg, native.CMSG_SIGNER_INFO_PARAM, 0, None, ctypes.byref(size)):
        return 0

    buffer = (ctypes.c_ubyte * size.value)()
    if not native.CryptMsgGetParam(crypt_msg, native.CMSG_SIGNER_INFO_PARAM, 0, ctypes.byref(buffer), ctypes.byref(size)):
        return 0

    signer_info = ctypes.cast(buffer, ctypes.POINTER(native.CmsgSignerInfo)).contents
    cert_id = native.CertId()
    cert_id.dwIdChoice = native.CERT_ID_ISSUER_SERIAL_NUMBER
    cert_id.Value.IssuerSerialNumber = native.CertIssuerSerialNumber(signer_info.Issuer, signer_info.SerialNumber)

    return native.CertFindCertificateInStore(
        cert_store,
        native.X509_ASN_ENCODING | native.PKCS_7_ASN_ENCODING,
        0,
        native.CERT_FIND_SUBJECT_CERT,
        ctypes.byref(cert_id),
        None,
    )
