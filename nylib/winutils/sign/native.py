import ctypes
from ctypes import wintypes
from ...winapi.utils import def_win_api


class GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", wintypes.DWORD),
        ("Data2", wintypes.WORD),
        ("Data3", wintypes.WORD),
        ("Data4", ctypes.c_ubyte * 8),
    ]


class SignerFileInfo(ctypes.Structure):
    _fields_ = [
        ("cbSize", wintypes.DWORD),
        ("pwszFileName", wintypes.LPWSTR),
        ("hFile", wintypes.HANDLE),
    ]


class SignerSubjectInfo(ctypes.Structure):
    _fields_ = [
        ("cbSize", wintypes.DWORD),
        ("pdwIndex", ctypes.c_void_p),
        ("dwSubjectChoice", wintypes.DWORD),
        ("pSignerFileInfo", ctypes.c_void_p),
    ]


class SignerCertStoreInfo(ctypes.Structure):
    _fields_ = [
        ("cbSize", wintypes.DWORD),
        ("pSigningCert", ctypes.c_void_p),
        ("dwCertPolicy", wintypes.DWORD),
        ("hCertStore", ctypes.c_void_p),
    ]


class SignerCert(ctypes.Structure):
    _fields_ = [
        ("cbSize", wintypes.DWORD),
        ("dwCertChoice", wintypes.DWORD),
        ("pCertStoreInfo", ctypes.c_void_p),
        ("hwnd", wintypes.HWND),
    ]


class SignerSignatureInfo(ctypes.Structure):
    _fields_ = [
        ("cbSize", wintypes.DWORD),
        ("algidHash", wintypes.DWORD),
        ("dwAttrChoice", wintypes.DWORD),
        ("pAttrAuthcode", ctypes.c_void_p),
        ("psAuthenticated", ctypes.c_void_p),
        ("psUnauthenticated", ctypes.c_void_p),
    ]


class SignerAttrAuthcode(ctypes.Structure):
    _fields_ = [
        ("cbSize", wintypes.DWORD),
        ("fCommercial", wintypes.BOOL),
        ("fIndividual", wintypes.BOOL),
        ("pwszName", wintypes.LPWSTR),
        ("pwszInfo", wintypes.LPWSTR),
    ]


class CryptDataBlob(ctypes.Structure):
    _fields_ = [
        ("cbData", wintypes.DWORD),
        ("pbData", ctypes.POINTER(ctypes.c_ubyte)),
    ]


class CertNameBlob(CryptDataBlob):
    pass


class CryptIntegerBlob(CryptDataBlob):
    pass


class CmsgSignerInfo(ctypes.Structure):
    _fields_ = [
        ("dwVersion", wintypes.DWORD),
        ("Issuer", CertNameBlob),
        ("SerialNumber", CryptIntegerBlob),
    ]


class CertIssuerSerialNumber(ctypes.Structure):
    _fields_ = [
        ("Issuer", CertNameBlob),
        ("SerialNumber", CryptIntegerBlob),
    ]


class CertIdUnion(ctypes.Union):
    _fields_ = [("IssuerSerialNumber", CertIssuerSerialNumber)]


class CertId(ctypes.Structure):
    _fields_ = [
        ("dwIdChoice", wintypes.DWORD),
        ("Value", CertIdUnion),
    ]


class WinTrustFileInfo(ctypes.Structure):
    _fields_ = [
        ("cbStruct", wintypes.DWORD),
        ("pcwszFilePath", wintypes.LPWSTR),
        ("hFile", wintypes.HANDLE),
        ("pgKnownSubject", ctypes.c_void_p),
    ]


class WinTrustData(ctypes.Structure):
    _fields_ = [
        ("cbStruct", wintypes.DWORD),
        ("pPolicyCallbackData", ctypes.c_void_p),
        ("pSIPClientData", ctypes.c_void_p),
        ("dwUIChoice", wintypes.DWORD),
        ("fdwRevocationChecks", wintypes.DWORD),
        ("dwUnionChoice", wintypes.DWORD),
        ("pFile", ctypes.c_void_p),
        ("dwStateAction", wintypes.DWORD),
        ("hWVTStateData", ctypes.c_void_p),
        ("pwszURLReference", wintypes.LPWSTR),
        ("dwProvFlags", wintypes.DWORD),
        ("dwUIContext", wintypes.DWORD),
        ("pSignatureSettings", ctypes.c_void_p),
    ]


SIGNER_SUBJECT_FILE = 0x1
SIGNER_CERT_STORE = 0x2
SIGNER_CERT_POLICY_STORE = 0x1
SIGNER_CERT_POLICY_CHAIN_NO_ROOT = 0x8
SIGNER_AUTHCODE_ATTR = 0x1
SIGNER_TIMESTAMP_AUTHENTICODE = 0x1
SIGNER_TIMESTAMP_RFC3161 = 0x2

CALG_SHA1 = 0x00008004
CALG_SHA256 = 0x0000800C
CALG_SHA384 = 0x0000800D
CALG_SHA512 = 0x0000800E

CRYPT_EXPORTABLE = 0x00000001
CRYPT_ACQUIRE_SILENT_FLAG = 0x00000040
CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG = 0x00040000
CERT_NCRYPT_KEY_SPEC = 0xFFFFFFFF

WTD_UI_NONE = 0x2
WTD_REVOKE_NONE = 0x0
WTD_CHOICE_FILE = 0x1
WTD_STATEACTION_IGNORE = 0x0
WTD_UICONTEXT_EXECUTE = 0x0

CERT_NAME_SIMPLE_DISPLAY_TYPE = 4
CERT_HASH_PROP_ID = 3
CERT_QUERY_OBJECT_FILE = 1
CERT_QUERY_CONTENT_FLAG_ALL = 0x00003FFE
CERT_QUERY_FORMAT_FLAG_ALL = 0x0000000E
X509_ASN_ENCODING = 0x00000001
PKCS_7_ASN_ENCODING = 0x00010000
CMSG_SIGNER_INFO_PARAM = 6
CERT_ID_ISSUER_SERIAL_NUMBER = 1
CERT_FIND_SUBJECT_CERT = 0x000B0000

WINTRUST_ACTION_GENERIC_VERIFY_V2 = GUID(
    0x00AAC56B,
    0xCD44,
    0x11D0,
    (ctypes.c_ubyte * 8)(0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE),
)


crypt32 = ctypes.WinDLL("crypt32.dll", use_last_error=True)
mssign32 = ctypes.WinDLL("Mssign32.dll", use_last_error=True)
wintrust = ctypes.WinDLL("wintrust.dll", use_last_error=True)
advapi32 = ctypes.WinDLL("advapi32.dll", use_last_error=True)
ncrypt = ctypes.WinDLL("ncrypt.dll", use_last_error=True)

PFXImportCertStore = def_win_api(crypt32.PFXImportCertStore, ctypes.c_void_p, (ctypes.c_void_p, wintypes.LPCWSTR, wintypes.DWORD), error_zero=True)
CertEnumCertificatesInStore = def_win_api(crypt32.CertEnumCertificatesInStore, ctypes.c_void_p, (ctypes.c_void_p, ctypes.c_void_p))
CertDuplicateCertificateContext = def_win_api(crypt32.CertDuplicateCertificateContext, ctypes.c_void_p, (ctypes.c_void_p,), error_zero=True)
CertFreeCertificateContext = def_win_api(crypt32.CertFreeCertificateContext, wintypes.BOOL, (ctypes.c_void_p,), error_zero=True)
CertCloseStore = def_win_api(crypt32.CertCloseStore, wintypes.BOOL, (ctypes.c_void_p, wintypes.DWORD), error_zero=True)
CertGetNameStringW = def_win_api(crypt32.CertGetNameStringW, wintypes.DWORD, (ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p, wintypes.LPWSTR, wintypes.DWORD), error_zero=True)
CertGetCertificateContextProperty = def_win_api(crypt32.CertGetCertificateContextProperty, wintypes.BOOL, (ctypes.c_void_p, wintypes.DWORD, ctypes.c_void_p, ctypes.c_void_p), error_zero=True)
CryptAcquireCertificatePrivateKey = def_win_api(crypt32.CryptAcquireCertificatePrivateKey, wintypes.BOOL, (ctypes.c_void_p, wintypes.DWORD, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p), error_zero=True)
CryptQueryObject = def_win_api(crypt32.CryptQueryObject, wintypes.BOOL, (wintypes.DWORD, wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p), error_zero=True)
CryptMsgClose = def_win_api(crypt32.CryptMsgClose, wintypes.BOOL, (ctypes.c_void_p,), error_zero=True)
CryptMsgGetParam = def_win_api(crypt32.CryptMsgGetParam, wintypes.BOOL, (ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p, ctypes.c_void_p), error_zero=True)
CertFindCertificateInStore = def_win_api(crypt32.CertFindCertificateInStore, ctypes.c_void_p, (ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p, ctypes.c_void_p), error_zero=True)
CryptMsgGetAndVerifySigner = def_win_api(crypt32.CryptMsgGetAndVerifySigner, wintypes.BOOL, (ctypes.c_void_p, wintypes.DWORD, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p), error_zero=True)
SignerSign = def_win_api(mssign32.SignerSign, ctypes.c_long, (ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, wintypes.LPCWSTR, ctypes.c_void_p, ctypes.c_void_p))
SignerTimeStamp = def_win_api(mssign32.SignerTimeStamp, ctypes.c_long, (ctypes.c_void_p, wintypes.LPCWSTR, ctypes.c_void_p, ctypes.c_void_p))
SignerTimeStampEx2 = def_win_api(mssign32.SignerTimeStampEx2, ctypes.c_long, (wintypes.DWORD, ctypes.c_void_p, wintypes.LPCWSTR, wintypes.DWORD, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p))
WinVerifyTrust = def_win_api(wintrust.WinVerifyTrust, wintypes.LONG, (wintypes.HWND, ctypes.c_void_p, ctypes.c_void_p))
CryptReleaseContext = def_win_api(advapi32.CryptReleaseContext, wintypes.BOOL, (ctypes.c_void_p, wintypes.DWORD), error_zero=True)
NCryptFreeObject = def_win_api(ncrypt.NCryptFreeObject, wintypes.BOOL, (ctypes.c_void_p,), error_zero=True)
