"""Recover VMware encrypted-VM passwords from the Windows Credential Manager.

VMware Workstation's "remember password" stores the VM *encryption* password in
the Windows Credential Manager as a GENERIC credential whose target name is the
VM's ``encryptedVM.guid`` (from the .vmx). It is not retrievable through the UI,
but the Win32 ``CredReadW`` API returns it. The credential blob is UTF-8.

Technique reference: gist andshrew/bf6e5e8fa09b957caffc09c6dee58472.

The Win32 calls go through nylib's unified ``nylib.winapi`` bindings
(``def_win_api`` + ``CREDENTIAL``). Those are imported lazily inside the
Windows-guarded functions so this module stays importable on any platform.
"""
from __future__ import annotations

import ctypes
import os

from nylib.vmware_wp.errors import CredentialNotFoundError


def read_credential_password(target: str) -> str:
    """Return the password blob of GENERIC credential ``target`` (UTF-8 decoded).

    Raises CredentialNotFoundError on non-Windows or if the credential is absent.
    """
    if os.name != "nt":
        raise CredentialNotFoundError("Windows Credential Manager is only available on Windows")
    from nylib.winapi.advapi32 import CRED_TYPE_GENERIC, CredFree, CredReadW
    from nylib.winapi.defs import CREDENTIAL

    ptr = ctypes.POINTER(CREDENTIAL)()
    try:
        CredReadW(target, CRED_TYPE_GENERIC, 0, ctypes.byref(ptr))
    except OSError as exc:  # def_win_api raises WinError(GetLastError()) on failure
        raise CredentialNotFoundError(f"CredReadW failed for {target!r}: {exc}") from exc
    try:
        cred = ptr.contents
        raw = ctypes.string_at(cred.CredentialBlob, cred.CredentialBlobSize)
    finally:
        CredFree(ptr)
    return raw.decode("utf-8", errors="replace")


def read_vmx_guid(vmx_path) -> str | None:
    """Return the ``encryptedVM.guid`` value from a .vmx file, or None."""
    try:
        with open(vmx_path, "r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                if line.strip().startswith("encryptedVM.guid"):
                    return line.split("=", 1)[1].strip().strip('"')
    except OSError:
        return None
    return None


def read_encrypted_vm_password(vmx_path) -> str | None:
    """Best-effort: resolve a .vmx's encryption password via its GUID + CredReadW.

    Returns None (never raises) when off-Windows, the VM is not encrypted, or no
    matching credential is stored — so callers can fall back to other inputs.
    """
    if os.name != "nt":
        return None
    guid = read_vmx_guid(vmx_path)
    if not guid:
        return None
    try:
        return read_credential_password(guid)
    except CredentialNotFoundError:
        return None


def require_encrypted_vm_password(vmx_path) -> str:
    """Like read_encrypted_vm_password but raises CredentialNotFoundError if absent."""
    guid = read_vmx_guid(vmx_path)
    if not guid:
        raise CredentialNotFoundError(f"no encryptedVM.guid in {vmx_path!r}")
    return read_credential_password(guid)
