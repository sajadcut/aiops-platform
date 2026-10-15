"""Fail-closed native Windows ACL check for encrypted worker candidate storage.

No pywin32 dependency: query NTFS DACL using the Windows security API.
Any broad allow ACE, unknown ACE layout, missing DACL or API failure blocks
storing and reading sensitive complete-file repair candidates.
"""
from __future__ import annotations

import os


def _worker_sid() -> str:
    """Obtain the actual worker token SID without pywin32 or guessing user names."""
    import ctypes
    from ctypes import wintypes

    class SID_AND_ATTRIBUTES(ctypes.Structure):
        _fields_ = [("Sid", ctypes.c_void_p), ("Attributes", wintypes.DWORD)]

    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.CloseHandle.restype = wintypes.BOOL
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    kernel.LocalFree.restype = ctypes.c_void_p
    advapi.OpenProcessToken.argtypes = [
        wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE),
    ]
    advapi.OpenProcessToken.restype = wintypes.BOOL
    advapi.GetTokenInformation.argtypes = [
        wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    advapi.GetTokenInformation.restype = wintypes.BOOL
    advapi.ConvertSidToStringSidW.argtypes = [
        ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p),
    ]
    advapi.ConvertSidToStringSidW.restype = wintypes.BOOL

    token = wintypes.HANDLE()
    if not advapi.OpenProcessToken(kernel.GetCurrentProcess(), 0x0008,
                                  ctypes.byref(token)):
        raise PermissionError("candidate_windows_acl_unverifiable")
    try:
        length = wintypes.DWORD()
        advapi.GetTokenInformation(token, 1, None, 0, ctypes.byref(length))
        if not 16 <= length.value <= 65536:
            raise PermissionError("candidate_windows_acl_unverifiable")
        buffer = ctypes.create_string_buffer(length.value)
        if not advapi.GetTokenInformation(token, 1, buffer, length,
                                         ctypes.byref(length)):
            raise PermissionError("candidate_windows_acl_unverifiable")
        sid = ctypes.cast(
            buffer, ctypes.POINTER(SID_AND_ATTRIBUTES)).contents.Sid
        output = ctypes.c_void_p()
        if not sid or not advapi.ConvertSidToStringSidW(
                sid, ctypes.byref(output)):
            raise PermissionError("candidate_windows_acl_unverifiable")
        try:
            return ctypes.wstring_at(output)
        finally:
            kernel.LocalFree(output)
    finally:
        kernel.CloseHandle(token)


def harden_private_windows_acl(path: str) -> None:
    """Protect only the dedicated candidate directory from inherited broad ACEs.

    No shell, icacls, PowerShell, pywin32, new secret or runtime setting.
    Replace the DACL with full control for SYSTEM, local Administrators and
    the *actual* worker SID, with inheritance disabled. The caller MUST
    verify the resulting ACL and never write a candidate if this fails.
    """
    if os.name != "nt":
        return
    import ctypes
    from ctypes import wintypes

    user_sid = _worker_sid()
    # SID comes only from the kernel token. The string never comes from
    # an incident, model, config path, or HTTP request.
    sddl = f"D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;{user_sid})"
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    convert = advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW
    convert.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(wintypes.DWORD),
    ]
    convert.restype = wintypes.BOOL
    dacl_from_descriptor = advapi.GetSecurityDescriptorDacl
    dacl_from_descriptor.argtypes = [
        ctypes.c_void_p, ctypes.POINTER(wintypes.BOOL),
        ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(wintypes.BOOL),
    ]
    dacl_from_descriptor.restype = wintypes.BOOL
    set_info = advapi.SetNamedSecurityInfoW
    set_info.argtypes = [
        wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD,
        ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
    ]
    set_info.restype = wintypes.DWORD
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    kernel.LocalFree.restype = ctypes.c_void_p
    descriptor = ctypes.c_void_p()
    if not convert(sddl, 1, ctypes.byref(descriptor), None):
        raise PermissionError("candidate_windows_acl_hardening_failed")
    try:
        present, defaulted = wintypes.BOOL(), wintypes.BOOL()
        dacl = ctypes.c_void_p()
        if not dacl_from_descriptor(
                descriptor, ctypes.byref(present), ctypes.byref(dacl),
                ctypes.byref(defaulted)) or not present.value or not dacl.value:
            raise PermissionError("candidate_windows_acl_hardening_failed")
        # DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION;
        # Windows will not propagate inherited Users/Everyone grants into
        # newly created sealed files under the protected directory.
        rc = set_info(path, 1, 0x00000004 | 0x80000000,
                      None, None, dacl, None)
        if rc:
            raise PermissionError("candidate_windows_acl_hardening_failed")
    finally:
        kernel.LocalFree(descriptor)


def ensure_private_windows_acl(path: str) -> None:
    if os.name != "nt":
        return
    import ctypes
    from ctypes import wintypes

    class ACL(ctypes.Structure):
        _fields_ = [
            ("AclRevision", ctypes.c_ubyte),
            ("Sbz1", ctypes.c_ubyte),
            ("AclSize", wintypes.WORD),
            ("AceCount", wintypes.WORD),
            ("Sbz2", wintypes.WORD),
        ]

    class ACE_HEADER(ctypes.Structure):
        _fields_ = [
            ("AceType", ctypes.c_ubyte),
            ("AceFlags", ctypes.c_ubyte),
            ("AceSize", wintypes.WORD),
        ]

    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    get_info = advapi.GetNamedSecurityInfoW
    get_info.argtypes = [
        wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
    ]
    get_info.restype = wintypes.DWORD
    get_ace = advapi.GetAce
    get_ace.argtypes = [ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p)]
    get_ace.restype = wintypes.BOOL
    sid_to_string = advapi.ConvertSidToStringSidW
    sid_to_string.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
    sid_to_string.restype = wintypes.BOOL
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    kernel.LocalFree.restype = ctypes.c_void_p

    class SID_AND_ATTRIBUTES(ctypes.Structure):
        _fields_ = [("Sid", ctypes.c_void_p), ("Attributes", wintypes.DWORD)]

    token = wintypes.HANDLE()
    advapi.OpenProcessToken.argtypes = [
        wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE),
    ]
    advapi.OpenProcessToken.restype = wintypes.BOOL
    advapi.GetTokenInformation.argtypes = [
        wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    advapi.GetTokenInformation.restype = wintypes.BOOL
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.CloseHandle.restype = wintypes.BOOL
    if not advapi.OpenProcessToken(kernel.GetCurrentProcess(), 0x0008,
                                  ctypes.byref(token)):
        raise PermissionError("candidate_windows_acl_unverifiable")
    try:
        length = wintypes.DWORD()
        advapi.GetTokenInformation(token, 1, None, 0, ctypes.byref(length))
        if not 16 <= length.value <= 65536:
            raise PermissionError("candidate_windows_acl_unverifiable")
        buff = ctypes.create_string_buffer(length.value)
        if not advapi.GetTokenInformation(token, 1, buff, length,
                                         ctypes.byref(length)):
            raise PermissionError("candidate_windows_acl_unverifiable")
        current_sid = ctypes.cast(
            buff, ctypes.POINTER(SID_AND_ATTRIBUTES)).contents.Sid
        sid_out = ctypes.c_void_p()
        if not current_sid or not sid_to_string(current_sid, ctypes.byref(sid_out)):
            raise PermissionError("candidate_windows_acl_unverifiable")
        try:
            user_sid = ctypes.wstring_at(sid_out)
        finally:
            kernel.LocalFree(sid_out)
    finally:
        kernel.CloseHandle(token)

    dacl, descriptor = ctypes.c_void_p(), ctypes.c_void_p()
    rc = get_info(path, 1, 4, None, None, ctypes.byref(dacl), None,
                  ctypes.byref(descriptor))
    if rc != 0 or not dacl.value:
        if descriptor.value:
            kernel.LocalFree(descriptor)
        raise PermissionError("candidate_windows_acl_unverifiable")
    allowed = {
        user_sid,           # worker service account
        "S-1-5-18",         # Local SYSTEM
        "S-1-5-32-544",     # Builtin Administrators
        "S-1-3-0",          # Creator Owner
    }
    try:
        count = ctypes.cast(dacl, ctypes.POINTER(ACL)).contents.AceCount
        for index in range(count):
            ptr = ctypes.c_void_p()
            if not get_ace(dacl, index, ctypes.byref(ptr)) or not ptr.value:
                raise PermissionError("candidate_windows_acl_unverifiable")
            ace = ctypes.cast(ptr, ctypes.POINTER(ACE_HEADER)).contents
            # Simple allow and deny ACEs only. Object/conditional ACEs have
            # different SID offsets and could hide broad access; block them.
            if ace.AceType not in (0, 1):
                raise PermissionError("candidate_windows_acl_unverifiable")
            if ace.AceSize < 12:
                raise PermissionError("candidate_windows_acl_unverifiable")
            if ace.AceType == 1:  # explicit/inherited DENY
                continue
            sid_ptr = ctypes.c_void_p(ptr.value + 8)
            sid_string = ctypes.c_void_p()
            if not sid_to_string(sid_ptr, ctypes.byref(sid_string)):
                raise PermissionError("candidate_windows_acl_unverifiable")
            try:
                sid = ctypes.wstring_at(sid_string)
            finally:
                kernel.LocalFree(sid_string)
            if sid not in allowed:
                raise PermissionError("candidate_windows_acl_too_broad")
    finally:
        kernel.LocalFree(descriptor)
