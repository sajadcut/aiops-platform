"""Fail-closed native Windows ACL check for encrypted worker candidate storage.

No pywin32 dependency: query NTFS DACL using the Windows security API.
Any broad allow ACE, unknown ACE layout, missing DACL or API failure blocks
storing and reading sensitive complete-file repair candidates.
"""
from __future__ import annotations

import os


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

    dacl, descriptor = ctypes.c_void_p(), ctypes.c_void_p()
    rc = get_info(path, 1, 4, None, None, ctypes.byref(dacl), None,
                  ctypes.byref(descriptor))
    if rc != 0 or not dacl.value:
        if descriptor.value:
            kernel.LocalFree(descriptor)
        raise PermissionError("candidate_windows_acl_unverifiable")
    forbidden = {
        "S-1-1-0",     # Everyone
        "S-1-5-11",    # Authenticated Users
        "S-1-5-7",     # Anonymous
        "S-1-5-32-545",  # Builtin Users
        "S-1-5-32-546",  # Guests
        "S-1-5-2",     # Network logons
        "S-1-5-4",     # Interactive logons
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
            if sid in forbidden:
                raise PermissionError("candidate_windows_acl_too_broad")
    finally:
        kernel.LocalFree(descriptor)
