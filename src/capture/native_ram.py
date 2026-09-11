from __future__ import annotations

import ctypes
import ctypes.wintypes as wintypes
import os
import platform
from dataclasses import dataclass
from typing import Any

from src.config.settings import JIT_WHITELIST, MEMORY_RULES


@dataclass
class MemoryFinding:
    pid: int
    process_name: str
    base_address: int
    region_size: int
    protection: int
    allocation_type: int
    rule: str
    risk_score: int
    details: dict[str, Any]


class NativeLiveRAMAnalyzer:
    MEM_COMMIT = 0x1000
    MEM_PRIVATE = 0x20000
    PAGE_EXECUTE = 0x10
    PAGE_EXECUTE_READ = 0x20
    PAGE_EXECUTE_READWRITE = 0x40
    PAGE_EXECUTE_WRITECOPY = 0x80
    PAGE_GUARD = 0x100
    PROCESS_QUERY_INFORMATION = 0x0400
    PROCESS_VM_READ = 0x0010
    TH32CS_SNAPPROCESS = 0x00000002
    INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

    class PROCESSENTRY32W(ctypes.Structure):
        _fields_ = [
            ("dwSize", wintypes.DWORD), ("cntUsage", wintypes.DWORD),
            ("th32ProcessID", wintypes.DWORD), ("th32DefaultHeapID", ctypes.c_size_t),
            ("th32ModuleID", wintypes.DWORD), ("cntThreads", wintypes.DWORD),
            ("th32ParentProcessID", wintypes.DWORD), ("pcPriClassBase", wintypes.LONG),
            ("dwFlags", wintypes.DWORD), ("szExeFile", wintypes.WCHAR * 260)
        ]

    class MEMORY_BASIC_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("BaseAddress", wintypes.LPVOID),
            ("AllocationBase", wintypes.LPVOID),
            ("AllocationProtect", wintypes.DWORD),
            ("RegionSize", ctypes.c_size_t),
            ("State", wintypes.DWORD),
            ("Protect", wintypes.DWORD),
            ("Type", wintypes.DWORD),
        ]

    def __init__(self) -> None:
        if platform.system() != "Windows":
            raise OSError("NativeLiveRAMAnalyzer is supported only on Windows.")
        self.kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self._configure_api()

    def _configure_api(self) -> None:
        self.kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
        self.kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
        self.kernel32.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(self.PROCESSENTRY32W)]
        self.kernel32.Process32FirstW.restype = wintypes.BOOL
        self.kernel32.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(self.PROCESSENTRY32W)]
        self.kernel32.Process32NextW.restype = wintypes.BOOL
        self.kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        self.kernel32.OpenProcess.restype = wintypes.HANDLE
        self.kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        self.kernel32.CloseHandle.restype = wintypes.BOOL
        self.kernel32.VirtualQueryEx.argtypes = [wintypes.HANDLE, wintypes.LPCVOID, ctypes.POINTER(self.MEMORY_BASIC_INFORMATION), ctypes.c_size_t]
        self.kernel32.VirtualQueryEx.restype = ctypes.c_size_t

    def _processes(self):
        snapshot = self.kernel32.CreateToolhelp32Snapshot(self.TH32CS_SNAPPROCESS, 0)
        if not snapshot or snapshot == self.INVALID_HANDLE_VALUE:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            entry = self.PROCESSENTRY32W()
            entry.dwSize = ctypes.sizeof(entry)
            ok = self.kernel32.Process32FirstW(snapshot, ctypes.byref(entry))
            while ok:
                yield entry.th32ProcessID, entry.th32ParentProcessID, entry.szExeFile
                ok = self.kernel32.Process32NextW(snapshot, ctypes.byref(entry))
        finally:
            self.kernel32.CloseHandle(snapshot)

    @staticmethod
    def _is_executable(protect: int) -> bool:
        return protect in {
            NativeLiveRAMAnalyzer.PAGE_EXECUTE,
            NativeLiveRAMAnalyzer.PAGE_EXECUTE_READ,
            NativeLiveRAMAnalyzer.PAGE_EXECUTE_READWRITE,
            NativeLiveRAMAnalyzer.PAGE_EXECUTE_WRITECOPY,
        }

    def scan(self) -> list[MemoryFinding]:
        findings: list[MemoryFinding] = []
        for pid, _ppid, name in self._processes():
            handle = self.kernel32.OpenProcess(
                self.PROCESS_QUERY_INFORMATION | self.PROCESS_VM_READ, False, pid
            )
            if not handle:
                continue
            try:
                addr = 0
                while addr < (1 << 47):
                    mbi = self.MEMORY_BASIC_INFORMATION()
                    result = self.kernel32.VirtualQueryEx(
                        handle, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)
                    )
                    if not result or mbi.RegionSize == 0:
                        break
                    protect = int(mbi.Protect)
                    region_size = int(mbi.RegionSize)
                    is_private = int(mbi.Type) == self.MEM_PRIVATE
                    rule = None
                    if int(mbi.State) == self.MEM_COMMIT:
                        if protect & self.PAGE_GUARD and self._is_executable(protect & 0xFF):
                            rule = "RWX_GUARD_STAGED_PAYLOAD"
                        elif (protect & 0xFF) == self.PAGE_EXECUTE_READWRITE:
                            rule = "RWX_SHELLCODE_INJECTION"
                        elif (protect & 0xFF) == self.PAGE_EXECUTE_WRITECOPY:
                            rule = "RWX_WRITECOPY_SUSPICIOUS"
                        elif is_private and region_size >= 1024 * 1024 and (protect & 0xFF) in {
                            self.PAGE_EXECUTE, self.PAGE_EXECUTE_READ
                        }:
                            rule = "LARGE_PRIVATE_EXECUTABLE"
                    if rule:
                        risk = MEMORY_RULES[rule]
                        if name.lower() in JIT_WHITELIST:
                            risk = max(10, risk - 30)
                        findings.append(MemoryFinding(
                            pid=int(pid), process_name=name,
                            base_address=int(ctypes.cast(mbi.BaseAddress, ctypes.c_void_p).value or 0),
                            region_size=region_size, protection=protect,
                            allocation_type=int(mbi.Type), rule=rule,
                            risk_score=min(100, risk), details={"jit_whitelisted": name.lower() in JIT_WHITELIST}
                        ))
                    addr = int(ctypes.cast(mbi.BaseAddress, ctypes.c_void_p).value or addr) + region_size
            finally:
                self.kernel32.CloseHandle(handle)
        return findings
