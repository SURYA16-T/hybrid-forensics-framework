from __future__ import annotations

import ctypes
import ctypes.wintypes as wintypes
import platform
import subprocess
from pathlib import Path


class LiveRAMCapturer:
    """Creates Windows process MiniDumps for selected PIDs using dbghelp.dll."""

    MiniDumpWithFullMemory = 0x00000002
    PROCESS_QUERY_INFORMATION = 0x0400
    PROCESS_VM_READ = 0x0010

    def __init__(self) -> None:
        if platform.system() != "Windows":
            raise OSError("Live RAM capture is supported only on Windows.")
        self.kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self.dbghelp = ctypes.WinDLL("dbghelp", use_last_error=True)
        self.kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        self.kernel32.OpenProcess.restype = wintypes.HANDLE
        self.kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        self.kernel32.CloseHandle.restype = wintypes.BOOL
        self.kernel32.CreateFileW.argtypes = [
            wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
            wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE
        ]
        self.kernel32.CreateFileW.restype = wintypes.HANDLE
        self.dbghelp.MiniDumpWriteDump.argtypes = [
            wintypes.HANDLE, wintypes.DWORD, wintypes.HANDLE,
            wintypes.DWORD, wintypes.LPVOID, wintypes.LPVOID, wintypes.LPVOID
        ]
        self.dbghelp.MiniDumpWriteDump.restype = wintypes.BOOL
        self.INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

    def dump_process(self, pid: int, output_path: str) -> str:
        out = Path(output_path).expanduser().resolve()
        out.parent.mkdir(parents=True, exist_ok=True)
        process = self.kernel32.OpenProcess(
            self.PROCESS_QUERY_INFORMATION | self.PROCESS_VM_READ, False, int(pid)
        )
        if not process:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            kernel32 = self.kernel32
            GENERIC_WRITE = 0x40000000
            CREATE_ALWAYS = 2
            file_handle = kernel32.CreateFileW(
                str(out), GENERIC_WRITE, 0, None, CREATE_ALWAYS, 0, None
            )
            if not file_handle or file_handle == self.INVALID_HANDLE_VALUE:
                raise ctypes.WinError(ctypes.get_last_error())
            try:
                ok = self.dbghelp.MiniDumpWriteDump(
                    process, int(pid), file_handle,
                    self.MiniDumpWithFullMemory, None, None, None
                )
                if not ok:
                    raise ctypes.WinError(ctypes.get_last_error())
            finally:
                kernel32.CloseHandle(file_handle)
        finally:
            self.kernel32.CloseHandle(process)
        return str(out)
