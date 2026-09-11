# Platform implementation guide

## Windows

Live analysis uses Python `ctypes` to call Win32 process and virtual-memory APIs. The optional MiniDump module uses `dbghelp.dll`. Protected processes may deny access. A MiniDump is a process dump, not the same thing as a complete physical-RAM image.

## macOS

Live analysis uses built-in `ps` for process enumeration and `vmmap` for virtual-memory-region inspection. These are appropriate for host-side triage and do not constitute full physical-RAM acquisition. macOS security controls can restrict access to protected processes. Apple documents Mach virtual-memory APIs, but using those directly from a portable Python project would require a substantially different native extension and still would not make physical-RAM acquisition equivalent to a traditional forensic RAM image. citeturn739850search7

## Linux

Live analysis uses `/proc` process information and `/proc/<pid>/maps` for virtual-memory mappings. Physical RAM acquisition is intentionally outside the portable framework; the expected workflow is to acquire a forensic memory image with a dedicated acquisition method and then analyze it with Volatility 3.

## Cross-platform design

```text
                    main.py
                       |
             +---------+---------+
             |         |         |
          Windows    macOS     Linux
             |         |         |
          Win32      ps/vmmap   /proc
             |         |         |
             +---------+---------+
                       |
                 common finding
                   structures
                       |
                timeline + score
                       |
                 JSON / HTML
```

## Important accuracy statement

The framework is cross-platform for the analysis workflow and live virtual-memory triage. It is **not** a claim of identical physical-RAM acquisition capability on all three operating systems. Forensic acquisition is platform-specific.
