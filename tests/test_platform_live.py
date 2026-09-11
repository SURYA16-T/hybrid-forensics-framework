from __future__ import annotations
import platform
import pytest

def test_current_platform_supported():
    assert platform.system() in {
        "Windows",
        "Linux",
        "Darwin",
    }

def test_platform_modules_import():
    from src.capture import (
        LinuxLiveAnalyzer,
        MacOSLiveAnalyzer,
        NativeLiveRAMAnalyzer,
    )

    assert LinuxLiveAnalyzer is not None
    assert MacOSLiveAnalyzer is not None
    assert NativeLiveRAMAnalyzer is not None

@pytest.mark.skipif(
    platform.system() != "Linux",
    reason="Linux live scanner test runs only on Linux",
)
def test_linux_live_scanner():
    from src.capture.linux_live import LinuxLiveAnalyzer

    analyzer = LinuxLiveAnalyzer()
    processes = analyzer.list_processes()

    assert isinstance(processes, list)
    assert len(processes) > 0

@pytest.mark.skipif(
    platform.system() != "Darwin",
    reason="macOS live scanner test runs only on macOS",
)
def test_macos_live_scanner():
    from src.capture.macos_live import MacOSLiveAnalyzer

    analyzer = MacOSLiveAnalyzer()
    processes = analyzer.list_processes()

    assert isinstance(processes, list)
    assert len(processes) > 0

@pytest.mark.skipif(
    platform.system() != "Windows",
    reason="Windows live scanner test runs only on Windows",
)
def test_windows_live_scanner():
    from src.capture.native_ram import NativeLiveRAMAnalyzer

    analyzer = NativeLiveRAMAnalyzer()
    processes = list(analyzer._processes())

    assert isinstance(processes, list)
    assert len(processes) > 0