import platform


def test_current_platform_supported():
    assert platform.system() in {
        "Linux",
        "Darwin",
        "Windows",
    }


def test_import_platform_modules():
    from src.capture import (
        LinuxLiveAnalyzer,
        MacOSLiveAnalyzer,
        NativeLiveRAMAnalyzer,
    )

    assert LinuxLiveAnalyzer is not None
    assert MacOSLiveAnalyzer is not None
    assert NativeLiveRAMAnalyzer is not None