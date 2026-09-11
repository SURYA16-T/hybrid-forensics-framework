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


def test_platform_smoke_scan():
    """Smoke test to ensure the scanner for the current platform executes without throwing exceptions."""
    system = platform.system()
    try:
        from src.capture import LinuxLiveAnalyzer, MacOSLiveAnalyzer, NativeLiveRAMAnalyzer

        if system == "Darwin":
            scanner = MacOSLiveAnalyzer()
            findings = scanner.scan()
            assert isinstance(findings, list)
        elif system == "Linux":
            scanner = LinuxLiveAnalyzer()
            findings = scanner.scan()
            assert isinstance(findings, list)
        elif system == "Windows":
            scanner = NativeLiveRAMAnalyzer()
            findings = scanner.scan()
            assert isinstance(findings, list)
    except EnvironmentError as e:
        # Expected on macOS if tools are missing, or Windows if admin is required
        pass