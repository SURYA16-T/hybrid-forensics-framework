# Hybrid Memory & Disk Forensics Framework

A local, modular digital-forensics framework that combines evidence intake, disk artifact inspection, offline memory analysis through Volatility 3, platform-specific live process/virtual-memory heuristics, timeline correlation, rule-based threat scoring, and offline JSON/HTML reporting.

## Platforms

### Windows

- Native live process + virtual-memory inspection through Win32 APIs (`ctypes`).
- Suspicious memory-region heuristics.
- Optional process MiniDump acquisition through `dbghelp.dll`.
- WinPMEM may be used separately for physical-memory acquisition; the resulting memory image can then be
  analyzed with Volatility 3.

### macOS

- Live process enumeration using the built-in `ps` command.
- Per-process virtual-memory inspection using the built-in `vmmap` command.
- Suspicious executable-region heuristics.
- Works on Intel and Apple-silicon Macs as far as the host tools permit.
- Does **not** claim physical-RAM acquisition; macOS permissions, SIP and protected-process restrictions can limit access. For forensic memory images, use Volatility 3.

### Linux

- Live process enumeration from `/proc`.
- Per-process virtual-memory-map inspection using `/proc/<pid>/maps`.
- Suspicious executable-region heuristics.
- Physical RAM acquisition is intentionally not implemented by this project; use a dedicated Linux acquisition method/tool and then analyze the image with Volatility 3.

The framework itself does not need network access.

## Full flow

```text
Evidence
   |
   +--> Intake -> MD5/SHA-256
   |
   +--> Disk -> SYSTEM / Prefetch / filesystem metadata
   |
   +--> Memory image -> Volatility 3 -> process records
   |
   +--> Live platform scanner
           |-- Windows -> Win32 API
           |-- macOS   -> ps + vmmap
           `-- Linux   -> /proc + /proc/<pid>/maps
   |
   +--> Timeline Builder
   |
   +--> Threat Scorer (transparent heuristics)
   |
   `--> JSON + HTML report
```

## Setup

### Linux/macOS

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pytest -q
```

Run the live platform scanner:

```bash
chmod +x run_macos.sh
./run_macos.sh       # macOS
python -m src.main --scan-live   # Linux or macOS
```

### Windows PowerShell (Administrator recommended for live scanning)

```powershell
py -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
pytest -q
python -m src.main --scan-live
```

## Offline memory analysis

Install Volatility 3 locally and make its launcher available as `vol` (or pass `--volatility`):

```bash
python -m src.main --image /path/to/memdump.raw --type memory
```

## Disk analysis

The disk parser operates on a mounted or already extracted filesystem tree:

```bash
python -m src.main --image /path/to/evidence.img --type disk --disk-root /mnt/evidence
```

## Hybrid analysis

```bash
python -m src.main --image /path/to/memdump.raw --type hybrid --disk-root /mnt/evidence
```

## Current artifact coverage

- Windows SYSTEM Registry hive discovery and metadata collection.
- Windows Prefetch `.pf` discovery and executable-name extraction.
- Filesystem timestamps and sizes.

## Correlation

Disk artifacts and memory observations are normalized into one `CorrelatedEvent` model and sorted chronologically. The current implementation is deliberately transparent: it does not claim advanced PID/path/hash/time-window entity matching.

## Threat heuristics

Windows checks include:

- `PAGE_EXECUTE_READWRITE`
- `PAGE_EXECUTE_WRITECOPY`
- guarded executable regions
- large private executable regions

Linux/macOS checks include suspicious executable/RWX virtual-memory regions. The threat scorer also considers suspicious executable names and path indicators.

Scores are triage heuristics, **not proof of malware**.

## macOS limitation to state in a presentation

The macOS module performs **live process and virtual-memory-map triage**, not a complete physical-RAM acquisition. This is intentional. A complete physical-memory workflow on macOS requires platform-specific acquisition mechanisms and permissions beyond a portable Python script.

## Safety / forensic note

Work on copies where possible and preserve originals and cryptographic hashes. Live process inspection can require elevated privileges and may be restricted by operating-system security controls.
