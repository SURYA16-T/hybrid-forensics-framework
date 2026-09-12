# Hybrid Memory & Disk Forensics Framework

**Repository:** [SURYA16-T/hybrid-forensics-framework](https://github.com/SURYA16-T/hybrid-forensics-framework)

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

## Setup & Usage

### macOS (Terminal)

```bash
# 1. Clone the repository
git clone https://github.com/SURYA16-T/hybrid-forensics-framework.git
cd hybrid-forensics-framework

# 2. Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run tests
python -m pytest -q tests/

# 5. Run the live process/virtual-memory scanner
python -m src.main --scan-live

# 6. Save a live triage snapshot to a JSON file
python -m src.main --capture-live output/macos_snapshot.json

# 7. Offline memory analysis (requires Volatility 3 installed as 'vol')
python -m src.main --image /path/to/memdump.raw --type memory

# 8. Disk artifact analysis (on a mounted or extracted filesystem)
python -m src.main --image /path/to/evidence.img --type disk --disk-root /mnt/evidence

# 9. Hybrid analysis (memory + disk combined)
python -m src.main --image /path/to/memdump.raw --type hybrid --disk-root /mnt/evidence

# 10. Launch the interactive forensics REPL
python -m src.main
# Available REPL commands:
#   /scan                         Live platform memory heuristic scan
#   /capture-live <file>          Save live triage snapshot JSON
#   /analyze <file>               Analyze memory/disk evidence
#   /help                         Show available commands
#   /exit                         Quit

# Or use the convenience script (does steps 2–5 automatically):
chmod +x run_macos.sh
./run_macos.sh
```

### Linux (Terminal)

```bash
# 1. Clone the repository
git clone https://github.com/SURYA16-T/hybrid-forensics-framework.git
cd hybrid-forensics-framework

# 2. Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run tests
python -m pytest -q tests/

# 5. Run the live process/virtual-memory scanner
python -m src.main --scan-live

# 6. Save a live triage snapshot to a JSON file
python -m src.main --capture-live output/linux_snapshot.json

# 7. Offline memory analysis (requires Volatility 3 installed as 'vol')
python -m src.main --image /path/to/memdump.raw --type memory

# 8. Disk artifact analysis (on a mounted or extracted filesystem)
python -m src.main --image /path/to/evidence.img --type disk --disk-root /mnt/evidence

# 9. Hybrid analysis (memory + disk combined)
python -m src.main --image /path/to/memdump.raw --type hybrid --disk-root /mnt/evidence

# 10. Launch the interactive forensics REPL
python -m src.main
# Available REPL commands:
#   /scan                         Live platform memory heuristic scan
#   /capture-live <file>          Save live triage snapshot JSON
#   /analyze <file>               Analyze memory/disk evidence
#   /help                         Show available commands
#   /exit                         Quit

# Or use the convenience script (does steps 2–5 automatically):
chmod +x run_linux.sh
./run_linux.sh
```

### Windows (PowerShell — Administrator recommended for live scanning)

```powershell
# 1. Clone the repository
git clone https://github.com/SURYA16-T/hybrid-forensics-framework.git
cd hybrid-forensics-framework

# 2. Create and activate virtual environment
py -m venv venv
.\venv\Scripts\Activate.ps1

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run tests
python -m pytest -q tests\

# 5. Run the live process/virtual-memory scanner (Administrator recommended)
python -m src.main --scan-live

# 6. Save a live triage snapshot to a JSON file
python -m src.main --capture-live output\windows_snapshot.json

# 7. Offline memory analysis (requires Volatility 3 installed as 'vol')
python -m src.main --image C:\path\to\memdump.raw --type memory

# 8. Disk artifact analysis (on a mounted or extracted filesystem)
python -m src.main --image C:\path\to\evidence.img --type disk --disk-root C:\mnt\evidence

# 9. Hybrid analysis (memory + disk combined)
python -m src.main --image C:\path\to\memdump.raw --type hybrid --disk-root C:\mnt\evidence

# 10. Launch the interactive forensics REPL
python -m src.main
# Available REPL commands:
#   /scan                         Live platform memory heuristic scan
#   /capture-live <file>          Save live triage snapshot JSON
#   /analyze <file>               Analyze memory/disk evidence
#   /help                         Show available commands
#   /exit                         Quit

# Or use the convenience script (does steps 2–5 automatically):
.\run_windows.ps1
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
