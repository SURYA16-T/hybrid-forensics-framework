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

## Threat Heuristics & Live RAM Risk Engine

The framework features a strict **Live RAM Risk Score (RS)** engine that calculates risk based on a weighted heuristic matrix. For every memory dump or live RAM scan, it evaluates the telemetry against the following specific deductions:

### 🚨 Critical Risk Indicators (45 Points Each)

- `CRIT_01`: Hidden Processes (`psxview` mismatches / unlinked `ActiveProcessLinks`).
- `CRIT_02`: Unbacked Executable Memory (`malfind` hits with `PAGE_EXECUTE_READWRITE` or `RWX_EXECUTABLE_MEMORY`).
- `CRIT_03`: Process Hollowing / Replacement (e.g., `svchost.exe` running out of a non-standard path).
- `CRIT_04`: Kernel Callback Table modifications or unauthorized driver hooks.

### ⚠️ High Risk Indicators (25 Points Each)

- `HIGH_01`: Suspicious Parent-Child relationships (e.g., `lsass.exe` spawned by `cmd.exe`).
- `HIGH_02`: Inline API Hooking or User/Kernel SSDT modifications (e.g., `CREATEFILE_W_HOOK`).
- `HIGH_03`: Orphaned Threads (running code without a parent process or valid DLL backing).

### 🔍 Medium/Low Risk Indicators (10 Points Each)

- `MED_01`: System binaries communicating with external/foreign IP addresses (`netscan`).
- `MED_02`: Sudden privilege escalation to `SYSTEM` by non-system apps.
- `MED_03`: Cleared history buffers (`cmdscan` / `consoles` tampering).

### Triage Output & Automation

After performing a live scan (`python -m src.main --scan-live`), the engine will automatically print an **Incident Response Triage Report** to the terminal, detailing the triggered heuristics, the mathematical breakdown `RS = min( ∑ (Wi × Ci), 100 )`, the final risk tier (Low, Medium, High, Critical), and immediate analyst recommendations.

**Example Terminal Output:**
```text
============================================================
            LIVE RAM RISK SCORE TRIAGE REPORT            
============================================================
FINAL RISK SCORE: 100 / 100
RISK TIER       : 🔴 CRITICAL
IMMEDIATE ACTION: Rootkit/Takeover verified. Execute full Incident Response playbook.

1. TRIGGERED HEURISTICS:
  [CRIT_02] Unbacked Executable Memory (malfind PAGE_EXECUTE_READWRITE) (Count: 3)
         Evidence: Memory Tag 255              150000000-157dc0000    [125.8M   464K   464K   272K] rwx/rwx SM=ZER
  [HIGH_01] Suspicious Parent-Child Relationship (Count: 1)
         Evidence: Process tree shows lsass.exe spawned directly by suspicious powershell.exe

2. MATHEMATICAL BREAKDOWN:
  Calculation: (45 pts * 3) + (25 pts * 1) = 160 points.
  Result: min(160, 100) -> Final Score: 100

3. ANALYSTS RECOMMENDATIONS:
  Isolate the host at the network layer to prevent lateral movement. Export a full physical memory dump (.raw/.dmp) for deep Volatility/YARA analysis and begin looking for persistent registry/scheduled task hooks.
============================================================
```

*Scores are triage heuristics, **not definitive proof of malware**.*

## macOS limitation to state in a presentation

The macOS module performs **live process and virtual-memory-map triage**, not a complete physical-RAM acquisition. This is intentional. A complete physical-memory workflow on macOS requires platform-specific acquisition mechanisms and permissions beyond a portable Python script.

## Safety / forensic note

Work on copies where possible and preserve originals and cryptographic hashes. Live process inspection can require elevated privileges and may be restricted by operating-system security controls.
