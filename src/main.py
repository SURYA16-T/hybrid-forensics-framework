from __future__ import annotations

import argparse
import json
import platform
import sys
from pathlib import Path

from src.capture import LinuxLiveAnalyzer, MacOSLiveAnalyzer, NativeLiveRAMAnalyzer, capture_live_snapshot
from src.correlation import TimelineBuilder, ThreatScorer, calculate_ram_risk_score
from src.disk import ArtifactExtractor
from src.intake import EvidenceIntake
from src.memory import ProcessScanner
from src.response import ReportGenerator
from src.config.settings import OUTPUT_DIR


def run_offline(evidence_path: str, evidence_type: str, disk_root: str | None, volatility: str, output_dir: str) -> dict:
    evidence = EvidenceIntake(evidence_path, evidence_type).process_evidence()
    timeline = TimelineBuilder()

    if evidence_type in {"disk", "hybrid"}:
        if not disk_root:
            raise ValueError("--disk-root is required for disk or hybrid analysis.")
        artifacts = ArtifactExtractor(disk_root).extract_all()
        timeline.ingest_disk_artifacts(artifacts)

    if evidence_type in {"memory", "hybrid"}:
        scanner = ProcessScanner(evidence_path, volatility)
        processes = scanner.scan_offline()
        timeline.ingest_memory_processes(processes, evidence.intake_timestamp_utc)

    events = timeline.build_timeline()
    threats = ThreatScorer().evaluate_timeline(events)
    output_path = Path(output_dir) / evidence.evidence_id
    json_path, html_path = ReportGenerator(output_path).generate(evidence, events, threats)
    return {"evidence_id": evidence.evidence_id, "json": json_path, "html": html_path, "events": len(events), "threats": len(threats)}


def live_scan() -> None:
    system = platform.system()
    if system == "Windows":
        analyzer = NativeLiveRAMAnalyzer()
        findings = analyzer.scan()
    elif system == "Darwin":
        analyzer = MacOSLiveAnalyzer()
        findings = analyzer.scan()
    elif system == "Linux":
        analyzer = LinuxLiveAnalyzer()
        findings = analyzer.scan()
    else:
        print(json.dumps({
            "platform": system,
            "mode": "live_virtual_memory_triage",
            "findings": [],
            "count": 0,
            "error": f"Unsupported operating system: {system}"
        }, indent=2))
        return

    from dataclasses import asdict
    payload = [item.to_dict() if hasattr(item, "to_dict") else asdict(item) for item in findings]
    telemetry = {
        "endpoint_id": platform.node(),
        "platform": system,
        "mode": "live_virtual_memory_triage",
        "findings": payload,
        "count": len(payload),
        "note": "Heuristic triage only; protected processes may be inaccessible and this command does not acquire physical RAM on Linux/macOS."
    }
    print(json.dumps(telemetry, indent=2))
    print("\n")
    calculate_ram_risk_score(telemetry)

def main() -> None:
    parser = argparse.ArgumentParser(description="Hybrid Memory & Disk Forensics Framework")
    parser.add_argument("--image", help="Forensic evidence image/file")
    parser.add_argument("--type", choices=["memory", "disk", "hybrid", "generic"], default="generic")
    parser.add_argument("--disk-root", help="Mounted/extracted disk root directory")
    parser.add_argument("--volatility", default="vol", help="Volatility 3 command or full executable path")
    parser.add_argument("--output", default=str(OUTPUT_DIR))
    parser.add_argument("--scan-live", action="store_true", help="Run the platform-appropriate live process/memory heuristic scanner")
    parser.add_argument("--capture-live", metavar="PATH", help="Save a platform-specific live triage snapshot as JSON (not physical RAM)")
    args = parser.parse_args()

    if args.capture_live:
        try:
            print(capture_live_snapshot(args.capture_live))
        except (OSError, EnvironmentError, PermissionError) as exc:
            print(f"LIVE CAPTURE ERROR: {exc}", file=sys.stderr)
            raise SystemExit(2)
        return

    if args.scan_live:
        try:
            live_scan()
        except (OSError, EnvironmentError, PermissionError) as exc:
            print(f"LIVE SCAN ERROR: {exc}", file=sys.stderr)
            raise SystemExit(2)
        return

    if not args.image:
        print(f"Hybrid Forensics Framework ({platform.system()})")
        print("  /scan                         Live platform memory heuristic scan")
        print("  /capture-live <file>          Save live triage snapshot JSON")
        print("  /analyze <file>               Analyze memory/disk evidence")
        print("  /exit                         Quit")
        while True:
            try:
                line = input("forensics> ").strip()
            except (EOFError, KeyboardInterrupt):
                print()
                return
            if line == "/exit":
                return
            if line.startswith("/capture-live "):
                target = line[len("/capture-live "):].strip().strip('"')
                try:
                    print(capture_live_snapshot(target))
                except Exception as exc:
                    print(f"ERROR: {exc}")
                continue
            if line == "/scan":
                try:
                    live_scan()
                except Exception as exc:
                    print(f"ERROR: {exc}")
                continue
            if line.startswith("/analyze "):
                file_path = line[len("/analyze "):].strip().strip('"')
                p = Path(file_path)
                kind = "memory" if p.suffix.lower() in {".raw", ".dmp", ".vmem", ".sav", ".mem"} else "disk"
                disk_root = args.disk_root or (str(p) if p.is_dir() else None)
                try:
                    print(run_offline(file_path, kind, disk_root, args.volatility, args.output))
                except Exception as exc:
                    print(f"ERROR: {exc}")
                continue
            if line in {"/help", "help"}:
                print("/scan | /capture-live <file> | /analyze <file> | /exit")
                continue
            print("Unknown command. Use /help.")
        return

    result = run_offline(args.image, args.type, args.disk_root, args.volatility, args.output)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
