from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path


class ReportGenerator:
    def __init__(self, output_dir: str | Path) -> None:
        self.output_dir = Path(output_dir).expanduser().resolve()
        self.output_dir.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _dict_list(items):
        return [asdict(x) if hasattr(x, "__dataclass_fields__") else x for x in items]

    def generate(self, evidence, timeline, threats) -> tuple[str, str]:
        payload = {
            "evidence": asdict(evidence),
            "timeline": self._dict_list(timeline),
            "threats": self._dict_list(threats),
            "summary": {
                "event_count": len(timeline),
                "threat_count": len(threats),
                "max_risk": max((getattr(x, "risk_score", 0) for x in threats), default=0),
            },
        }
        json_path = self.output_dir / "forensic_report.json"
        html_path = self.output_dir / "forensic_report.html"
        json_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        rows = "".join(
            f"<tr><td>{e.timestamp}</td><td>{e.source_module}</td><td>{e.event_type}</td>"
            f"<td>{e.description}</td><td>{e.risk_score}</td></tr>" for e in timeline
        )
        html = f"<!doctype html><html><head><meta charset='utf-8'><title>Forensic Report</title>\n<style>body{{font-family:Arial,sans-serif;margin:2rem;background:#f5f7fb;color:#172033}} .card{{background:white;padding:1rem;margin-bottom:1rem;border-radius:10px}} table{{width:100%;border-collapse:collapse;background:white}} th,td{{padding:8px;border:1px solid #ddd;text-align:left;vertical-align:top}} th{{background:#eef2f7}}</style>\n</head><body><div class='card'><h1>Hybrid Forensic Report</h1><p><b>Evidence ID:</b> {evidence.evidence_id}</p><p><b>MD5:</b> {evidence.hashes['md5']}</p><p><b>SHA-256:</b> {evidence.hashes['sha256']}</p><p><b>Events:</b> {len(timeline)} &nbsp; <b>Threats:</b> {len(threats)} &nbsp; <b>Max Risk:</b> {payload['summary']['max_risk']}</p></div>\n<table><thead><tr><th>Timestamp</th><th>Source</th><th>Type</th><th>Description</th><th>Risk</th></tr></thead><tbody>{rows}</tbody></table></body></html>"
        html_path.write_text(html, encoding="utf-8")
        return str(json_path), str(html_path)
