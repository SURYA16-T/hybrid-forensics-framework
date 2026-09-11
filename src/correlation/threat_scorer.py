from __future__ import annotations

from src.config.settings import SUSPICIOUS_NAMES, SUSPICIOUS_PATH_PARTS


class ThreatScorer:
    def score_event(self, event) -> int:
        score = int(event.risk_score or 0)
        text = f"{event.description} {event.details}".lower()
        for name, points in SUSPICIOUS_NAMES.items():
            if name in text:
                score = max(score, points)
        for part, points in SUSPICIOUS_PATH_PARTS.items():
            if part in text.replace("\\", "/"):
                score += points
        return min(100, score)

    def evaluate_timeline(self, timeline):
        threats = []
        for event in timeline:
            event.risk_score = self.score_event(event)
            if event.risk_score > 0:
                threats.append(event)
        return threats
