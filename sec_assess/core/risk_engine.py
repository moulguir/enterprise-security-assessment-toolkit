from sec_assess.core.finding import Finding
from sec_assess.core.severity import Severity, SEVERITY_WEIGHTS


class RiskEngine:
    def calculate_score(self, findings: list[Finding]) -> int:
        """
        Returns a security score from 0 to 100.
        100 means no relevant risk was detected.
        Lower score means higher risk.
        """
        total_penalty = 0

        for finding in findings:
            total_penalty += SEVERITY_WEIGHTS.get(finding.severity, 0)

        score = max(0, 100 - total_penalty)
        return score

    def classify_risk(self, score: int) -> str:
        if score >= 85:
            return "LOW"
        if score >= 65:
            return "MEDIUM"
        if score >= 40:
            return "HIGH"
        return "CRITICAL"

    def count_by_severity(self, findings: list[Finding]) -> dict:
        result = {
            Severity.INFO.value: 0,
            Severity.LOW.value: 0,
            Severity.MEDIUM.value: 0,
            Severity.HIGH.value: 0,
            Severity.CRITICAL.value: 0,
        }

        for finding in findings:
            result[finding.severity.value] += 1

        return result