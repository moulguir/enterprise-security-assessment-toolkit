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

    def classify_risk(self, score: int, findings: list[Finding] | None = None) -> str:
        """
        Classifies overall risk using both numerical score and maximum finding severity.

        This avoids situations where a target has a HIGH finding but the global
        risk is still displayed as LOW because the numeric score remains high.
        """
        if findings:
            severities = {finding.severity for finding in findings}

            if Severity.CRITICAL in severities:
                return "CRITICAL"

            if Severity.HIGH in severities:
                return "HIGH"

            if Severity.MEDIUM in severities:
                return "MEDIUM"

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