from dataclasses import dataclass, field
from typing import Any, Optional

from sec_assess.core.severity import Severity


@dataclass
class Finding:
    id: str
    title: str
    severity: Severity
    category: str
    description: str
    evidence: str
    recommendation: str
    target: str
    framework: Optional[str] = None
    mitre_tactic: Optional[str] = None
    mitre_technique: Optional[str] = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity.value,
            "category": self.category,
            "description": self.description,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
            "target": self.target,
            "framework": self.framework,
            "mitre_tactic": self.mitre_tactic,
            "mitre_technique": self.mitre_technique,
            "metadata": self.metadata,
        }