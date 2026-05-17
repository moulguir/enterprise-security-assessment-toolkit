from copy import deepcopy

from sec_assess.core.finding import Finding
from sec_assess.modules.compliance.mitre_attack import MITRE_ATTACK_MAPPING
from sec_assess.modules.compliance.nist_csf import NIST_CSF_MAPPING
from sec_assess.modules.compliance.owasp_asvs import OWASP_ASVS_MAPPING


def get_compliance_mapping(finding_id: str) -> dict:
    return {
        "mitre_attack": MITRE_ATTACK_MAPPING.get(finding_id),
        "owasp_asvs": OWASP_ASVS_MAPPING.get(finding_id),
        "nist_csf": NIST_CSF_MAPPING.get(finding_id),
    }


def enrich_finding_with_compliance(finding: Finding) -> Finding:
    enriched_finding = deepcopy(finding)
    mapping = get_compliance_mapping(enriched_finding.id)

    compliance_metadata = {
        key: value
        for key, value in mapping.items()
        if value is not None
    }

    if compliance_metadata:
        enriched_finding.metadata["compliance"] = compliance_metadata

    mitre_mapping = mapping.get("mitre_attack")
    if mitre_mapping:
        enriched_finding.framework = "MITRE ATT&CK"
        enriched_finding.mitre_tactic = mitre_mapping.get("tactic")
        enriched_finding.mitre_technique = mitre_mapping.get("technique")

    owasp_mapping = mapping.get("owasp_asvs")
    if owasp_mapping and not enriched_finding.framework:
        enriched_finding.framework = "OWASP ASVS"

    nist_mapping = mapping.get("nist_csf")
    if nist_mapping and not enriched_finding.framework:
        enriched_finding.framework = "NIST CSF"

    return enriched_finding


def enrich_findings_with_compliance(findings: list[Finding]) -> list[Finding]:
    return [
        enrich_finding_with_compliance(finding)
        for finding in findings
    ]