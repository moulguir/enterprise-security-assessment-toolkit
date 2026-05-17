from sec_assess.core.finding import Finding
from sec_assess.core.severity import Severity
from sec_assess.modules.compliance.mapper import (
    enrich_finding_with_compliance,
    enrich_findings_with_compliance,
    get_compliance_mapping,
)


def make_finding(finding_id: str) -> Finding:
    return Finding(
        id=finding_id,
        title="Test finding",
        severity=Severity.MEDIUM,
        category="Test",
        description="Test description",
        evidence="Test evidence",
        recommendation="Test recommendation",
        target="https://example.com",
    )


def test_get_compliance_mapping_for_log_ssh_bruteforce():
    mapping = get_compliance_mapping("LOG-SSH-001")

    assert mapping["mitre_attack"]["technique"] == "T1110 - Brute Force"
    assert mapping["nist_csf"]["function"] == "Detect"


def test_enrich_log_finding_with_mitre_and_nist():
    finding = make_finding("LOG-SSH-001")

    enriched = enrich_finding_with_compliance(finding)

    assert enriched.framework == "MITRE ATT&CK"
    assert enriched.mitre_tactic == "Credential Access"
    assert enriched.mitre_technique == "T1110 - Brute Force"
    assert "compliance" in enriched.metadata
    assert "mitre_attack" in enriched.metadata["compliance"]
    assert "nist_csf" in enriched.metadata["compliance"]


def test_enrich_web_header_with_owasp_and_nist():
    finding = make_finding("WEB-HEADER-002")

    enriched = enrich_finding_with_compliance(finding)

    assert enriched.framework == "OWASP ASVS"
    assert "compliance" in enriched.metadata
    assert "owasp_asvs" in enriched.metadata["compliance"]
    assert "nist_csf" in enriched.metadata["compliance"]


def test_enrich_findings_with_compliance_list():
    findings = [
        make_finding("WEB-HEADER-002"),
        make_finding("LOG-SSH-001"),
    ]

    enriched_findings = enrich_findings_with_compliance(findings)

    assert len(enriched_findings) == 2
    assert "compliance" in enriched_findings[0].metadata
    assert "compliance" in enriched_findings[1].metadata


def test_unknown_finding_id_is_not_modified():
    finding = make_finding("UNKNOWN-001")

    enriched = enrich_finding_with_compliance(finding)

    assert enriched.framework is None
    assert enriched.mitre_tactic is None
    assert enriched.mitre_technique is None
    assert "compliance" not in enriched.metadata