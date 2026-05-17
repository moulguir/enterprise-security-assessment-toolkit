from sec_assess.modules.web_security.tls import analyze_tls_certificate


def test_tls_analysis_skipped_for_http_target():
    findings = analyze_tls_certificate("http://example.com")

    finding_ids = [finding.id for finding in findings]

    assert "WEB-TLS-000" in finding_ids


def test_tls_analysis_returns_findings_for_https_target():
    findings = analyze_tls_certificate("https://example.com")

    assert len(findings) >= 1

    finding_ids = [finding.id for finding in findings]

    assert any(
        finding_id.startswith("WEB-TLS-")
        for finding_id in finding_ids
    )