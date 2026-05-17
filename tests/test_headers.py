from sec_assess.modules.web_security.headers import analyze_security_headers


def test_missing_security_headers_generate_findings():
    headers = {}

    findings = analyze_security_headers(headers, target="https://example.com")

    finding_ids = [finding.id for finding in findings]

    assert "WEB-HEADER-001" in finding_ids
    assert "WEB-HEADER-002" in finding_ids
    assert "WEB-HEADER-003" in finding_ids
    assert "WEB-HEADER-004" in finding_ids
    assert "WEB-HEADER-005" in finding_ids


def test_present_security_headers_do_not_generate_missing_header_findings():
    headers = {
        "Strict-Transport-Security": "max-age=31536000",
        "Content-Security-Policy": "default-src 'self'",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "strict-origin-when-cross-origin",
    }

    findings = analyze_security_headers(headers, target="https://example.com")

    missing_header_findings = [
        finding for finding in findings if finding.id.startswith("WEB-HEADER-00")
    ]

    assert len(missing_header_findings) == 0


def test_server_header_generates_info_finding():
    headers = {
        "Strict-Transport-Security": "max-age=31536000",
        "Content-Security-Policy": "default-src 'self'",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Server": "nginx/1.24.0",
    }

    findings = analyze_security_headers(headers, target="https://example.com")

    finding_ids = [finding.id for finding in findings]

    assert "WEB-HEADER-006" in finding_ids