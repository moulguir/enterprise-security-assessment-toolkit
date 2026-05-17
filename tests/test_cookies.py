from sec_assess.modules.web_security.cookies import analyze_cookies


def test_cookie_without_security_flags_generates_findings():
    raw_cookies = [
        "sessionid=abc123; Path=/"
    ]

    findings = analyze_cookies(raw_cookies, target="https://example.com")

    finding_ids = [finding.id for finding in findings]

    assert "WEB-COOKIE-001" in finding_ids
    assert "WEB-COOKIE-002" in finding_ids
    assert "WEB-COOKIE-003" in finding_ids


def test_cookie_with_security_flags_generates_no_findings():
    raw_cookies = [
        "sessionid=abc123; Path=/; HttpOnly; Secure; SameSite=Lax"
    ]

    findings = analyze_cookies(raw_cookies, target="https://example.com")

    assert len(findings) == 0