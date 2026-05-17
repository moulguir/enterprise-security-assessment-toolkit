from sec_assess.core.finding import Finding
from sec_assess.core.severity import Severity


SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "id": "WEB-HEADER-001",
        "title": "Missing Strict-Transport-Security header",
        "severity": Severity.MEDIUM,
        "description": "The application does not enforce HTTPS through the HSTS header.",
        "recommendation": "Enable Strict-Transport-Security with an appropriate max-age value.",
        "framework": "OWASP ASVS",
    },
    "Content-Security-Policy": {
        "id": "WEB-HEADER-002",
        "title": "Missing Content-Security-Policy header",
        "severity": Severity.MEDIUM,
        "description": "The application does not define a Content-Security-Policy header.",
        "recommendation": "Define a restrictive Content-Security-Policy to reduce XSS and injection risks.",
        "framework": "OWASP ASVS",
    },
    "X-Frame-Options": {
        "id": "WEB-HEADER-003",
        "title": "Missing X-Frame-Options header",
        "severity": Severity.LOW,
        "description": "The application may be vulnerable to clickjacking if framing is allowed.",
        "recommendation": "Set X-Frame-Options to DENY or SAMEORIGIN.",
        "framework": "OWASP ASVS",
    },
    "X-Content-Type-Options": {
        "id": "WEB-HEADER-004",
        "title": "Missing X-Content-Type-Options header",
        "severity": Severity.LOW,
        "description": "The browser may try to MIME-sniff the content type.",
        "recommendation": "Set X-Content-Type-Options to nosniff.",
        "framework": "OWASP ASVS",
    },
    "Referrer-Policy": {
        "id": "WEB-HEADER-005",
        "title": "Missing Referrer-Policy header",
        "severity": Severity.LOW,
        "description": "The application does not control how much referrer information is shared.",
        "recommendation": "Set a Referrer-Policy such as strict-origin-when-cross-origin.",
        "framework": "OWASP ASVS",
    },
}


def analyze_security_headers(headers: dict, target: str) -> list[Finding]:
    findings: list[Finding] = []

    normalized_headers = {key.lower(): value for key, value in headers.items()}

    for header_name, metadata in SECURITY_HEADERS.items():
        if header_name.lower() not in normalized_headers:
            findings.append(
                Finding(
                    id=metadata["id"],
                    title=metadata["title"],
                    severity=metadata["severity"],
                    category="Web Security Headers",
                    description=metadata["description"],
                    evidence=f"Header '{header_name}' was not present in the HTTP response.",
                    recommendation=metadata["recommendation"],
                    target=target,
                    framework=metadata["framework"],
                )
            )

    server_header = normalized_headers.get("server")
    if server_header:
        findings.append(
            Finding(
                id="WEB-HEADER-006",
                title="Server header exposed",
                severity=Severity.INFO,
                category="Information Disclosure",
                description="The application exposes server information through the Server header.",
                evidence=f"Server header value: {server_header}",
                recommendation="Avoid exposing detailed server version information where possible.",
                target=target,
                framework="OWASP ASVS",
            )
        )

    return findings