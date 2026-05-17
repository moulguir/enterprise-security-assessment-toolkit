from http.cookies import SimpleCookie

from sec_assess.core.finding import Finding
from sec_assess.core.severity import Severity


def analyze_cookies(set_cookie_headers: list[str], target: str) -> list[Finding]:
    findings: list[Finding] = []

    for raw_cookie in set_cookie_headers:
        cookie = SimpleCookie()
        cookie.load(raw_cookie)

        for cookie_name, morsel in cookie.items():
            cookie_output = raw_cookie.lower()

            if "httponly" not in cookie_output:
                findings.append(
                    Finding(
                        id="WEB-COOKIE-001",
                        title="Cookie missing HttpOnly flag",
                        severity=Severity.HIGH,
                        category="Cookie Security",
                        description="A cookie is missing the HttpOnly flag, which may expose it to client-side scripts.",
                        evidence=f"Cookie '{cookie_name}' does not include HttpOnly.",
                        recommendation="Set the HttpOnly flag for session and sensitive cookies.",
                        target=target,
                        framework="OWASP ASVS",
                    )
                )

            if "secure" not in cookie_output:
                findings.append(
                    Finding(
                        id="WEB-COOKIE-002",
                        title="Cookie missing Secure flag",
                        severity=Severity.HIGH,
                        category="Cookie Security",
                        description="A cookie is missing the Secure flag and may be sent over unencrypted connections.",
                        evidence=f"Cookie '{cookie_name}' does not include Secure.",
                        recommendation="Set the Secure flag for cookies used over HTTPS.",
                        target=target,
                        framework="OWASP ASVS",
                    )
                )

            if "samesite" not in cookie_output:
                findings.append(
                    Finding(
                        id="WEB-COOKIE-003",
                        title="Cookie missing SameSite attribute",
                        severity=Severity.MEDIUM,
                        category="Cookie Security",
                        description="A cookie does not define the SameSite attribute.",
                        evidence=f"Cookie '{cookie_name}' does not include SameSite.",
                        recommendation="Set SameSite=Lax or SameSite=Strict depending on application requirements.",
                        target=target,
                        framework="OWASP ASVS",
                    )
                )

    return findings