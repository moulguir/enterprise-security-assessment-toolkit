import requests

from sec_assess.core.finding import Finding
from sec_assess.core.severity import Severity
from sec_assess.modules.web_security.cookies import analyze_cookies
from sec_assess.modules.web_security.headers import analyze_security_headers
from sec_assess.utils.url_utils import is_https, normalize_url


class WebSecurityScanner:
    def __init__(self, timeout: int = 10):
        self.timeout = timeout

    def scan(self, url: str) -> list[Finding]:
        target = normalize_url(url)
        findings: list[Finding] = []

        if not is_https(target):
            findings.append(
                Finding(
                    id="WEB-HTTPS-001",
                    title="Application does not use HTTPS",
                    severity=Severity.HIGH,
                    category="Transport Security",
                    description="The target URL is using HTTP instead of HTTPS.",
                    evidence=f"URL provided: {target}",
                    recommendation="Use HTTPS and redirect all HTTP traffic to HTTPS.",
                    target=target,
                    framework="OWASP ASVS",
                )
            )

        try:
            response = requests.get(
                target,
                timeout=self.timeout,
                allow_redirects=True,
                verify=True,
            )
        except requests.exceptions.SSLError as error:
            findings.append(
                Finding(
                    id="WEB-TLS-001",
                    title="TLS certificate validation failed",
                    severity=Severity.CRITICAL,
                    category="Transport Security",
                    description="The TLS certificate could not be validated.",
                    evidence=str(error),
                    recommendation="Install a valid TLS certificate issued by a trusted certificate authority.",
                    target=target,
                    framework="OWASP ASVS",
                )
            )
            return findings

        except requests.exceptions.RequestException as error:
            findings.append(
                Finding(
                    id="WEB-CONN-001",
                    title="Connection error",
                    severity=Severity.INFO,
                    category="Connectivity",
                    description="The scanner could not connect to the target.",
                    evidence=str(error),
                    recommendation="Verify that the target is reachable and that the URL is correct.",
                    target=target,
                )
            )
            return findings

        findings.extend(
            analyze_security_headers(
                headers=dict(response.headers),
                target=target,
            )
        )

        set_cookie_headers = []

        if "Set-Cookie" in response.headers:
            set_cookie_headers.append(response.headers.get("Set-Cookie", ""))

        findings.extend(
            analyze_cookies(
                set_cookie_headers=set_cookie_headers,
                target=target,
            )
        )

        if response.url.startswith("http://"):
            findings.append(
                Finding(
                    id="WEB-REDIRECT-001",
                    title="Final URL uses HTTP",
                    severity=Severity.HIGH,
                    category="Transport Security",
                    description="The final URL after redirects uses HTTP.",
                    evidence=f"Final URL: {response.url}",
                    recommendation="Ensure all redirects lead to HTTPS endpoints.",
                    target=target,
                    framework="OWASP ASVS",
                )
            )

        return findings