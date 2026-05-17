import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse

from cryptography import x509
from cryptography.hazmat.backends import default_backend

from sec_assess.core.finding import Finding
from sec_assess.core.severity import Severity
from sec_assess.utils.url_utils import normalize_url


WEAK_SIGNATURE_KEYWORDS = [
    "md5",
    "sha1",
]


def _format_name(name: x509.Name) -> str:
    return ", ".join(
        f"{attribute.oid._name}={attribute.value}"
        for attribute in name
    )


def _get_hostname_and_port(url: str) -> tuple[str, int]:
    parsed = urlparse(normalize_url(url))

    if not parsed.hostname:
        raise ValueError(f"Could not extract hostname from URL: {url}")

    port = parsed.port or 443
    return parsed.hostname, port


def analyze_tls_certificate(
    url: str,
    timeout: int = 10,
    expires_soon_days: int = 30,
) -> list[Finding]:
    target = normalize_url(url)
    findings: list[Finding] = []

    if not target.startswith("https://"):
        findings.append(
            Finding(
                id="WEB-TLS-000",
                title="TLS analysis skipped for non-HTTPS target",
                severity=Severity.INFO,
                category="TLS Security",
                description="TLS certificate analysis was skipped because the target does not use HTTPS.",
                evidence=f"Target URL: {target}",
                recommendation="Use HTTPS to enable TLS certificate validation.",
                target=target,
                framework="OWASP ASVS",
            )
        )
        return findings

    try:
        hostname, port = _get_hostname_and_port(target)

        context = ssl.create_default_context()

        with socket.create_connection((hostname, port), timeout=timeout) as tcp_socket:
            with context.wrap_socket(tcp_socket, server_hostname=hostname) as tls_socket:
                der_certificate = tls_socket.getpeercert(binary_form=True)

        certificate = x509.load_der_x509_certificate(
            der_certificate,
            default_backend(),
        )

        now = datetime.now(timezone.utc)
        not_valid_before = certificate.not_valid_before_utc
        not_valid_after = certificate.not_valid_after_utc
        days_remaining = (not_valid_after - now).days

        subject = _format_name(certificate.subject)
        issuer = _format_name(certificate.issuer)
        signature_algorithm = certificate.signature_hash_algorithm.name.lower()

        metadata = {
            "subject": subject,
            "issuer": issuer,
            "serial_number": str(certificate.serial_number),
            "not_valid_before": not_valid_before.isoformat(),
            "not_valid_after": not_valid_after.isoformat(),
            "days_remaining": days_remaining,
            "signature_algorithm": signature_algorithm,
        }

        findings.append(
            Finding(
                id="WEB-TLS-006",
                title="TLS certificate metadata collected",
                severity=Severity.INFO,
                category="TLS Security",
                description="TLS certificate metadata was collected successfully.",
                evidence=(
                    f"Issuer: {issuer}\n"
                    f"Subject: {subject}\n"
                    f"Valid until: {not_valid_after.isoformat()}\n"
                    f"Days remaining: {days_remaining}\n"
                    f"Signature algorithm: {signature_algorithm}"
                ),
                recommendation="Review TLS certificate metadata periodically as part of security monitoring.",
                target=target,
                framework="OWASP ASVS",
                metadata=metadata,
            )
        )

        if now > not_valid_after:
            findings.append(
                Finding(
                    id="WEB-TLS-003",
                    title="TLS certificate expired",
                    severity=Severity.CRITICAL,
                    category="TLS Security",
                    description="The TLS certificate is expired.",
                    evidence=f"Certificate expired at: {not_valid_after.isoformat()}",
                    recommendation="Renew and deploy a valid TLS certificate immediately.",
                    target=target,
                    framework="OWASP ASVS",
                    metadata=metadata,
                )
            )

        elif days_remaining <= expires_soon_days:
            findings.append(
                Finding(
                    id="WEB-TLS-002",
                    title="TLS certificate expires soon",
                    severity=Severity.MEDIUM,
                    category="TLS Security",
                    description="The TLS certificate is close to expiration.",
                    evidence=f"Certificate expires in {days_remaining} days.",
                    recommendation="Renew the TLS certificate before expiration to avoid service disruption.",
                    target=target,
                    framework="OWASP ASVS",
                    metadata=metadata,
                )
            )

        if any(keyword in signature_algorithm for keyword in WEAK_SIGNATURE_KEYWORDS):
            findings.append(
                Finding(
                    id="WEB-TLS-005",
                    title="TLS certificate uses weak signature algorithm",
                    severity=Severity.HIGH,
                    category="TLS Security",
                    description="The TLS certificate appears to use a weak signature hash algorithm.",
                    evidence=f"Signature algorithm: {signature_algorithm}",
                    recommendation="Use a certificate signed with a modern algorithm such as SHA-256 or stronger.",
                    target=target,
                    framework="OWASP ASVS",
                    metadata=metadata,
                )
            )

    except ssl.SSLCertVerificationError as error:
        findings.append(
            Finding(
                id="WEB-TLS-001",
                title="TLS certificate validation failed",
                severity=Severity.CRITICAL,
                category="TLS Security",
                description="The TLS certificate could not be validated by the local trust store.",
                evidence=str(error),
                recommendation="Install a valid certificate issued by a trusted certificate authority.",
                target=target,
                framework="OWASP ASVS",
            )
        )

    except ssl.CertificateError as error:
        findings.append(
            Finding(
                id="WEB-TLS-004",
                title="TLS certificate hostname mismatch",
                severity=Severity.CRITICAL,
                category="TLS Security",
                description="The TLS certificate does not match the requested hostname.",
                evidence=str(error),
                recommendation="Deploy a certificate that matches the requested hostname.",
                target=target,
                framework="OWASP ASVS",
            )
        )

    except Exception as error:
        findings.append(
            Finding(
                id="WEB-TLS-999",
                title="TLS analysis failed",
                severity=Severity.INFO,
                category="TLS Security",
                description="TLS certificate analysis could not be completed.",
                evidence=str(error),
                recommendation="Verify that the target supports TLS and is reachable.",
                target=target,
                framework="OWASP ASVS",
            )
        )

    return findings