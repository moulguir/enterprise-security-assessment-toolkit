from dataclasses import dataclass

from sec_assess.core.severity import Severity


@dataclass(frozen=True)
class ServiceProfile:
    port: int
    service: str
    severity: Severity
    description: str
    recommendation: str


COMMON_PORTS = [
    21,
    22,
    23,
    25,
    53,
    80,
    110,
    143,
    389,
    443,
    445,
    1433,
    1521,
    3306,
    3389,
    5432,
    6379,
    9200,
]


SERVICE_PROFILES = {
    21: ServiceProfile(
        port=21,
        service="FTP",
        severity=Severity.HIGH,
        description="FTP service is exposed. FTP often transmits credentials and data in clear text.",
        recommendation="Disable FTP or replace it with SFTP/FTPS. Restrict access using firewall rules.",
    ),
    22: ServiceProfile(
        port=22,
        service="SSH",
        severity=Severity.MEDIUM,
        description="SSH service is exposed. This may be expected, but it should be restricted and hardened.",
        recommendation="Restrict SSH by source IP, disable password login, use keys and enable MFA where possible.",
    ),
    23: ServiceProfile(
        port=23,
        service="Telnet",
        severity=Severity.CRITICAL,
        description="Telnet service is exposed. Telnet transmits credentials in clear text.",
        recommendation="Disable Telnet immediately and use SSH instead.",
    ),
    25: ServiceProfile(
        port=25,
        service="SMTP",
        severity=Severity.MEDIUM,
        description="SMTP service is exposed. Misconfigured SMTP may enable abuse or relay issues.",
        recommendation="Verify relay restrictions, authentication and mail security configuration.",
    ),
    53: ServiceProfile(
        port=53,
        service="DNS",
        severity=Severity.MEDIUM,
        description="DNS service is exposed. Public or internal DNS services should be carefully restricted.",
        recommendation="Restrict recursion, validate zone transfer settings and monitor DNS abuse.",
    ),
    80: ServiceProfile(
        port=80,
        service="HTTP",
        severity=Severity.MEDIUM,
        description="HTTP service is exposed without transport encryption.",
        recommendation="Redirect HTTP to HTTPS and avoid serving sensitive content over clear text.",
    ),
    110: ServiceProfile(
        port=110,
        service="POP3",
        severity=Severity.HIGH,
        description="POP3 service is exposed. Legacy mail protocols may transmit credentials insecurely.",
        recommendation="Disable POP3 if not required or enforce secure variants and strong authentication.",
    ),
    143: ServiceProfile(
        port=143,
        service="IMAP",
        severity=Severity.HIGH,
        description="IMAP service is exposed. Plain IMAP can expose credentials and mailbox data.",
        recommendation="Use IMAPS, enforce TLS and restrict access.",
    ),
    389: ServiceProfile(
        port=389,
        service="LDAP",
        severity=Severity.HIGH,
        description="LDAP service is exposed. Directory services can reveal sensitive identity information.",
        recommendation="Restrict LDAP access and use LDAPS where possible.",
    ),
    443: ServiceProfile(
        port=443,
        service="HTTPS",
        severity=Severity.INFO,
        description="HTTPS service is exposed.",
        recommendation="Verify TLS configuration, certificates and application security controls.",
    ),
    445: ServiceProfile(
        port=445,
        service="SMB",
        severity=Severity.HIGH,
        description="SMB service is exposed. SMB exposure can increase lateral movement and ransomware risk.",
        recommendation="Restrict SMB to trusted internal networks and disable SMBv1.",
    ),
    1433: ServiceProfile(
        port=1433,
        service="Microsoft SQL Server",
        severity=Severity.HIGH,
        description="Microsoft SQL Server port is exposed.",
        recommendation="Restrict database access to trusted application servers and internal networks.",
    ),
    1521: ServiceProfile(
        port=1521,
        service="Oracle Database",
        severity=Severity.HIGH,
        description="Oracle database listener port is exposed.",
        recommendation="Restrict database listener access and monitor authentication attempts.",
    ),
    3306: ServiceProfile(
        port=3306,
        service="MySQL/MariaDB",
        severity=Severity.HIGH,
        description="MySQL/MariaDB port is exposed.",
        recommendation="Restrict database access to trusted application servers and internal networks.",
    ),
    3389: ServiceProfile(
        port=3389,
        service="RDP",
        severity=Severity.HIGH,
        description="RDP service is exposed. RDP is commonly targeted for brute force and lateral movement.",
        recommendation="Restrict RDP through VPN, bastion hosts, firewall rules and MFA.",
    ),
    5432: ServiceProfile(
        port=5432,
        service="PostgreSQL",
        severity=Severity.HIGH,
        description="PostgreSQL port is exposed.",
        recommendation="Restrict database access and require strong authentication.",
    ),
    6379: ServiceProfile(
        port=6379,
        service="Redis",
        severity=Severity.CRITICAL,
        description="Redis service is exposed. Exposed Redis instances can lead to severe compromise.",
        recommendation="Bind Redis to localhost/internal interfaces and enforce authentication.",
    ),
    9200: ServiceProfile(
        port=9200,
        service="Elasticsearch",
        severity=Severity.CRITICAL,
        description="Elasticsearch service is exposed. Exposed clusters may leak sensitive data.",
        recommendation="Restrict access, enable authentication and avoid public exposure.",
    ),
}


def get_service_profile(port: int) -> ServiceProfile:
    return SERVICE_PROFILES.get(
        port,
        ServiceProfile(
            port=port,
            service="Unknown",
            severity=Severity.LOW,
            description="An open TCP port was detected.",
            recommendation="Verify whether this service is required and restrict access if unnecessary.",
        ),
    )


def parse_ports(ports: str) -> list[int]:
    if ports.lower() == "common":
        return COMMON_PORTS

    parsed_ports: list[int] = []

    for item in ports.split(","):
        item = item.strip()

        if not item:
            continue

        if "-" in item:
            start_text, end_text = item.split("-", maxsplit=1)
            start = int(start_text)
            end = int(end_text)

            if start > end:
                raise ValueError(f"Invalid port range: {item}")

            parsed_ports.extend(range(start, end + 1))
        else:
            parsed_ports.append(int(item))

    unique_ports = sorted(set(parsed_ports))

    for port in unique_ports:
        if port < 1 or port > 65535:
            raise ValueError(f"Invalid TCP port: {port}")

    return unique_ports