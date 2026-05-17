from sec_assess.core.finding import Finding
from sec_assess.modules.host_exposure.banner_grab import grab_banner
from sec_assess.modules.host_exposure.port_scan import scan_tcp_ports
from sec_assess.modules.host_exposure.service_detection import (
    get_service_profile,
    parse_ports,
)


class HostExposureScanner:
    def __init__(
        self,
        timeout: float = 1.0,
        banner_timeout: float = 2.0,
        enable_banner_grab: bool = True,
    ):
        self.timeout = timeout
        self.banner_timeout = banner_timeout
        self.enable_banner_grab = enable_banner_grab

    def scan(self, target: str, ports: str = "common") -> list[Finding]:
        selected_ports = parse_ports(ports)
        scan_results = scan_tcp_ports(
            target=target,
            ports=selected_ports,
            timeout=self.timeout,
        )

        findings: list[Finding] = []

        for result in scan_results:
            if not result.is_open:
                continue

            profile = get_service_profile(result.port)
            banner = ""

            if self.enable_banner_grab:
                banner = grab_banner(
                    target=target,
                    port=result.port,
                    timeout=self.banner_timeout,
                )

            evidence = f"Open TCP port detected: {result.port}/{profile.service}"

            if banner:
                evidence += f"\n\nBanner:\n{banner[:500]}"

            findings.append(
                Finding(
                    id=f"HOST-PORT-{result.port}",
                    title=f"Open {profile.service} service detected on port {result.port}",
                    severity=profile.severity,
                    category="Host Exposure",
                    description=profile.description,
                    evidence=evidence,
                    recommendation=profile.recommendation,
                    target=target,
                    framework="MITRE ATT&CK",
                    mitre_tactic="Discovery",
                    mitre_technique="T1046 - Network Service Discovery",
                    metadata={
                        "port": result.port,
                        "service": profile.service,
                        "banner": banner,
                    },
                )
            )

        return findings