"""Safe network enumeration and socket exposure prober for NSAT."""

import asyncio
import ipaddress
from pathlib import Path
import socket
from typing import Optional
from nsat.core.surface import SecuritySurface
from nsat.normalization.models import CanonicalFinding, FindingEvidence
from nsat.scanners.base import BaseScanner

COMMON_AUDIT_PORTS = [21, 22, 25, 53, 80, 443, 3000, 3306, 5000, 5432, 6379, 8000, 8080, 9000, 27017]


async def probe_port(host: str, port: int, timeout: float = 0.5) -> Optional[int]:
    """Non-blocking, non-destructive TCP connect check."""
    try:
        conn = asyncio.open_connection(host, port)
        reader, writer = await asyncio.wait_for(conn, timeout=timeout)
        writer.close()
        await writer.wait_closed()
        return port
    except Exception:
        return None


class NetworkScanner(BaseScanner):
    """
    Defensive network prober that checks listening ports on authorized targets.
    Strictly non-destructive and bounded.
    """

    @property
    def scanner_name(self) -> str:
        return "network_prober"

    def scan(self, target_path: Path, surface: SecuritySurface) -> list[CanonicalFinding]:
        # Static surface binding findings are emitted via NativeSASTScanner
        return []

    async def scan_target_async(self, target_host: str, ports: list[int] | None = None) -> list[CanonicalFinding]:
        """Probe an explicitly authorized target IP or hostname for open listening services."""
        ports_to_check = ports or COMMON_AUDIT_PORTS
        findings: list[CanonicalFinding] = []

        tasks = [probe_port(target_host, p) for p in ports_to_check]
        results = await asyncio.gather(*tasks)
        open_ports = [p for p in results if p is not None]

        seq = 1
        for p in open_ports:
            sev = "HIGH" if p in [3306, 5432, 6379, 27017] else "MEDIUM"
            service_hint = {
                22: "SSH",
                80: "HTTP",
                443: "HTTPS",
                3000: "Node / React Dev Server",
                3306: "MySQL Database",
                5432: "PostgreSQL Database",
                6379: "Redis In-Memory Datastore",
                8000: "Web Application / API",
                8080: "HTTP Alternative / Spring",
                27017: "MongoDB",
            }.get(p, "TCP Service")

            findings.append(
                CanonicalFinding(
                    id=f"NSAT-NET-PORT-{seq:03d}",
                    title=f"Open Port Discovered: {p} ({service_hint})",
                    category="network_exposure",
                    severity=sev,
                    confidence=1.0,
                    confidence_label="Confirmed by safe check",
                    source=self.scanner_name,
                    asset=f"{target_host}:{p}",
                    port=p,
                    binding_address=target_host,
                    description=f"Port {p} ({service_hint}) is open and accepting TCP connections on {target_host}.",
                    impact="Reachable network service exposes internal attack surface if unauthenticated.",
                    recommendation="Ensure firewall rules restrict this port to authorized IP addresses.",
                    evidence=[
                        FindingEvidence(
                            type="NETWORK_PROBE",
                            description=f"TCP 3-way handshake established on {target_host}:{p}",
                        )
                    ],
                )
            )
            seq += 1

        return findings

    def scan_target(self, target_host: str, ports: list[int] | None = None) -> list[CanonicalFinding]:
        """Synchronous wrapper for scan_target_async."""
        try:
            return asyncio.run(self.scan_target_async(target_host, ports))
        except Exception:
            return []
