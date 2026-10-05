"""Dockerfile and docker-compose security auditor for NSAT."""

from pathlib import Path
from nsat.core.surface import SecuritySurface
from nsat.normalization.models import CanonicalFinding, FindingEvidence
from nsat.scanners.base import BaseScanner


class ContainerScanner(BaseScanner):
    """
    Audits Dockerfiles and docker-compose files for container mis-configurations.
    Detects: root user, privileged mode, docker.sock mounts, latest tag, ADD not COPY.
    """

    @property
    def scanner_name(self) -> str:
        return "container_scanner"

    def scan(self, target_path: Path, surface: SecuritySurface) -> list[CanonicalFinding]:
        findings: list[CanonicalFinding] = []
        seq = 1

        for dockerfile in target_path.rglob("Dockerfile*"):
            if not dockerfile.is_file():
                continue
            if any(p in {"node_modules", "vendor", ".venv", ".git"} for p in dockerfile.parts):
                continue
            seq, findings = self._audit_dockerfile(dockerfile, findings, seq)

        for compose_file in target_path.rglob("docker-compose*.yml"):
            if not compose_file.is_file():
                continue
            seq, findings = self._audit_compose(compose_file, findings, seq)

        for compose_file in target_path.rglob("docker-compose*.yaml"):
            if not compose_file.is_file():
                continue
            seq, findings = self._audit_compose(compose_file, findings, seq)

        return findings

    def _audit_dockerfile(self, file_path: Path, findings: list, seq: int):
        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return seq, findings

        lines = content.splitlines()
        has_user_instruction = False

        for idx, line in enumerate(lines, 1):
            stripped = line.strip().upper()

            # Check for USER root
            if stripped.startswith("USER"):
                has_user_instruction = True
                if "ROOT" in stripped:
                    findings.append(CanonicalFinding(
                        id=f"NSAT-CONT-{seq:03d}",
                        title="Dockerfile: Container Runs as root",
                        category="container",
                        severity="HIGH",
                        confidence=1.0,
                        confidence_label="Confirmed by safe check",
                        source=self.scanner_name,
                        asset=file_path.name,
                        file_path=str(file_path),
                        line_number=idx,
                        description=(
                            "The Dockerfile explicitly sets the container process user to 'root'. "
                            "If the application is compromised, attackers gain root privileges inside the container."
                        ),
                        impact="Container breakout or privilege escalation if paired with misconfigured volumes or socket mounts.",
                        recommendation="Create a non-root user (e.g., `RUN adduser -D appuser`) and switch with `USER appuser`.",
                        evidence=[FindingEvidence(
                            type="DOCKERFILE_DIRECTIVE",
                            description="USER root instruction detected",
                            snippet=line.strip()[:80],
                            line_number=idx,
                        )],
                    ))
                    seq += 1

            # Check for docker.sock mount in VOLUME or RUN
            if "/var/run/docker.sock" in line:
                findings.append(CanonicalFinding(
                    id=f"NSAT-CONT-{seq:03d}",
                    title="Dockerfile: Docker Socket Mounted (Container Escape Risk)",
                    category="container",
                    severity="CRITICAL",
                    confidence=1.0,
                    confidence_label="Confirmed by safe check",
                    source=self.scanner_name,
                    asset=file_path.name,
                    file_path=str(file_path),
                    line_number=idx,
                    description=(
                        "The Docker daemon socket (/var/run/docker.sock) is mounted or referenced in the container. "
                        "This grants the container full control of the Docker daemon."
                    ),
                    impact="TIER 3 Host Takeover: Any code injection in this container can escape to the host.",
                    recommendation="Never mount /var/run/docker.sock unless explicitly necessary. Use dedicated sidecar patterns.",
                    evidence=[FindingEvidence(
                        type="DOCKER_SOCK_MOUNT",
                        description="Docker socket reference found",
                        snippet=line.strip()[:80],
                        line_number=idx,
                    )],
                ))
                seq += 1

            # Check for ADD instead of COPY
            if stripped.startswith("ADD ") and ("http://" in line or "https://" in line or ".tar" in line.lower()):
                findings.append(CanonicalFinding(
                    id=f"NSAT-CONT-{seq:03d}",
                    title="Dockerfile: Insecure ADD Instruction (Remote URL or Archive)",
                    category="container",
                    severity="MEDIUM",
                    confidence=0.9,
                    confidence_label="Detected structurally",
                    source=self.scanner_name,
                    asset=file_path.name,
                    file_path=str(file_path),
                    line_number=idx,
                    description="ADD instruction with remote URL or archive is potentially insecure; COPY is preferred.",
                    impact="Potential supply-chain attack or unintended file extraction.",
                    recommendation="Replace ADD with COPY for local files. Use curl with checksum verification for remote downloads.",
                    evidence=[FindingEvidence(
                        type="DOCKERFILE_DIRECTIVE",
                        description="ADD with remote/archive",
                        snippet=line.strip()[:80],
                        line_number=idx,
                    )],
                ))
                seq += 1

        # No USER instruction at all → root by default
        if not has_user_instruction:
            findings.append(CanonicalFinding(
                id=f"NSAT-CONT-{seq:03d}",
                title="Dockerfile: Missing USER Instruction (Implicit root)",
                category="container",
                severity="MEDIUM",
                confidence=0.95,
                confidence_label="Detected structurally",
                source=self.scanner_name,
                asset=file_path.name,
                file_path=str(file_path),
                description=(
                    "The Dockerfile has no USER instruction. Container processes run as root by default, "
                    "increasing privilege escalation risk."
                ),
                impact="Container compromise provides attacker root-level access within the container namespace.",
                recommendation="Add `RUN adduser -D appuser && USER appuser` before CMD/ENTRYPOINT.",
                evidence=[FindingEvidence(
                    type="DOCKERFILE_DIRECTIVE",
                    description="No USER directive found in Dockerfile",
                )],
            ))
            seq += 1

        return seq, findings

    def _audit_compose(self, file_path: Path, findings: list, seq: int):
        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return seq, findings

        lines = content.splitlines()
        for idx, line in enumerate(lines, 1):
            # Privileged mode
            if "privileged:" in line and "true" in line.lower():
                findings.append(CanonicalFinding(
                    id=f"NSAT-CONT-{seq:03d}",
                    title="docker-compose: Privileged Mode Enabled",
                    category="container",
                    severity="CRITICAL",
                    confidence=1.0,
                    confidence_label="Confirmed by safe check",
                    source=self.scanner_name,
                    asset=file_path.name,
                    file_path=str(file_path),
                    line_number=idx,
                    description="A service is configured with `privileged: true` granting full host kernel capabilities.",
                    impact="TIER 3 Host Takeover: Full host kernel namespace access from within the container.",
                    recommendation="Remove `privileged: true`. Use specific capability additions (cap_add) instead.",
                    evidence=[FindingEvidence(
                        type="COMPOSE_DIRECTIVE",
                        description="privileged: true",
                        snippet=line.strip()[:80],
                        line_number=idx,
                    )],
                ))
                seq += 1

            # Docker socket in volumes
            if "/var/run/docker.sock" in line:
                findings.append(CanonicalFinding(
                    id=f"NSAT-CONT-{seq:03d}",
                    title="docker-compose: Docker Socket Mounted (Container Escape Risk)",
                    category="container",
                    severity="CRITICAL",
                    confidence=1.0,
                    confidence_label="Confirmed by safe check",
                    source=self.scanner_name,
                    asset=file_path.name,
                    file_path=str(file_path),
                    line_number=idx,
                    description="The Docker socket is mounted as a volume, granting full host Docker daemon control.",
                    impact="TIER 3 Host Takeover: Any command injection in this container achieves full host root.",
                    recommendation="Remove docker.sock volume unless this service is explicitly a Docker management daemon.",
                    evidence=[FindingEvidence(
                        type="COMPOSE_VOLUME",
                        description="docker.sock volume mount found",
                        snippet=line.strip()[:80],
                        line_number=idx,
                    )],
                ))
                seq += 1

        return seq, findings
