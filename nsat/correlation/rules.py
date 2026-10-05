"""Deterministic Correlation Rule Engine and Attack Path Generator for NSAT."""

from typing import Optional

from nsat.core.surface import SecuritySurface
from nsat.correlation.models import (
    AttackPath,
    FindingRelationship,
    RelationshipType,
)
from nsat.normalization.models import CanonicalFinding


class CorrelationRuleEngine:
    """
    Deterministic cross-domain correlation engine.
    Identifies evidence-based relationships between findings and synthesizes multi-hop attack paths.
    """

    @classmethod
    def correlate(
        cls,
        findings: list[CanonicalFinding],
        surface: Optional[SecuritySurface] = None,
    ) -> tuple[list[FindingRelationship], list[AttackPath]]:
        """
        Execute deterministic correlation rules.
        Returns:
            (relationships, attack_paths)
        """
        relationships: list[FindingRelationship] = []
        attack_paths: list[AttackPath] = []
        path_counter = 1

        # Index findings by id and characteristics
        f_by_id = {f.id: f for f in findings}

        # Helper category / title matchers
        sqli_findings = [f for f in findings if "sql" in f.title.lower() or "sqli" in f.id.lower()]
        cmdi_findings = [f for f in findings if ("command" in f.title.lower() or "shell" in f.title.lower() or "rce" in f.title.lower()) and "injection" in f.title.lower()]
        secret_findings = [f for f in findings if f.category == "secret"]
        db_secrets = [f for f in secret_findings if "db" in f.title.lower() or "password" in f.title.lower() or "database" in f.title.lower()]
        docker_findings = [f for f in findings if f.category == "container" or "docker" in f.title.lower() or "root" in f.title.lower()]
        docker_sock_findings = [f for f in findings if "docker.sock" in f.title.lower() or "docker.sock" in f.description.lower()]
        rate_limit_findings = [f for f in findings if "rate limit" in f.title.lower()]
        url_leak_findings = [f for f in findings if "url" in f.title.lower() or "otp" in f.title.lower() or "token in url" in f.title.lower()]
        auth_findings = [f for f in findings if f.category == "authentication" or "admin" in f.title.lower() or "auth" in f.title.lower()]
        client_trust_findings = [f for f in findings if "client" in f.title.lower() or "price" in f.title.lower()]
        order_findings = [f for f in findings if "order" in f.title.lower() or "state transition" in f.title.lower() or "payment" in f.title.lower()]
        debug_findings = [f for f in findings if "debug" in f.title.lower() or "dump" in f.title.lower()]
        stack_findings = [f for f in findings if "stack trace" in f.title.lower() or "error" in f.title.lower() or "crash" in f.title.lower()]
        cookie_findings = [f for f in findings if "cookie" in f.title.lower()]
        network_findings = [f for f in findings if f.category == "network_exposure" or "binding" in f.title.lower()]

        # -------------------------------------------------------------
        # Rule CR-01: Exposed DB Port / Binding + Leaked DB Secret + SQLi
        # -------------------------------------------------------------
        if sqli_findings and (db_secrets or secret_findings):
            sqli = sqli_findings[0]
            sec = db_secrets[0] if db_secrets else secret_findings[0]

            relationships.append(
                FindingRelationship(
                    source_id=sec.id,
                    target_id=sqli.id,
                    relation_type=RelationshipType.CONTRIBUTES_TO,
                    reason="Leaked database credential provides direct access and persistence alongside SQL injection.",
                )
            )

            is_validated = any(f.status == "VALIDATED" for f in [sqli, sec])
            ptype = "Validated exposure path" if is_validated else "Potential attack path"

            attack_paths.append(
                AttackPath(
                    id=f"AP-{path_counter:02d}",
                    title="Direct Database Compromise & Credential Pivot",
                    path_type=ptype,
                    severity="CRITICAL",
                    confidence=0.92 if is_validated else 0.85,
                    steps=[
                        "External / LAN Reachable Network Interface (0.0.0.0)",
                        f"Vulnerable SQL Query Handler ({sqli.file_path or 'API'}:{sqli.line_number or ''})",
                        f"Exposed Database Credentials in Environment ({sec.asset})",
                        "Post-Compromise Database Access & Exfiltration",
                    ],
                    involved_finding_ids=[sqli.id, sec.id] + ([nf.id for nf in network_findings] if network_findings else []),
                    impact="Remote unauthenticated attackers can execute arbitrary SQL queries and leverage leaked database credentials for complete database takeover.",
                    recommendation="Convert SQL queries to parameterized statements and rotate compromised credentials out of source repositories.",
                )
            )
            path_counter += 1

        # -------------------------------------------------------------
        # Rule CR-02: Container Breakout to Host Takeover (Docker Sock + Command Injection)
        # -------------------------------------------------------------
        if (docker_sock_findings or docker_findings) and cmdi_findings:
            cmdi = cmdi_findings[0]
            dock = docker_sock_findings[0] if docker_sock_findings else docker_findings[0]

            relationships.append(
                FindingRelationship(
                    source_id=dock.id,
                    target_id=cmdi.id,
                    relation_type=RelationshipType.AMPLIFIES,
                    reason="Mounted host Docker socket allows arbitrary command execution to escape container isolation to host root.",
                )
            )
            relationships.append(
                FindingRelationship(
                    source_id=cmdi.id,
                    target_id=dock.id,
                    relation_type=RelationshipType.CONTRIBUTES_TO,
                    reason="Command injection provides interactive execution context needed to invoke the Docker API socket.",
                )
            )

            is_validated = any(f.status == "VALIDATED" for f in [cmdi, dock])
            attack_paths.append(
                AttackPath(
                    id=f"AP-{path_counter:02d}",
                    title="Container Breakout to Host Root via Docker Socket",
                    path_type="Post-compromise path",
                    severity="CRITICAL",
                    confidence=0.95 if is_validated else 0.90,
                    steps=[
                        "Compromised Application Process (Shell Execution Sink)",
                        f"Arbitrary Command Injection in {cmdi.file_path or 'Worker'}",
                        f"Accessible Host Docker Daemon Socket ({dock.asset})",
                        "Spawn Privileged Container & Host Root Takeover",
                    ],
                    involved_finding_ids=[cmdi.id, dock.id],
                    impact="Attacker executes commands inside container, mounts root filesystem via Docker socket, and assumes full host root control.",
                    recommendation="Remove /var/run/docker.sock mount from container specification and sanitize subprocess command invocations.",
                )
            )
            path_counter += 1

        # -------------------------------------------------------------
        # Rule CR-03: Authentication Information Leakage & Credential Harvest
        # -------------------------------------------------------------
        if url_leak_findings and rate_limit_findings:
            url_f = url_leak_findings[0]
            rl_f = rate_limit_findings[0]

            relationships.append(
                FindingRelationship(
                    source_id=rl_f.id,
                    target_id=url_f.id,
                    relation_type=RelationshipType.AMPLIFIES,
                    reason="Missing rate limiting on authentication allows automated harvesting and brute-forcing of URL-exposed credentials.",
                )
            )
            relationships.append(
                FindingRelationship(
                    source_id=url_f.id,
                    target_id=rl_f.id,
                    relation_type=RelationshipType.RELATED,
                    reason="Both weaknesses affect the authentication perimeter, reducing credential secrecy and brute-force resistance.",
                )
            )

            is_validated = any(f.status == "VALIDATED" for f in [url_f, rl_f])
            attack_paths.append(
                AttackPath(
                    id=f"AP-{path_counter:02d}",
                    title="Authentication Credential Harvesting & Brute-Force Exposure",
                    path_type="Validated exposure path" if is_validated else "Potential attack path",
                    severity="HIGH",
                    confidence=0.88 if is_validated else 0.80,
                    steps=[
                        "Authentication Endpoint Without Rate Limiting",
                        f"Sensitive Token / OTP Transmitted in URL ({url_f.file_path or 'API'})",
                        "Telemetry, Proxy Logs, and Browser History Leakage",
                        "Unthrottled Automated Credential Reuse / Replay",
                    ],
                    involved_finding_ids=[url_f.id, rl_f.id],
                    impact="Authentication credentials and one-time passwords leak into server logs and can be replayed or brute-forced without throttling.",
                    recommendation="Transmit authentication credentials via secure POST request bodies and enforce IP rate limiting middleware.",
                )
            )
            path_counter += 1

        # -------------------------------------------------------------
        # Rule CR-04: Business Logic & Payment Fraud Chain
        # -------------------------------------------------------------
        if client_trust_findings and order_findings:
            ct_f = client_trust_findings[0]
            ord_f = order_findings[0]

            relationships.append(
                FindingRelationship(
                    source_id=ct_f.id,
                    target_id=ord_f.id,
                    relation_type=RelationshipType.CONTRIBUTES_TO,
                    reason="Client-supplied price and unverified payment status directly feed into automated order confirmation logic.",
                )
            )
            relationships.append(
                FindingRelationship(
                    source_id=ord_f.id,
                    target_id=ct_f.id,
                    relation_type=RelationshipType.AMPLIFIES,
                    reason="Premature state transition amplifies risk of client-trusted financial parameters.",
                )
            )

            is_validated = any(f.status == "VALIDATED" for f in [ct_f, ord_f])
            attack_paths.append(
                AttackPath(
                    id=f"AP-{path_counter:02d}",
                    title="Client-Controlled Financial Parameters to Fraudulent Order Execution",
                    path_type="Validated exposure path" if is_validated else "Potential attack path",
                    severity="HIGH",
                    confidence=0.90 if is_validated else 0.82,
                    steps=[
                        "Client Checkout Request with Manipulated Price or Status",
                        f"Client-Trusted Price Parameter in {ct_f.file_path or 'Handlers'}",
                        f"Premature Order Confirmation in {ord_f.file_path or 'API'}",
                        "Fulfillment of Orders Without Valid Financial Transaction",
                    ],
                    involved_finding_ids=[ct_f.id, ord_f.id],
                    impact="Attackers can purchase items at arbitrary prices or finalize orders without verified payment gateway callbacks.",
                    recommendation="Enforce strict server-side price lookups and require cryptographic webhook validation before transitioning order state.",
                )
            )
            path_counter += 1

        # -------------------------------------------------------------
        # Rule CR-05: Information Leakage & Debug Exposure Chain
        # -------------------------------------------------------------
        if debug_findings and stack_findings:
            dbg_f = debug_findings[0]
            stk_f = stack_findings[0]

            relationships.append(
                FindingRelationship(
                    source_id=dbg_f.id,
                    target_id=stk_f.id,
                    relation_type=RelationshipType.AMPLIFIES,
                    reason="Active debug endpoints combined with verbose stack traces enable precise application reconnaissance.",
                )
            )

            attack_paths.append(
                AttackPath(
                    id=f"AP-{path_counter:02d}",
                    title="Internal Runtime State Disclosure via Debug Endpoint & Stack Traces",
                    path_type="Potential attack path",
                    severity="MEDIUM",
                    confidence=0.85,
                    steps=[
                        "Unauthenticated Public Endpoint Access",
                        f"Active Debug Mode / Dump Endpoint in {dbg_f.file_path or 'API'}",
                        f"Unhandled Exception with Stack Trace Leakage ({stk_f.file_path or 'Crash Handler'})",
                        "Source File Paths and Database Configuration Reconnaissance",
                    ],
                    involved_finding_ids=[dbg_f.id, stk_f.id],
                    impact="Internal database paths, source file structures, and library versions are revealed to external actors.",
                    recommendation="Disable DEBUG flags in production builds and implement generic error response middleware.",
                )
            )
            path_counter += 1

        # -------------------------------------------------------------
        # Rule CR-06: Insecure Session Cookie & Authentication Hijacking
        # -------------------------------------------------------------
        if cookie_findings and (auth_findings or rate_limit_findings):
            ck_f = cookie_findings[0]
            target_f = auth_findings[0] if auth_findings else rate_limit_findings[0]

            relationships.append(
                FindingRelationship(
                    source_id=ck_f.id,
                    target_id=target_f.id,
                    relation_type=RelationshipType.RELATED,
                    reason="Session cookie missing HttpOnly and Secure flags compromises authentication session confidentiality.",
                )
            )

        # -------------------------------------------------------------
        # Rule CR-07: Unauthenticated Admin Endpoint & Public Network Exposure
        # -------------------------------------------------------------
        unauth_admin = [f for f in findings if "admin" in f.title.lower() and "unauthenticated" in f.title.lower() or "admin dashboard" in f.title.lower()]
        if unauth_admin and network_findings:
            adm_f = unauth_admin[0]
            net_f = network_findings[0]

            relationships.append(
                FindingRelationship(
                    source_id=net_f.id,
                    target_id=adm_f.id,
                    relation_type=RelationshipType.AMPLIFIES,
                    reason="Wildcard network listener binds unauthenticated administrative endpoints to the public perimeter.",
                )
            )

            attack_paths.append(
                AttackPath(
                    id=f"AP-{path_counter:02d}",
                    title="Public Exposure of Unauthenticated Administrative Interface",
                    path_type="Validated exposure path" if adm_f.status == "VALIDATED" else "Potential attack path",
                    severity="HIGH",
                    confidence=0.92,
                    steps=[
                        "Network Service Bound to Wildcard Address (0.0.0.0)",
                        "External HTTP Request to Administrative Route",
                        f"Missing Authentication & Authorization Check in {adm_f.file_path or 'Admin Handler'}",
                        "Disclosure of Administrative Controls and System Metrics",
                    ],
                    involved_finding_ids=[adm_f.id, net_f.id],
                    impact="Unauthorized users can access internal administrative dashboards and trigger privileged operational procedures.",
                    recommendation="Enforce role-based access control (RBAC) middleware across all administrative endpoints.",
                )
            )
            path_counter += 1

        # -------------------------------------------------------------
        # Rule CR-08: Active Validation Verification Links
        # -------------------------------------------------------------
        for f in findings:
            if f.status in ("VALIDATED", "CONFIRMED_BY_SAFE_CHECK"):
                for ev in f.evidence:
                    if ev.type == "ACTIVE_VALIDATION":
                        relationships.append(
                            FindingRelationship(
                                source_id="active_swarm",
                                target_id=f.id,
                                relation_type=RelationshipType.VALIDATES,
                                reason=f"Phase 3 Active Validation probe confirmed vulnerability: {ev.description}",
                            )
                        )

        # Update findings' related_findings and attack_path attributes
        for rel in relationships:
            if rel.source_id in f_by_id and rel.target_id not in f_by_id[rel.source_id].related_findings:
                f_by_id[rel.source_id].related_findings.append(f"{rel.target_id} ({rel.relation_type.value})")
            if rel.target_id in f_by_id and rel.source_id not in f_by_id[rel.target_id].related_findings:
                f_by_id[rel.target_id].related_findings.append(f"{rel.source_id} ({rel.relation_type.value})")

        for ap in attack_paths:
            for fid in ap.involved_finding_ids:
                if fid in f_by_id and ap.title not in f_by_id[fid].attack_path:
                    f_by_id[fid].attack_path.append(ap.title)

        return relationships, attack_paths
