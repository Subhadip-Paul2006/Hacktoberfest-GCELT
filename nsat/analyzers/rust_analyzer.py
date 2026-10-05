"""Rust structural syntax analyzer for NSAT."""

from pathlib import Path
import re
from typing import Any
from nsat.analyzers.base import LanguageAnalyzer
from nsat.core.models import (
    AuthIndicator,
    DatabaseComponent,
    EntryPoint,
    FrameworkEvidence,
    NetworkComponent,
    SecurityRelevantOperation,
)


class RustAnalyzer(LanguageAnalyzer):
    """
    Analyzes Rust source files using structural patterns.
    Functions completely independent of variable or function naming.
    """

    @property
    def language_name(self) -> str:
        return "rust"

    @property
    def supported_extensions(self) -> set[str]:
        return {".rs"}

    def detect(self, file_path: Path, content: str) -> float:
        if file_path.suffix.lower() in self.supported_extensions:
            return 1.0
        if re.search(r"\b(fn\s+main\s*\(\s*\)|use\s+std::|let\s+mut\s+)\b", content):
            return 0.85
        return 0.0

    def extract_structure(self, file_path: Path, content: str) -> dict[str, Any]:
        return {
            "frameworks": self.extract_frameworks(file_path, content),
            "entry_points": self.extract_entry_points(file_path, content),
            "network_operations": self.extract_network_operations(file_path, content),
            "database_components": self.extract_database_components(file_path, content),
            "auth_indicators": self.extract_auth_indicators(file_path, content),
            "security_operations": self.extract_security_operations(file_path, content),
        }

    def extract_frameworks(self, file_path: Path, content: str) -> list[FrameworkEvidence]:
        evidences: list[FrameworkEvidence] = []
        patterns = [
            ("Actix-web", r"""(?i)(use\s+actix_web\b|actix_web::|HttpServer::new)"""),
            ("Axum", r"""(?i)(use\s+axum\b|axum::Router)"""),
            ("Rocket", r"""(?i)(use\s+rocket\b|#\[(?:get|post|put|delete)\()"""),
            ("Tokio Async", r"""(?i)(#\[tokio::main\]|tokio::)"""),
            ("SQLx Database Toolkit", r"""(?i)(use\s+sqlx\b|sqlx::query)"""),
            ("Diesel ORM", r"""(?i)(use\s+diesel\b|diesel::)"""),
        ]

        for name, pattern in patterns:
            if re.search(pattern, content):
                evidences.append(
                    FrameworkEvidence(
                        name=name,
                        confidence=0.95,
                        matched_files=[str(file_path)],
                        evidence_type="use_statement_or_macro",
                    )
                )
        return evidences

    def extract_entry_points(self, file_path: Path, content: str) -> list[EntryPoint]:
        entries: list[EntryPoint] = []
        lines = content.splitlines()

        # 1. Main entry function: fn main()
        main_pattern = re.compile(r"""\b(?:async\s+)?fn\s+main\s*\([^)]*\)""")
        for idx, line in enumerate(lines, 1):
            if main_pattern.search(line):
                entries.append(
                    EntryPoint(
                        file_path=str(file_path),
                        line_number=idx,
                        entry_type="main",
                        signature=line.strip()[:50],
                    )
                )

        # 2. Rocket / Actix macro attributes: #[get("/path")], #[post("/path")]
        attr_pattern = re.compile(r"""#\[(get|post|put|delete|patch)\s*\(\s*(['"][^'"]+['"])""")
        for idx, line in enumerate(lines, 1):
            m = attr_pattern.search(line)
            if m:
                verb = m.group(1).upper()
                route = m.group(2).strip("'\"")
                entries.append(
                    EntryPoint(
                        file_path=str(file_path),
                        line_number=idx,
                        entry_type="http_route",
                        signature=f"#[{m.group(1)}({route})]",
                        details={"verb": verb, "route": route},
                    )
                )

        # 3. Axum/Actix route builder: .route("/path", ...)
        route_pattern = re.compile(r"""\.route\s*\(\s*(['"][^'"]+['"])""")
        for idx, line in enumerate(lines, 1):
            m = route_pattern.search(line)
            if m:
                route = m.group(1).strip("'\"")
                entries.append(
                    EntryPoint(
                        file_path=str(file_path),
                        line_number=idx,
                        entry_type="http_route",
                        signature=f".route({route})",
                        details={"route": route},
                    )
                )
        return entries

    def extract_network_operations(self, file_path: Path, content: str) -> list[NetworkComponent]:
        components: list[NetworkComponent] = []
        lines = content.splitlines()

        # TcpListener::bind or HttpServer::bind
        bind_pattern = re.compile(r"""\b(?:TcpListener|HttpServer::new\([^)]*\))\.bind\s*\(\s*(['"][^'"]+['"])""")
        for idx, line in enumerate(lines, 1):
            m = bind_pattern.search(line)
            if m:
                addr = m.group(1).strip("'\"")
                host = None
                port = None
                if ":" in addr:
                    host, port_str = addr.split(":", 1)
                    port = int(port_str) if port_str.isdigit() else None
                components.append(
                    NetworkComponent(
                        file_path=str(file_path),
                        line_number=idx,
                        component_type="http_listener" if "HttpServer" in line else "socket_bind",
                        host=host or ("0.0.0.0" if "0.0.0.0" in addr else "127.0.0.1"),
                        port=port,
                        protocol="tcp",
                        details={"address": addr},
                    )
                )
        return components

    def extract_database_components(self, file_path: Path, content: str) -> list[DatabaseComponent]:
        components: list[DatabaseComponent] = []
        lines = content.splitlines()

        db_pattern = re.compile(r"""\b(sqlx::query(?:_as)?|diesel::insert_into|diesel::select|PgPool::connect|MySqlPool::connect)\b""")
        for idx, line in enumerate(lines, 1):
            m = db_pattern.search(line)
            if m:
                components.append(
                    DatabaseComponent(
                        file_path=str(file_path),
                        line_number=idx,
                        db_type="rust_db_driver",
                        operation=m.group(1),
                    )
                )
        return components

    def extract_auth_indicators(self, file_path: Path, content: str) -> list[AuthIndicator]:
        indicators: list[AuthIndicator] = []
        lines = content.splitlines()

        auth_pattern = re.compile(r"""\b(argon2::|bcrypt::|jsonwebtoken::|oauth2::)\b""")
        for idx, line in enumerate(lines, 1):
            m = auth_pattern.search(line)
            if m:
                indicators.append(
                    AuthIndicator(
                        file_path=str(file_path),
                        line_number=idx,
                        indicator_type="crypto_or_auth_crate",
                        details={"call": m.group(1)},
                    )
                )
        return indicators

    def extract_security_operations(self, file_path: Path, content: str) -> list[SecurityRelevantOperation]:
        ops: list[SecurityRelevantOperation] = []
        lines = content.splitlines()

        # Command execution: Command::new(...)
        cmd_pattern = re.compile(r"""\bCommand::new\s*\(\s*(['"][^'"]+['"]|[a-zA-Z0-9_]+)""")
        for idx, line in enumerate(lines, 1):
            m = cmd_pattern.search(line)
            if m:
                ops.append(
                    SecurityRelevantOperation(
                        file_path=str(file_path),
                        line_number=idx,
                        operation_type="process_execution",
                        sink_category="command_injection",
                        snippet=line.strip()[:80],
                    )
                )

        # Unsafe blocks
        unsafe_pattern = re.compile(r"""\bunsafe\s*\{""")
        for idx, line in enumerate(lines, 1):
            if unsafe_pattern.search(line):
                ops.append(
                    SecurityRelevantOperation(
                        file_path=str(file_path),
                        line_number=idx,
                        operation_type="memory_unsafe_block",
                        sink_category="memory_safety",
                        snippet=line.strip()[:80],
                    )
                )
        return ops
