"""Go structural syntax analyzer for NSAT."""

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


class GoAnalyzer(LanguageAnalyzer):
    """
    Analyzes Go source files using structural patterns and standard library conventions.
    Functions completely independent of variable or function naming.
    """

    @property
    def language_name(self) -> str:
        return "go"

    @property
    def supported_extensions(self) -> set[str]:
        return {".go"}

    def detect(self, file_path: Path, content: str) -> float:
        if file_path.suffix.lower() in self.supported_extensions:
            return 1.0
        if re.search(r"\b(package\s+[a-zA-Z0-9_]+|func\s+main\s*\(\s*\))\b", content):
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
            ("Gin Web Framework", r"""(?i)("github\.com/gin-gonic/gin"|gin\.Default|gin\.New)"""),
            ("Echo Web Framework", r"""(?i)("github\.com/labstack/echo|echo\.New)"""),
            ("Fiber Web Framework", r"""(?i)("github\.com/gofiber/fiber|fiber\.New)"""),
            ("Chi Router", r"""(?i)("github\.com/go-chi/chi|chi\.NewRouter)"""),
            ("GORM", r"""(?i)("gorm\.io/gorm"|gorm\.Open)"""),
        ]

        for name, pattern in patterns:
            if re.search(pattern, content):
                evidences.append(
                    FrameworkEvidence(
                        name=name,
                        confidence=0.95,
                        matched_files=[str(file_path)],
                        evidence_type="import_or_call",
                    )
                )
        return evidences

    def extract_entry_points(self, file_path: Path, content: str) -> list[EntryPoint]:
        entries: list[EntryPoint] = []
        lines = content.splitlines()

        # 1. Main entry function: func main()
        main_pattern = re.compile(r"""\bfunc\s+main\s*\(\s*\)""")
        for idx, line in enumerate(lines, 1):
            if main_pattern.search(line):
                entries.append(
                    EntryPoint(
                        file_path=str(file_path),
                        line_number=idx,
                        entry_type="main",
                        signature="func main()",
                    )
                )

        # 2. HTTP route handlers: r.GET("/path", ...), http.HandleFunc("/path", ...)
        route_pattern = re.compile(
            r"""\b(?:r|router|app|e|mux|http)\.(GET|POST|PUT|DELETE|PATCH|HandleFunc|Handle)\s*\(\s*(['"][^'"]+['"])""",
            re.IGNORECASE,
        )
        for idx, line in enumerate(lines, 1):
            m = route_pattern.search(line)
            if m:
                verb = m.group(1).upper()
                route = m.group(2).strip("'\"")
                entries.append(
                    EntryPoint(
                        file_path=str(file_path),
                        line_number=idx,
                        entry_type="http_route",
                        signature=f"{verb} {route}",
                        details={"verb": verb, "route": route},
                    )
                )
        return entries

    def extract_network_operations(self, file_path: Path, content: str) -> list[NetworkComponent]:
        components: list[NetworkComponent] = []
        lines = content.splitlines()

        # http.ListenAndServe(":8080", nil) or net.Listen("tcp", "0.0.0.0:8080")
        listen_pattern = re.compile(r"""\b(?:http\.ListenAndServe|net\.Listen)\s*\(\s*(?:['"]tcp['"]\s*,\s*)?(['"][^'"]+['"])""")
        for idx, line in enumerate(lines, 1):
            m = listen_pattern.search(line)
            if m:
                addr = m.group(1).strip("'\"")
                host = None
                port = None
                if ":" in addr:
                    parts = addr.split(":", 1)
                    host = parts[0] or "0.0.0.0"
                    port = int(parts[1]) if parts[1].isdigit() else None
                components.append(
                    NetworkComponent(
                        file_path=str(file_path),
                        line_number=idx,
                        component_type="http_listener",
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

        db_pattern = re.compile(r"""\b(sql\.Open|db\.Query|db\.Exec|db\.QueryRow|gorm\.Open)\b""")
        for idx, line in enumerate(lines, 1):
            m = db_pattern.search(line)
            if m:
                components.append(
                    DatabaseComponent(
                        file_path=str(file_path),
                        line_number=idx,
                        db_type="go_sql_driver",
                        operation=m.group(1),
                    )
                )
        return components

    def extract_auth_indicators(self, file_path: Path, content: str) -> list[AuthIndicator]:
        indicators: list[AuthIndicator] = []
        lines = content.splitlines()

        auth_pattern = re.compile(r"""\b(bcrypt\.GenerateFromPassword|bcrypt\.CompareHashAndPassword|jwt\.Parse|jwt\.NewWithClaims)\b""")
        for idx, line in enumerate(lines, 1):
            m = auth_pattern.search(line)
            if m:
                indicators.append(
                    AuthIndicator(
                        file_path=str(file_path),
                        line_number=idx,
                        indicator_type="crypto_or_jwt_auth",
                        details={"call": m.group(1)},
                    )
                )
        return indicators

    def extract_security_operations(self, file_path: Path, content: str) -> list[SecurityRelevantOperation]:
        ops: list[SecurityRelevantOperation] = []
        lines = content.splitlines()

        # Command execution: exec.Command(...)
        cmd_pattern = re.compile(r"""\bexec\.Command\s*\(\s*(['"][^'"]+['"]|[a-zA-Z0-9_]+)""")
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
        return ops
