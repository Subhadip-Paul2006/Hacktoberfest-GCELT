"""Java structural syntax analyzer for NSAT."""

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


class JavaAnalyzer(LanguageAnalyzer):
    """
    Analyzes Java source files using structural patterns and annotations.
    Functions completely independent of class, method, or variable naming.
    """

    @property
    def language_name(self) -> str:
        return "java"

    @property
    def supported_extensions(self) -> set[str]:
        return {".java", ".jsp", ".jspx"}

    def detect(self, file_path: Path, content: str) -> float:
        if file_path.suffix.lower() in self.supported_extensions:
            return 1.0
        if re.search(r"\b(public\s+class\s+[A-Za-z0-9_]+|package\s+[a-z0-9_.]+;)\b", content):
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
            ("Spring Boot", r"""(?i)(@SpringBootApplication\b|org\.springframework\.boot)"""),
            ("Spring MVC", r"""(?i)(@RestController\b|@Controller\b|@RequestMapping\b)"""),
            ("Jakarta / Java EE", r"""(?i)(extends\s+HttpServlet\b|@WebServlet\b|jakarta\.servlet|javax\.servlet)"""),
            ("Hibernate / JPA", r"""(?i)(@Entity\b|@Table\b|jakarta\.persistence|javax\.persistence)"""),
        ]

        for name, pattern in patterns:
            if re.search(pattern, content):
                evidences.append(
                    FrameworkEvidence(
                        name=name,
                        confidence=0.95,
                        matched_files=[str(file_path)],
                        evidence_type="annotation_or_import",
                    )
                )
        return evidences

    def extract_entry_points(self, file_path: Path, content: str) -> list[EntryPoint]:
        entries: list[EntryPoint] = []
        lines = content.splitlines()

        # 1. Main method
        main_pattern = re.compile(r"""public\s+static\s+void\s+main\s*\(\s*String\s*(?:\[\s*\]|\.\.\.)""")
        for idx, line in enumerate(lines, 1):
            if main_pattern.search(line):
                entries.append(
                    EntryPoint(
                        file_path=str(file_path),
                        line_number=idx,
                        entry_type="main",
                        signature="public static void main(String[] args)",
                    )
                )

        # 2. Spring Mapping annotations (e.g. @GetMapping("/items"), @PostMapping)
        mapping_pattern = re.compile(r"""@(Get|Post|Put|Delete|Patch|Request)Mapping\s*(?:\(\s*(?:value\s*=\s*)?(['"][^'"]+['"]))?""")
        for idx, line in enumerate(lines, 1):
            m = mapping_pattern.search(line)
            if m:
                verb = m.group(1).upper()
                route = m.group(2).strip("'\"") if m.group(2) else "/"
                entries.append(
                    EntryPoint(
                        file_path=str(file_path),
                        line_number=idx,
                        entry_type="http_route",
                        signature=f"@{verb}Mapping({route})",
                        details={"verb": verb, "route": route},
                    )
                )
        return entries

    def extract_network_operations(self, file_path: Path, content: str) -> list[NetworkComponent]:
        components: list[NetworkComponent] = []
        lines = content.splitlines()

        # Server socket listener
        socket_pattern = re.compile(r"""new\s+ServerSocket\s*\(\s*(\d+)""")
        for idx, line in enumerate(lines, 1):
            m = socket_pattern.search(line)
            if m:
                components.append(
                    NetworkComponent(
                        file_path=str(file_path),
                        line_number=idx,
                        component_type="socket_bind",
                        port=int(m.group(1)),
                        protocol="tcp",
                    )
                )
        return components

    def extract_database_components(self, file_path: Path, content: str) -> list[DatabaseComponent]:
        components: list[DatabaseComponent] = []
        lines = content.splitlines()

        db_pattern = re.compile(r"""\b(createStatement|prepareStatement|executeQuery|executeUpdate|createQuery)\b""")
        for idx, line in enumerate(lines, 1):
            m = db_pattern.search(line)
            if m:
                components.append(
                    DatabaseComponent(
                        file_path=str(file_path),
                        line_number=idx,
                        db_type="jdbc_or_jpa",
                        operation=m.group(1),
                    )
                )
        return components

    def extract_auth_indicators(self, file_path: Path, content: str) -> list[AuthIndicator]:
        indicators: list[AuthIndicator] = []
        lines = content.splitlines()

        auth_pattern = re.compile(r"""\b(@PreAuthorize|@Secured|BCryptPasswordEncoder|SecurityFilterChain)\b""")
        for idx, line in enumerate(lines, 1):
            m = auth_pattern.search(line)
            if m:
                indicators.append(
                    AuthIndicator(
                        file_path=str(file_path),
                        line_number=idx,
                        indicator_type="spring_security_control",
                        details={"control": m.group(1)},
                    )
                )
        return indicators

    def extract_security_operations(self, file_path: Path, content: str) -> list[SecurityRelevantOperation]:
        ops: list[SecurityRelevantOperation] = []
        lines = content.splitlines()

        danger_patterns = [
            ("process_execution", "command_injection", re.compile(r"""Runtime\.getRuntime\(\)\.exec|new\s+ProcessBuilder""")),
            ("insecure_hash", "weak_cryptography", re.compile(r"""MessageDigest\.getInstance\s*\(\s*["'](MD5|SHA-1)["']""")),
            ("deserialization", "unsafe_deserialization", re.compile(r"""new\s+ObjectInputStream\b""")),
        ]

        for idx, line in enumerate(lines, 1):
            for op_type, sink_cat, pat in danger_patterns:
                if pat.search(line):
                    ops.append(
                        SecurityRelevantOperation(
                            file_path=str(file_path),
                            line_number=idx,
                            operation_type=op_type,
                            sink_category=sink_cat,
                            snippet=line.strip()[:80],
                        )
                    )
        return ops
