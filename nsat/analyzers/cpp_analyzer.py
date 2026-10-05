"""C++ and C structural syntax analyzer for NSAT."""

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


class CppAnalyzer(LanguageAnalyzer):
    """
    Analyzes C and C++ source files using structural patterns and preprocessor directives.
    Functions completely independent of variable or function naming.
    """

    @property
    def language_name(self) -> str:
        return "cpp"

    @property
    def supported_extensions(self) -> set[str]:
        return {".cpp", ".cxx", ".cc", ".c", ".hpp", ".hxx", ".hh", ".h"}

    def detect(self, file_path: Path, content: str) -> float:
        if file_path.suffix.lower() in self.supported_extensions:
            return 1.0
        if re.search(r"""#include\s*[<"][a-zA-Z0-9_./]+[>"]""", content):
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
            ("Crow C++ Web Daemon", r"""(?i)(#include\s*["<]crow\.h[">]|crow::SimpleApp|CROW_ROUTE)"""),
            ("Drogon C++ Web Framework", r"""(?i)(#include\s*<drogon/|drogon::HttpAppFramework)"""),
            ("Boost C++ Libraries", r"""(?i)(#include\s*<boost/|boost::asio|boost::beast)"""),
            ("Qt Framework", r"""(?i)(#include\s*<Q[A-Z][a-zA-Z]+>|QApplication\b|QObject\b)"""),
            ("POCO C++ Libraries", r"""(?i)(#include\s*<Poco/)"""),
        ]

        for name, pattern in patterns:
            if re.search(pattern, content):
                evidences.append(
                    FrameworkEvidence(
                        name=name,
                        confidence=0.95,
                        matched_files=[str(file_path)],
                        evidence_type="include_or_symbol",
                    )
                )
        return evidences

    def extract_entry_points(self, file_path: Path, content: str) -> list[EntryPoint]:
        entries: list[EntryPoint] = []
        lines = content.splitlines()

        # 1. Main entry function: int main(...)
        main_pattern = re.compile(r"""\bint\s+main\s*\([^)]*\)""")
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

        # 2. Crow route macro: CROW_ROUTE(app, "/path")
        crow_pattern = re.compile(r"""CROW_ROUTE\s*\(\s*[a-zA-Z0-9_]+\s*,\s*(['"][^'"]+['"])""")
        for idx, line in enumerate(lines, 1):
            m = crow_pattern.search(line)
            if m:
                route = m.group(1).strip("'\"")
                entries.append(
                    EntryPoint(
                        file_path=str(file_path),
                        line_number=idx,
                        entry_type="http_route",
                        signature=f"CROW_ROUTE({route})",
                        details={"route": route},
                    )
                )
        return entries

    def extract_network_operations(self, file_path: Path, content: str) -> list[NetworkComponent]:
        components: list[NetworkComponent] = []
        lines = content.splitlines()

        # POSIX socket bind and INADDR_ANY
        for idx, line in enumerate(lines, 1):
            if re.search(r"""\bbind\s*\(\s*[a-zA-Z0-9_]+""", line):
                host = "0.0.0.0" if "INADDR_ANY" in line or "0.0.0.0" in line else None
                components.append(
                    NetworkComponent(
                        file_path=str(file_path),
                        line_number=idx,
                        component_type="socket_bind",
                        host=host,
                        protocol="tcp",
                        details={"snippet": line.strip()[:60]},
                    )
                )

            # Crow app.port(18080).run()
            m_crow_run = re.search(r"""\.port\s*\(\s*(\d+)\s*\)\.run\s*\(\s*\)""", line)
            if m_crow_run:
                components.append(
                    NetworkComponent(
                        file_path=str(file_path),
                        line_number=idx,
                        component_type="http_listener",
                        port=int(m_crow_run.group(1)),
                        protocol="http",
                    )
                )
        return components

    def extract_database_components(self, file_path: Path, content: str) -> list[DatabaseComponent]:
        components: list[DatabaseComponent] = []
        lines = content.splitlines()

        db_pattern = re.compile(r"""\b(sqlite3_exec|sqlite3_open|PQexec|PQconnectdb|mysql_query|mysql_real_connect)\b""")
        for idx, line in enumerate(lines, 1):
            m = db_pattern.search(line)
            if m:
                components.append(
                    DatabaseComponent(
                        file_path=str(file_path),
                        line_number=idx,
                        db_type="c_database_api",
                        operation=m.group(1),
                    )
                )
        return components

    def extract_auth_indicators(self, file_path: Path, content: str) -> list[AuthIndicator]:
        indicators: list[AuthIndicator] = []
        lines = content.splitlines()

        auth_pattern = re.compile(r"""\b(SSL_CTX_new|EVP_EncryptInit|EVP_DigestInit|HMAC\b)""")
        for idx, line in enumerate(lines, 1):
            m = auth_pattern.search(line)
            if m:
                indicators.append(
                    AuthIndicator(
                        file_path=str(file_path),
                        line_number=idx,
                        indicator_type="openssl_cryptography",
                        details={"call": m.group(1)},
                    )
                )
        return indicators

    def extract_security_operations(self, file_path: Path, content: str) -> list[SecurityRelevantOperation]:
        ops: list[SecurityRelevantOperation] = []
        lines = content.splitlines()

        danger_patterns = [
            ("process_execution", "command_injection", re.compile(r"""\b(popen|system|execve|execvp)\s*\(""")),
            ("unsafe_buffer_operation", "memory_safety", re.compile(r"""\b(strcpy|sprintf|strcat|gets)\s*\(""")),
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
