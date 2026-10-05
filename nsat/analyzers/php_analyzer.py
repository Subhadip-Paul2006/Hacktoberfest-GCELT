"""PHP structural syntax analyzer for NSAT."""

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


class PhpAnalyzer(LanguageAnalyzer):
    """
    Analyzes PHP source files using structural patterns.
    Functions completely independent of variable or function naming.
    """

    @property
    def language_name(self) -> str:
        return "php"

    @property
    def supported_extensions(self) -> set[str]:
        return {".php", ".phtml"}

    def detect(self, file_path: Path, content: str) -> float:
        if file_path.suffix.lower() in self.supported_extensions:
            return 1.0
        if content.strip().startswith("<?php") or "<?php" in content:
            return 0.95
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
            ("Laravel", r"""(?i)(Illuminate\\|Route::(?:get|post|put|delete)|artisan)"""),
            ("Symfony", r"""(?i)(Symfony\\Component|#\[Route\()"""),
            ("WordPress", r"""(?i)(add_action\s*\(|add_filter\s*\(|wp_enqueue_script)"""),
            ("CodeIgniter", r"""(?i)(CodeIgniter\\|CI_Controller)"""),
        ]

        for name, pattern in patterns:
            if re.search(pattern, content):
                evidences.append(
                    FrameworkEvidence(
                        name=name,
                        confidence=0.95,
                        matched_files=[str(file_path)],
                        evidence_type="namespace_or_route",
                    )
                )
        return evidences

    def extract_entry_points(self, file_path: Path, content: str) -> list[EntryPoint]:
        entries: list[EntryPoint] = []
        lines = content.splitlines()

        # 1. Laravel / Lumen Route::get('/path', ...)
        route_pattern = re.compile(r"""\bRoute::(get|post|put|delete|patch|any)\s*\(\s*(['"][^'"]+['"])""", re.IGNORECASE)
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
                        signature=f"Route::{verb}({route})",
                        details={"verb": verb, "route": route},
                    )
                )

        # 2. Direct HTTP entry files accessing superglobals
        superglobal_pattern = re.compile(r"""\b\$(?:_GET|_POST|_REQUEST)\[""")
        has_superglobals = False
        for idx, line in enumerate(lines, 1):
            if superglobal_pattern.search(line):
                has_superglobals = True
                break

        if has_superglobals:
            entries.append(
                EntryPoint(
                    file_path=str(file_path),
                    line_number=1,
                    entry_type="http_endpoint",
                    signature=file_path.name,
                    details={"type": "php_direct_script"},
                )
            )
        return entries

    def extract_network_operations(self, file_path: Path, content: str) -> list[NetworkComponent]:
        components: list[NetworkComponent] = []
        lines = content.splitlines()

        # Socket listeners / stream servers
        stream_pattern = re.compile(r"""\bstream_socket_server\s*\(\s*(['"][^'"]+['"])""")
        for idx, line in enumerate(lines, 1):
            m = stream_pattern.search(line)
            if m:
                addr = m.group(1).strip("'\"")
                components.append(
                    NetworkComponent(
                        file_path=str(file_path),
                        line_number=idx,
                        component_type="socket_bind",
                        details={"address": addr},
                    )
                )
        return components

    def extract_database_components(self, file_path: Path, content: str) -> list[DatabaseComponent]:
        components: list[DatabaseComponent] = []
        lines = content.splitlines()

        db_pattern = re.compile(r"""\b(mysqli_query|mysql_query|->query|->prepare|DB::select|DB::insert)\b""")
        for idx, line in enumerate(lines, 1):
            m = db_pattern.search(line)
            if m:
                components.append(
                    DatabaseComponent(
                        file_path=str(file_path),
                        line_number=idx,
                        db_type="php_db_call",
                        operation=m.group(1),
                    )
                )
        return components

    def extract_auth_indicators(self, file_path: Path, content: str) -> list[AuthIndicator]:
        indicators: list[AuthIndicator] = []
        lines = content.splitlines()

        auth_pattern = re.compile(r"""\b(password_hash|password_verify|session_start|Auth::check|Auth::attempt)\b""")
        for idx, line in enumerate(lines, 1):
            m = auth_pattern.search(line)
            if m:
                indicators.append(
                    AuthIndicator(
                        file_path=str(file_path),
                        line_number=idx,
                        indicator_type="php_auth_function",
                        details={"call": m.group(1)},
                    )
                )
        return indicators

    def extract_security_operations(self, file_path: Path, content: str) -> list[SecurityRelevantOperation]:
        ops: list[SecurityRelevantOperation] = []
        lines = content.splitlines()

        danger_patterns = [
            ("process_execution", "command_injection", re.compile(r"""\b(system|exec|passthru|shell_exec|popen|proc_open)\s*\(""")),
            ("eval_execution", "code_injection", re.compile(r"""\beval\s*\(""")),
            ("insecure_deserialization", "unsafe_deserialization", re.compile(r"""\bunserialize\s*\(""")),
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
