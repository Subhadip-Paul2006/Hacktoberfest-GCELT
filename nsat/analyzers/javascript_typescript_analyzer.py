"""JavaScript and TypeScript structural syntax analyzer for NSAT."""

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


class JavaScriptTypeScriptAnalyzer(LanguageAnalyzer):
    """
    Analyzes JavaScript and TypeScript files using structural pattern extraction.
    Independent of variable and function naming conventions.
    """

    @property
    def language_name(self) -> str:
        return "javascript_typescript"

    @property
    def supported_extensions(self) -> set[str]:
        return {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}

    def detect(self, file_path: Path, content: str) -> float:
        if file_path.suffix.lower() in self.supported_extensions:
            return 1.0
        # Check node shebang
        first_line = content.splitlines()[0] if content else ""
        if first_line.startswith("#!") and "node" in first_line:
            return 0.9
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
            ("React", r"""(?i)(from\s+['"]react['"]|require\(['"]react['"]\)|<[A-Z][a-zA-Z0-9]*\b)"""),
            ("Next.js", r"""(?i)(from\s+['"]next/|require\(['"]next/|getServerSideProps|getStaticProps)"""),
            ("Express", r"""(?i)(from\s+['"]express['"]|require\(['"]express['"]\)|express\(\))"""),
            ("NestJS", r"""(?i)(@Controller\b|@Injectable\b|@Module\b)"""),
            ("Fastify", r"""(?i)(from\s+['"]fastify['"]|require\(['"]fastify['"]\))"""),
            ("Vue", r"""(?i)(from\s+['"]vue['"]|createApp\()"""),
        ]

        for name, pattern in patterns:
            if re.search(pattern, content):
                evidences.append(
                    FrameworkEvidence(
                        name=name,
                        confidence=0.9,
                        matched_files=[str(file_path)],
                        evidence_type="structural_signature",
                    )
                )
        return evidences

    def extract_entry_points(self, file_path: Path, content: str) -> list[EntryPoint]:
        entries: list[EntryPoint] = []
        lines = content.splitlines()

        # Route handlers in Express/Fastify: app.get('/...', ...), router.post('/...', ...)
        # Notice: works regardless of whether handler is an anonymous arrow function or named handler2
        route_pattern = re.compile(
            r"""\b(?:app|router|server)\.(get|post|put|delete|patch|all)\s*\(\s*(['"][^'"]+['"])""",
            re.IGNORECASE,
        )
        for idx, line in enumerate(lines, 1):
            match = route_pattern.search(line)
            if match:
                method = match.group(1).upper()
                route = match.group(2).strip("'\"")
                entries.append(
                    EntryPoint(
                        file_path=str(file_path),
                        line_number=idx,
                        entry_type="http_route",
                        signature=f"{method} {route}",
                        details={"method": method, "route": route},
                    )
                )

        # Next.js API route handlers: export default function ..., export async function GET...
        next_route_pattern = re.compile(r"""export\s+(?:async\s+)?function\s+(GET|POST|PUT|DELETE|handler)\b""")
        for idx, line in enumerate(lines, 1):
            m = next_route_pattern.search(line)
            if m:
                entries.append(
                    EntryPoint(
                        file_path=str(file_path),
                        line_number=idx,
                        entry_type="http_route",
                        signature=line.strip()[:60],
                        details={"handler": m.group(1)},
                    )
                )
        return entries

    def extract_network_operations(self, file_path: Path, content: str) -> list[NetworkComponent]:
        components: list[NetworkComponent] = []
        lines = content.splitlines()

        # Listen patterns: .listen(port, [host])
        listen_pattern = re.compile(r"""\b\.listen\s*\(\s*(\d+|process\.env\.[A-Z_]+)(?:\s*,\s*(['"][^'"]+['"]))?""")
        for idx, line in enumerate(lines, 1):
            m = listen_pattern.search(line)
            if m:
                port_str = m.group(1)
                host_str = m.group(2).strip("'\"") if m.group(2) else None
                port_val = int(port_str) if port_str.isdigit() else None
                components.append(
                    NetworkComponent(
                        file_path=str(file_path),
                        line_number=idx,
                        component_type="http_listener",
                        host=host_str or "0.0.0.0",
                        port=port_val,
                        protocol="http",
                    )
                )

        # Fetch/Axios HTTP client calls
        client_pattern = re.compile(r"""\b(axios\.(?:get|post|put|delete)|fetch\s*\()""")
        for idx, line in enumerate(lines, 1):
            if client_pattern.search(line):
                components.append(
                    NetworkComponent(
                        file_path=str(file_path),
                        line_number=idx,
                        component_type="client_connect",
                        protocol="http",
                        details={"snippet": line.strip()[:60]},
                    )
                )
        return components

    def extract_database_components(self, file_path: Path, content: str) -> list[DatabaseComponent]:
        components: list[DatabaseComponent] = []
        lines = content.splitlines()

        db_pattern = re.compile(r"""\b(prisma\.[a-zA-Z0-9_]+\.(?:findMany|findUnique|create|update)|mongoose\.connect|new\s+Pool\b|\.query\s*\()""")
        for idx, line in enumerate(lines, 1):
            if db_pattern.search(line):
                components.append(
                    DatabaseComponent(
                        file_path=str(file_path),
                        line_number=idx,
                        db_type="orm_or_sql",
                        operation=line.strip()[:60],
                    )
                )
        return components

    def extract_auth_indicators(self, file_path: Path, content: str) -> list[AuthIndicator]:
        indicators: list[AuthIndicator] = []
        lines = content.splitlines()

        auth_pattern = re.compile(r"""\b(jwt\.(?:sign|verify)|bcrypt\.(?:hash|compare)|passport\.authenticate)\b""")
        for idx, line in enumerate(lines, 1):
            m = auth_pattern.search(line)
            if m:
                indicators.append(
                    AuthIndicator(
                        file_path=str(file_path),
                        line_number=idx,
                        indicator_type="token_or_credential_auth",
                        details={"call": m.group(1)},
                    )
                )
        return indicators

    def extract_security_operations(self, file_path: Path, content: str) -> list[SecurityRelevantOperation]:
        ops: list[SecurityRelevantOperation] = []
        lines = content.splitlines()

        # Dangerous sinks: child_process.exec, eval, dangerouslySetInnerHTML
        danger_patterns = [
            ("process_execution", "command_injection", re.compile(r"""\b(child_process\.(?:exec|spawn|execSync)|exec\s*\()""")),
            ("eval_execution", "code_injection", re.compile(r"""\b(eval\s*\(|new\s+Function\s*\()""")),
            ("dom_xss", "xss_injection", re.compile(r"""dangerouslySetInnerHTML\b""")),
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
