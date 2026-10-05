"""Python AST language analyzer for NSAT."""

import ast
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


class PythonAnalyzer(LanguageAnalyzer):
    """
    Analyzes Python source files using AST structural inspection.
    Functions completely independent of variable or function naming conventions.
    """

    @property
    def language_name(self) -> str:
        return "python"

    @property
    def supported_extensions(self) -> set[str]:
        return {".py", ".pyw"}

    def detect(self, file_path: Path, content: str) -> float:
        if file_path.suffix.lower() in self.supported_extensions:
            return 1.0
        # Check shebang for python script
        first_line = content.splitlines()[0] if content else ""
        if first_line.startswith("#!") and "python" in first_line:
            return 0.9
        return 0.0

    def _safe_parse_ast(self, content: str) -> ast.AST | None:
        try:
            return ast.parse(content)
        except SyntaxError:
            return None

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
        tree = self._safe_parse_ast(content)

        # Framework detection patterns via imports and decorators
        framework_modules = {
            "fastapi": "FastAPI",
            "flask": "Flask",
            "django": "Django",
            "tornado": "Tornado",
            "sqlalchemy": "SQLAlchemy",
            "graphene": "GraphQL",
            "strawberry": "GraphQL",
            "click": "Click (CLI)",
            "typer": "Typer (CLI)",
        }

        if tree:
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        top_pkg = alias.name.split(".")[0].lower()
                        if top_pkg in framework_modules:
                            evidences.append(
                                FrameworkEvidence(
                                    name=framework_modules[top_pkg],
                                    confidence=0.95,
                                    matched_files=[str(file_path)],
                                    evidence_type="import",
                                )
                            )
                elif isinstance(node, ast.ImportFrom) and node.module:
                    top_pkg = node.module.split(".")[0].lower()
                    if top_pkg in framework_modules:
                        evidences.append(
                            FrameworkEvidence(
                                name=framework_modules[top_pkg],
                                confidence=0.95,
                                matched_files=[str(file_path)],
                                evidence_type="import",
                            )
                        )
        else:
            # Fallback regex when AST parse fails on malformed file
            for pkg, fw in framework_modules.items():
                if re.search(rf"\b(import\s+{pkg}|from\s+{pkg}\b)", content):
                    evidences.append(
                        FrameworkEvidence(
                            name=fw,
                            confidence=0.8,
                            matched_files=[str(file_path)],
                            evidence_type="fallback_regex",
                        )
                    )
        return evidences

    def extract_entry_points(self, file_path: Path, content: str) -> list[EntryPoint]:
        entries: list[EntryPoint] = []
        tree = self._safe_parse_ast(content)
        if not tree:
            return entries

        for node in ast.walk(tree):
            # 1. Main guard: if __name__ == '__main__':
            if isinstance(node, ast.If):
                test = node.test
                if isinstance(test, ast.Compare):
                    left = getattr(test.left, "id", None)
                    if left == "__name__":
                        entries.append(
                            EntryPoint(
                                file_path=str(file_path),
                                line_number=node.lineno,
                                entry_type="main",
                                signature="if __name__ == '__main__':",
                            )
                        )

            # 2. Decorated HTTP routes (e.g. @app.get('/'), @router.post('/api/x'))
            # Note: We inspect decorator structure regardless of the function name (e.g. def a(), def handler2())
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for dec in node.decorator_list:
                    dec_call = dec if isinstance(dec, ast.Call) else None
                    dec_func = dec_call.func if dec_call else dec
                    attr_name = getattr(dec_func, "attr", None)
                    if attr_name in {"get", "post", "put", "delete", "patch", "route"}:
                        route_path = "/"
                        if dec_call and dec_call.args and isinstance(dec_call.args[0], ast.Constant):
                            route_path = str(dec_call.args[0].value)
                        entries.append(
                            EntryPoint(
                                file_path=str(file_path),
                                line_number=node.lineno,
                                entry_type="http_route",
                                signature=f"@{attr_name}('{route_path}') -> {node.name}()",
                                details={"method": attr_name.upper(), "route": route_path},
                            )
                        )
        return entries

    def extract_network_operations(self, file_path: Path, content: str) -> list[NetworkComponent]:
        components: list[NetworkComponent] = []
        tree = self._safe_parse_ast(content)
        if not tree:
            return components

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func_name = ""
                if isinstance(node.func, ast.Attribute):
                    func_name = node.func.attr
                elif isinstance(node.func, ast.Name):
                    func_name = node.func.id

                # Socket bind
                if func_name == "bind" and node.args:
                    components.append(
                        NetworkComponent(
                            file_path=str(file_path),
                            line_number=node.lineno,
                            component_type="socket_bind",
                            protocol="tcp",
                            details={"call": "socket.bind"},
                        )
                    )

                # Server listener: app.run() or uvicorn.run()
                if func_name == "run":
                    host_val, port_val = None, None
                    for kw in node.keywords:
                        if kw.arg == "host" and isinstance(kw.value, ast.Constant):
                            host_val = str(kw.value.value)
                        elif kw.arg == "port" and isinstance(kw.value, ast.Constant):
                            try:
                                port_val = int(kw.value.value)
                            except (ValueError, TypeError):
                                pass

                    if host_val or port_val:
                        components.append(
                            NetworkComponent(
                                file_path=str(file_path),
                                line_number=node.lineno,
                                component_type="http_listener",
                                host=host_val or "0.0.0.0",
                                port=port_val,
                                protocol="http",
                            )
                        )
        return components

    def extract_database_components(self, file_path: Path, content: str) -> list[DatabaseComponent]:
        components: list[DatabaseComponent] = []
        tree = self._safe_parse_ast(content)
        if not tree:
            return components

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func_name = getattr(node.func, "attr", None)
                if func_name in {"execute", "executemany", "raw_sql", "execute_query"}:
                    components.append(
                        DatabaseComponent(
                            file_path=str(file_path),
                            line_number=node.lineno,
                            db_type="sql_query",
                            operation=func_name,
                        )
                    )
        return components

    def extract_auth_indicators(self, file_path: Path, content: str) -> list[AuthIndicator]:
        indicators: list[AuthIndicator] = []
        tree = self._safe_parse_ast(content)
        if not tree:
            return indicators

        auth_modules = {"bcrypt", "jwt", "passlib", "hashlib", "argon2"}
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func_str = ast.unparse(node.func).lower() if hasattr(ast, "unparse") else ""
                for mod in auth_modules:
                    if mod in func_str:
                        indicators.append(
                            AuthIndicator(
                                file_path=str(file_path),
                                line_number=node.lineno,
                                indicator_type="credential_or_token_processing",
                                details={"target": func_str},
                            )
                        )
                        break
        return indicators

    def extract_security_operations(self, file_path: Path, content: str) -> list[SecurityRelevantOperation]:
        ops: list[SecurityRelevantOperation] = []
        tree = self._safe_parse_ast(content)
        if not tree:
            return ops

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                # 1. Process execution: os.system, subprocess.run, popen
                call_str = ""
                if hasattr(ast, "unparse"):
                    try:
                        call_str = ast.unparse(node.func)
                    except Exception:
                        pass

                if any(k in call_str for k in ["subprocess.run", "subprocess.Popen", "os.system", "os.popen"]):
                    snippet = ""
                    if hasattr(ast, "unparse"):
                        try:
                            snippet = ast.unparse(node)[:80]
                        except Exception:
                            pass
                    ops.append(
                        SecurityRelevantOperation(
                            file_path=str(file_path),
                            line_number=node.lineno,
                            operation_type="process_execution",
                            sink_category="command_injection",
                            snippet=snippet or call_str,
                        )
                    )

                # 2. Insecure hashing: hashlib.md5, hashlib.sha1
                if any(k in call_str for k in ["hashlib.md5", "hashlib.sha1"]):
                    ops.append(
                        SecurityRelevantOperation(
                            file_path=str(file_path),
                            line_number=node.lineno,
                            operation_type="weak_cryptography",
                            sink_category="insecure_crypto",
                            snippet=call_str,
                        )
                    )
        return ops
