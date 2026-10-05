"""Source Location Resolver for NSAT findings."""

import ast
import re
from pathlib import Path
from typing import Any, Optional

from nsat.core.surface import SecuritySurface
from nsat.correlation.models import PrimaryLocation
from nsat.normalization.models import CanonicalFinding


class SourceLocationResolver:
    """
    Deterministically resolves the best available source code location:
    File, Line, Column, Function, Class, Module, and Endpoint.
    If function or class cannot be reliably resolved, explicitly indicates 'Not reliably resolved'.
    """

    @classmethod
    def resolve_location(
        cls,
        finding: CanonicalFinding,
        target_path: Optional[Path] = None,
        surface: Optional[SecuritySurface] = None,
    ) -> PrimaryLocation:
        """Resolve precise file, line, function, class, and endpoint for a finding."""
        file_path_str = finding.file_path or finding.asset
        line_num = finding.line_number
        col_num = finding.column_number

        resolved_func = "Not reliably resolved"
        resolved_class = "Not reliably resolved"
        resolved_module: Optional[str] = None
        resolved_endpoint = finding.endpoint

        # Locate physical file on disk
        disk_path: Optional[Path] = None
        if file_path_str:
            p = Path(file_path_str)
            if p.is_file():
                disk_path = p
            elif target_path:
                candidate = (target_path / p).resolve()
                if candidate.is_file():
                    disk_path = candidate
                elif (target_path / file_path_str).is_file():
                    disk_path = target_path / file_path_str

        # If disk file found, attempt structural AST resolution
        if disk_path and disk_path.is_file():
            # Derive module name
            if target_path:
                try:
                    rel = disk_path.relative_to(target_path)
                    resolved_module = ".".join(rel.with_suffix("").parts)
                except ValueError:
                    resolved_module = disk_path.stem
            else:
                resolved_module = disk_path.stem

            if disk_path.suffix == ".py":
                func_name, cls_name = cls._resolve_python_ast(disk_path, line_num)
                if func_name:
                    resolved_func = func_name
                if cls_name:
                    resolved_class = cls_name
            else:
                # Heuristic AST / regex resolver for JS, TS, Java, C++
                func_name, cls_name = cls._resolve_non_python_source(disk_path, line_num)
                if func_name:
                    resolved_func = func_name
                if cls_name:
                    resolved_class = cls_name

        # If endpoint not yet specified on finding, cross-reference with security surface
        if not resolved_endpoint and surface and surface.application:
            resolved_endpoint = cls._match_endpoint_from_surface(
                file_path_str=file_path_str,
                line_num=line_num,
                func_name=resolved_func,
                surface=surface,
            )

        return PrimaryLocation(
            file_path=file_path_str,
            line_number=line_num,
            column=col_num,
            function_name=resolved_func,
            class_name=resolved_class,
            module=resolved_module,
            endpoint=resolved_endpoint,
        )

    @classmethod
    def _resolve_python_ast(cls, py_file: Path, target_line: Optional[int]) -> tuple[Optional[str], Optional[str]]:
        """Walk Python AST to find enclosing FunctionDef/AsyncFunctionDef and ClassDef."""
        try:
            content = py_file.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(content, filename=str(py_file))
        except Exception:
            return None, None

        if target_line is None:
            return None, None

        best_func: Optional[str] = None
        best_func_span = float("inf")
        best_class: Optional[str] = None
        best_class_span = float("inf")

        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                start = getattr(node, "lineno", None)
                end = getattr(node, "end_lineno", None)
                if start is not None:
                    # If end_lineno is None (Python < 3.8), approximate
                    end_line = end if end is not None else start + 50
                    if start <= target_line <= end_line:
                        span = end_line - start
                        if span < best_func_span:
                            best_func = node.name
                            best_func_span = span

            elif isinstance(node, ast.ClassDef):
                start = getattr(node, "lineno", None)
                end = getattr(node, "end_lineno", None)
                if start is not None:
                    end_line = end if end is not None else start + 200
                    if start <= target_line <= end_line:
                        span = end_line - start
                        if span < best_class_span:
                            best_class = node.name
                            best_class_span = span

        return best_func, best_class

    @classmethod
    def _resolve_non_python_source(cls, file_path: Path, target_line: Optional[int]) -> tuple[Optional[str], Optional[str]]:
        """Inspect JS/TS/Java/C++ source code lines preceding target line for function/class signatures."""
        if target_line is None or target_line <= 0:
            return None, None

        try:
            lines = file_path.read_text(encoding="utf-8", errors="replace").splitlines()
        except Exception:
            return None, None

        if not lines:
            return None, None

        # Inspect up to 60 lines backwards from target_line
        start_idx = max(0, target_line - 1)
        search_window = lines[max(0, start_idx - 60): start_idx + 1]

        func_pattern = re.compile(
            r"""(?:async\s+function\s+([a-zA-Z0-9_$]+)|"""  # JS/TS async function
            r"""function\s+([a-zA-Z0-9_$]+)|"""            # JS/TS function
            r"""(?:const|let|var)\s+([a-zA-Z0-9_$]+)\s*=\s*(?:async\s*)?\([^)]*\)\s*=>|""" # Arrow func
            r"""(?:public|private|protected|static|\s)*[\w<>\[\]]+\s+([a-zA-Z0-9_$]+)\s*\([^)]*\)\s*(?:throws\s+[\w,\s]+)?\s*\{|""" # Java/C++ method
            r"""(?:void|int|bool|string|auto|char)\s+([a-zA-Z0-9_$]+)\s*\()""" # C++ func
        )
        class_pattern = re.compile(r"""(?:class|struct|interface)\s+([a-zA-Z0-9_$]+)""")

        found_func: Optional[str] = None
        found_class: Optional[str] = None

        for line in reversed(search_window):
            if not found_func:
                m_fn = func_pattern.search(line)
                if m_fn:
                    # Pick first non-None group
                    found_func = next(g for g in m_fn.groups() if g is not None)
            if not found_class:
                m_cls = class_pattern.search(line)
                if m_cls:
                    found_class = m_cls.group(1)

            if found_func and found_class:
                break

        return found_func, found_class

    @classmethod
    def _match_endpoint_from_surface(
        cls,
        file_path_str: Optional[str],
        line_num: Optional[int],
        func_name: Optional[str],
        surface: SecuritySurface,
    ) -> Optional[str]:
        """Cross-reference with SecuritySurface endpoints."""
        all_endpoints = (
            surface.application.endpoints
            + surface.application.auth_endpoints
            + surface.application.admin_endpoints
            + surface.application.upload_endpoints
        )

        # 1. Match by function / handler name
        if func_name and func_name != "Not reliably resolved":
            for ep in all_endpoints:
                if ep.handler == func_name:
                    return f"{ep.method} {ep.path}"

        # 2. Match by file path and nearby line
        if file_path_str and line_num is not None:
            normalized_file = Path(file_path_str).name
            for ep in all_endpoints:
                if Path(ep.file_path).name == normalized_file:
                    if abs(ep.line_number - line_num) <= 15:
                        return f"{ep.method} {ep.path}"

        return None
