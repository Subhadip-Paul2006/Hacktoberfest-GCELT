"""Project discovery and language detection layer for NSAT."""

from collections import defaultdict
import json
from pathlib import Path
import re
from typing import Optional
from nsat.analyzers import get_default_analyzers
from nsat.analyzers.base import LanguageAnalyzer
from nsat.core.classifier import ProjectClassifier
from nsat.core.config import NSATConfig
from nsat.core.models import (
    AuthIndicator,
    DatabaseComponent,
    DependencyInfo,
    DiscoveredFile,
    EntryPoint,
    FrameworkEvidence,
    LanguageDistribution,
    NetworkComponent,
    ProjectIntelligence,
    ProjectMetadata,
    SecurityRelevantOperation,
)
from nsat.core.relevance import RelevanceFilter


class DiscoveryEngine:
    """
    Recursively audits a repository, identifies languages, extracts structural artifacts,
    and constructs a normalized ProjectIntelligence representation.
    """

    def __init__(self, config: Optional[NSATConfig] = None, analyzers: Optional[list[LanguageAnalyzer]] = None):
        self.config = config or NSATConfig()
        self.analyzers = analyzers or get_default_analyzers()

    def discover(self, target_path: Path) -> ProjectIntelligence:
        """
        Main entry point for Phase 1 project intelligence discovery.
        """
        target_path = target_path.resolve()
        if not target_path.exists():
            raise FileNotFoundError(f"Target path does not exist: {target_path}")

        files_discovered: list[DiscoveredFile] = []
        entry_points: list[EntryPoint] = []
        network_components: list[NetworkComponent] = []
        database_components: list[DatabaseComponent] = []
        auth_indicators: list[AuthIndicator] = []
        security_ops: list[SecurityRelevantOperation] = []
        frameworks_map: dict[str, FrameworkEvidence] = {}
        language_stats = defaultdict(lambda: {"files": 0, "lines": 0})
        total_loc = 0

        # Walk repository
        candidate_paths = self._collect_file_paths(target_path)
        for file_path in candidate_paths:
            # 1. Path-based relevance check
            is_rel, rel_reason = RelevanceFilter.assess_path(file_path, target_path)
            if not is_rel:
                continue

            # 2. Read file safely
            try:
                content = file_path.read_text(encoding="utf-8", errors="replace")
            except Exception as e:
                # Malformed/unreadable file handling
                files_discovered.append(
                    DiscoveredFile(
                        relative_path=str(file_path.relative_to(target_path)),
                        absolute_path=str(file_path),
                        is_relevant=False,
                        relevance_reason=f"unreadable: {str(e)}",
                    )
                )
                continue

            # 3. Content-based relevance check (filters trivial hello world, keeps meaningless identifiers)
            is_content_rel, content_reason = RelevanceFilter.assess_content(file_path, content)
            if not is_content_rel and self.config.analysis.filter_trivial_hello_world:
                continue

            line_count = len(content.splitlines())
            total_loc += line_count

            # 4. Language detection & analysis
            matched_analyzer: Optional[LanguageAnalyzer] = None
            highest_confidence = 0.0

            for analyzer in self.analyzers:
                conf = analyzer.detect(file_path, content)
                if conf > highest_confidence:
                    highest_confidence = conf
                    matched_analyzer = analyzer

            detected_lang = matched_analyzer.language_name if (matched_analyzer and highest_confidence >= 0.5) else None

            if detected_lang:
                language_stats[detected_lang]["files"] += 1
                language_stats[detected_lang]["lines"] += line_count

                # Extract structural syntax independent of names
                try:
                    ep_list = matched_analyzer.extract_entry_points(file_path, content)
                    entry_points.extend(ep_list)

                    net_list = matched_analyzer.extract_network_operations(file_path, content)
                    network_components.extend(net_list)

                    db_list = matched_analyzer.extract_database_components(file_path, content)
                    database_components.extend(db_list)

                    auth_list = matched_analyzer.extract_auth_indicators(file_path, content)
                    auth_indicators.extend(auth_list)

                    sec_list = matched_analyzer.extract_security_operations(file_path, content)
                    security_ops.extend(sec_list)

                    fw_list = matched_analyzer.extract_frameworks(file_path, content)
                    for fw in fw_list:
                        if fw.name not in frameworks_map:
                            frameworks_map[fw.name] = fw
                        else:
                            frameworks_map[fw.name].matched_files.extend(fw.matched_files)
                except Exception:
                    # Never crash because of one file's AST extraction failure
                    pass

            files_discovered.append(
                DiscoveredFile(
                    relative_path=str(file_path.relative_to(target_path)),
                    absolute_path=str(file_path),
                    language=detected_lang,
                    size_bytes=file_path.stat().st_size if file_path.is_file() else 0,
                    line_count=line_count,
                    is_relevant=True,
                    relevance_reason=content_reason,
                )
            )

        # Calculate language distribution percentages
        total_analyzed_files = sum(d["files"] for d in language_stats.values())
        lang_distributions: list[LanguageDistribution] = []
        for lang_name, stats in language_stats.items():
            pct = (stats["files"] / total_analyzed_files * 100.0) if total_analyzed_files > 0 else 0.0
            lang_distributions.append(
                LanguageDistribution(
                    language=lang_name,
                    file_count=stats["files"],
                    line_count=stats["lines"],
                    percentage=round(pct, 1),
                    confidence=1.0,
                )
            )
        # Sort languages by percentage descending
        lang_distributions.sort(key=lambda x: x.percentage, reverse=True)

        # Parse package dependencies from manifests
        dependencies = self._discover_dependencies(target_path)

        # Classify project archetype based on evidence
        frameworks_list = list(frameworks_map.values())
        project_type = ProjectClassifier.classify(
            frameworks=frameworks_list,
            entry_points=entry_points,
            network_components=network_components,
            database_components=database_components,
        )

        metadata = ProjectMetadata(
            target_path=str(target_path),
            project_name=target_path.name or "repository",
            total_files_discovered=len(files_discovered),
            analyzable_files_count=total_analyzed_files,
            total_lines_of_code=total_loc,
        )

        return ProjectIntelligence(
            metadata=metadata,
            languages=lang_distributions,
            frameworks=frameworks_list,
            project_type=project_type,
            files=files_discovered,
            entry_points=entry_points,
            dependencies=dependencies,
            network_components=network_components,
            database_components=database_components,
            authentication_indicators=auth_indicators,
            security_relevant_operations=security_ops,
            analyzer_metadata={"analyzers_run": [a.language_name for a in self.analyzers]},
        )

    def _collect_file_paths(self, target_path: Path) -> list[Path]:
        """Collect all files avoiding ignored directories and oversized files."""
        if target_path.is_file():
            return [target_path]

        max_size = self.config.project.max_file_size_mb * 1024 * 1024
        ignore_set = set(self.config.project.ignore_dirs)
        collected: list[Path] = []

        for p in target_path.rglob("*"):
            if not p.is_file():
                continue
            # Check if any parent component matches ignore list
            parts = p.relative_to(target_path).parts
            if any(part in ignore_set or part.startswith(".") for part in parts[:-1]):
                continue
            try:
                if p.stat().st_size <= max_size:
                    collected.append(p)
            except OSError:
                pass
        return collected

    def _discover_dependencies(self, target_path: Path) -> list[DependencyInfo]:
        """Extract top-level dependency metadata from standard package manifests."""
        deps: list[DependencyInfo] = []

        # 1. requirements.txt & pyproject.toml (Python)
        req_file = target_path / "requirements.txt"
        if req_file.is_file():
            try:
                for line in req_file.read_text(encoding="utf-8").splitlines():
                    clean = line.strip().split("#")[0]
                    if clean:
                        m = re.match(r"^([a-zA-Z0-9_\-\.]+)(?:[>=<~]+(.+))?", clean)
                        if m:
                            deps.append(
                                DependencyInfo(
                                    name=m.group(1),
                                    version=m.group(2),
                                    package_manager="pip",
                                    source_file=str(req_file.relative_to(target_path)),
                                )
                            )
            except Exception:
                pass

        pyproj_file = target_path / "pyproject.toml"
        if pyproj_file.is_file():
            try:
                for line in pyproj_file.read_text(encoding="utf-8").splitlines():
                    clean = line.strip().strip('"\'')
                    m = re.match(r"^([a-zA-Z0-9_\-\.]+)[>=<~]+(.+)", clean)
                    if m and not line.startswith("["):
                        deps.append(
                            DependencyInfo(
                                name=m.group(1),
                                version=m.group(2),
                                package_manager="pip",
                                source_file=str(pyproj_file.relative_to(target_path)),
                            )
                        )
            except Exception:
                pass

        # 2. package.json & package-lock.json (Node.js)
        pkg_file = target_path / "package.json"
        if pkg_file.is_file():
            try:
                data = json.loads(pkg_file.read_text(encoding="utf-8"))
                for dep_map in [data.get("dependencies", {}), data.get("devDependencies", {})]:
                    for name, ver in dep_map.items():
                        deps.append(
                            DependencyInfo(
                                name=name,
                                version=str(ver),
                                package_manager="npm",
                                source_file=str(pkg_file.relative_to(target_path)),
                            )
                        )
            except Exception:
                pass

        # 3. pom.xml (Maven / Java)
        pom_file = target_path / "pom.xml"
        if pom_file.is_file():
            try:
                content = pom_file.read_text(encoding="utf-8")
                matches = re.findall(r"<artifactId>([a-zA-Z0-9_\-\.]+)</artifactId>", content)
                for art in matches[:25]:
                    deps.append(
                        DependencyInfo(
                            name=art,
                            package_manager="maven",
                            source_file=str(pom_file.relative_to(target_path)),
                        )
                    )
            except Exception:
                pass

        # 4. Cargo.toml (Rust)
        cargo_file = target_path / "Cargo.toml"
        if cargo_file.is_file():
            try:
                in_deps = False
                for line in cargo_file.read_text(encoding="utf-8").splitlines():
                    stripped = line.strip()
                    if stripped.startswith("[dependencies]") or stripped.startswith("[dev-dependencies]"):
                        in_deps = True
                        continue
                    elif stripped.startswith("["):
                        in_deps = False
                        continue
                    if in_deps and "=" in stripped:
                        parts = stripped.split("=", 1)
                        name = parts[0].strip()
                        ver = parts[1].strip().strip('"\'')
                        deps.append(
                            DependencyInfo(
                                name=name,
                                version=ver,
                                package_manager="cargo",
                                source_file=str(cargo_file.relative_to(target_path)),
                            )
                        )
            except Exception:
                pass

        # 5. go.mod (Go)
        go_mod_file = target_path / "go.mod"
        if go_mod_file.is_file():
            try:
                in_req = False
                for line in go_mod_file.read_text(encoding="utf-8").splitlines():
                    stripped = line.strip()
                    if stripped.startswith("require ("):
                        in_req = True
                        continue
                    elif in_req and stripped == ")":
                        in_req = False
                        continue
                    if stripped.startswith("require "):
                        parts = stripped[len("require "):].strip().split()
                        if len(parts) >= 2:
                            deps.append(
                                DependencyInfo(
                                    name=parts[0],
                                    version=parts[1],
                                    package_manager="go",
                                    source_file=str(go_mod_file.relative_to(target_path)),
                                )
                            )
                    elif in_req and stripped and not stripped.startswith("//"):
                        parts = stripped.split()
                        if len(parts) >= 2:
                            deps.append(
                                DependencyInfo(
                                    name=parts[0],
                                    version=parts[1],
                                    package_manager="go",
                                    source_file=str(go_mod_file.relative_to(target_path)),
                                )
                            )
            except Exception:
                pass

        # 6. composer.json (PHP)
        composer_file = target_path / "composer.json"
        if composer_file.is_file():
            try:
                data = json.loads(composer_file.read_text(encoding="utf-8"))
                for dep_map in [data.get("require", {}), data.get("require-dev", {})]:
                    for name, ver in dep_map.items():
                        deps.append(
                            DependencyInfo(
                                name=name,
                                version=str(ver),
                                package_manager="composer",
                                source_file=str(composer_file.relative_to(target_path)),
                            )
                        )
            except Exception:
                pass

        return deps
