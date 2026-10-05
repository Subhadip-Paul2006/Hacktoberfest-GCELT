"""Race Condition and TOCTOU Structural Indicator Rule for NSAT Phase 3.5."""

from pathlib import Path
import re
from typing import Any
from nsat.core.models import ProjectIntelligence
from nsat.core.surface import SecuritySurface
from nsat.normalization.models import CanonicalFinding, FindingEvidence


class RaceConditionRule:
    """
    Detects structural check-then-use (TOCTOU) anti-patterns across state operations
    and filesystem transactions that lack atomic locking or transactional isolation.
    """

    def audit(
        self,
        repo_path: Path,
        intel: ProjectIntelligence,
        surface: SecuritySurface,
        existing_findings: list[CanonicalFinding],
    ) -> list[CanonicalFinding]:
        findings: list[CanonicalFinding] = []
        finding_id_seq = 1

        # Check-then-act regexes
        balance_check_regex = re.compile(
            r'if\s+(?:[a-zA-Z0-9_]*_)?(?:user\.)?(?:balance|credits|stock|quota|amount)\s*(?:>=|>|==)',
            re.IGNORECASE,
        )
        file_check_regex = re.compile(
            r'if\s+(?:os\.path\.exists|Path\([^)]+\)\.exists|existsSync)\s*\(',
            re.IGNORECASE,
        )

        for src_file in repo_path.rglob("*"):
            if not src_file.is_file() or src_file.suffix not in (".py", ".js", ".ts", ".java", ".cpp"):
                continue

            rel_path = str(src_file.relative_to(repo_path))
            if any(part in rel_path.lower() for part in ["test", "tests", "fixtures", "node_modules", "vendor"]):
                continue

            try:
                content = src_file.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue

            lines = content.splitlines()

            for line_idx, line in enumerate(lines, start=1):
                # Pattern 1: Balance / Stock Check-Then-Act without Transaction
                if balance_check_regex.search(line):
                    # Check next 5 lines for state mutation (e.g. -=, update, deduct)
                    window = lines[line_idx:min(len(lines), line_idx + 6)]
                    has_mutation = any(
                        any(op in w for op in ["-=", "+=", "update", "deduct", "withdraw", "save()"])
                        for w in window
                    )
                    has_lock_or_txn = any(
                        any(kw in w.lower() for kw in ["select_for_update", "lock", "transaction.atomic", "synchronized", "mutex"])
                        for w in window
                    )

                    if has_mutation and not has_lock_or_txn:
                        fid = f"NSAT-RACE-TOCTOU-{finding_id_seq:03d}"
                        finding_id_seq += 1

                        desc = (
                            f"Structural check-then-act (TOCTOU) pattern identified without concurrency locking or transaction isolation: "
                            f"'{line.strip()[:140]}'. Concurrent asynchronous requests can pass the check simultaneously "
                            "before the first request records the mutation (double-spending / inventory exhaustion)."
                        )
                        impact = "Business logic flaw enabling race condition exploitation, negative balances, and unauthorized asset allocation."
                        rec = "Wrap state verification and mutation inside an atomic database transaction with row-level locking (e.g., SELECT ... FOR UPDATE) or distributed mutex."

                        ev = FindingEvidence(
                            type="TOCTOU_CHECK_THEN_ACT",
                            description="State balance/quota checked and subsequently mutated without concurrency locking",
                            snippet=f"{line.strip()} ... " + "; ".join(w.strip() for w in window[:2]),
                            line_number=line_idx,
                            context={"classification": "STATIC_INDICATOR", "file": rel_path},
                        )

                        findings.append(
                            CanonicalFinding(
                                id=fid,
                                title="Potential Race Condition / TOCTOU in State Check-and-Deduct Flow",
                                category="race_condition",
                                severity="MEDIUM",
                                confidence=0.68,
                                confidence_label="Structural check-then-use anti-pattern",
                                source="developer_oversight",
                                sources=["developer_oversight"],
                                asset=rel_path,
                                description=desc,
                                impact=impact,
                                recommendation=rec,
                                status="POTENTIAL",
                                file_path=str(src_file),
                                line_number=line_idx,
                                evidence=[ev],
                            )
                        )

                # Pattern 2: Filesystem Check-Then-Use (os.path.exists -> open)
                if file_check_regex.search(line):
                    window = lines[line_idx:min(len(lines), line_idx + 4)]
                    if any("open(" in w or "writeFile(" in w or "readFile(" in w for w in window):
                        fid = f"NSAT-RACE-FILE-{finding_id_seq:03d}"
                        finding_id_seq += 1

                        findings.append(
                            CanonicalFinding(
                                id=fid,
                                title="Time-of-Check to Time-of-Use (TOCTOU) Filesystem Race Condition",
                                category="race_condition",
                                severity="LOW",
                                confidence=0.65,
                                confidence_label="Structural filesystem existence check anti-pattern",
                                source="developer_oversight",
                                sources=["developer_oversight"],
                                asset=rel_path,
                                description=(
                                    f"Filesystem existence checked followed by separate file open/write operation: '{line.strip()[:140]}'. "
                                    "A symlink or file replacement may be introduced between the check and the actual file access."
                                ),
                                impact="Symlink exploitation or unexpected file manipulation by local concurrent processes.",
                                recommendation="Use atomic open flags (e.g., O_CREAT | O_EXCL in Python os.open) instead of separate check and open calls.",
                                status="POTENTIAL",
                                file_path=str(src_file),
                                line_number=line_idx,
                                evidence=[
                                    FindingEvidence(
                                        type="FILESYSTEM_TOCTOU",
                                        description="File existence check precedes separate file open call",
                                        snippet=line.strip()[:160],
                                        line_number=line_idx,
                                    )
                                ],
                            )
                        )

        return findings
