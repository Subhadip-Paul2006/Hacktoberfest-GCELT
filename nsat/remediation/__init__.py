"""
NSAT Remediation and Verification Subsystem (Phase 4C).
"""

from nsat.remediation.models import (
    RemediationProposal,
    RemediationStatus,
    SnapshotMetadata,
    VerificationOutcome,
    VerificationReport,
)
from nsat.remediation.snapshot import SnapshotManager
from nsat.remediation.rollback import RollbackManager, RollbackResult
from nsat.remediation.patcher import Patcher, PatchApplicationResult
from nsat.remediation.planner import RemediationPlanner
from nsat.remediation.verifier import VerificationEngine
from nsat.remediation.manager import RemediationManager

__all__ = [
    "RemediationProposal",
    "RemediationStatus",
    "SnapshotMetadata",
    "VerificationOutcome",
    "VerificationReport",
    "SnapshotManager",
    "RollbackManager",
    "RollbackResult",
    "Patcher",
    "PatchApplicationResult",
    "RemediationPlanner",
    "VerificationEngine",
    "RemediationManager",
]
